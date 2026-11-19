"""The MCP server: four read-only tools over stdio.

Each tool call goes: validate input -> rate limit -> run one check -> summarise.
Nothing is stored, logged to disk, or sent anywhere except back to the
Claude session that asked.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import __version__, dns, ping, port, runner, trace
from .ratelimit import RateLimited, RateLimiter
from .validate import (
    ValidationError,
    validate_host,
    validate_int,
    validate_port,
    validate_record_type,
)

INSTRUCTIONS = """netdoctor runs safe, read-only network checks on the user's own computer
to help diagnose slow or broken internet. Suggested order when someone says
"my internet is slow/broken": ping the router (often 192.168.1.1 or 192.168.0.1;
the first traceroute hop shows it), then ping 1.1.1.1, then dns_lookup a well-known
name, then traceroute to whatever is slow. check_port tells you whether one specific
service (e.g. port 443 on a website) can be reached. Calls are rate-limited
(1 per second, 20 per minute), so plan checks rather than retrying in a loop.
Never use check_port to look for open ports: it allows only a few ports per host."""

MAX_CONCURRENT = 2  # never more than two checks (child processes) at once

READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,
)


class Doctor:
    """Plain, synchronous core so it can be tested without MCP."""

    def __init__(self, limiter: RateLimiter | None = None):
        self.limiter = limiter or RateLimiter()
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT)

    def ping(self, host: str, count: int = 4) -> dict[str, Any]:
        return self._guard(self._ping, host, count)

    def dns_lookup(self, name: str, record_type: str = "A", server: str | None = None) -> dict[str, Any]:
        return self._guard(self._dns, name, record_type, server)

    def traceroute(self, host: str, max_hops: int = 15) -> dict[str, Any]:
        return self._guard(self._trace, host, max_hops)

    def check_port(self, host: str, port: int) -> dict[str, Any]:
        return self._guard(self._port, host, port)

    # --- internals ---

    def _guard(self, fn, *args) -> dict[str, Any]:
        if not self._slots.acquire(blocking=False):
            return {
                "ok": False,
                "error": f"{MAX_CONCURRENT} checks are already running; wait for them to finish.",
                "retry_after_s": 2.0,
            }
        try:
            result = fn(*args)
        except ValidationError as exc:
            return {"ok": False, "error": f"Rejected input: {exc}"}
        except RateLimited as exc:
            return {"ok": False, "error": str(exc), "retry_after_s": round(exc.retry_after, 1)}
        except runner.ProgramNotFound as exc:
            return {"ok": False, "error": str(exc)}
        except (ValueError, TypeError) as exc:
            return {"ok": False, "error": f"Rejected input: {exc}"}
        finally:
            self._slots.release()
        return {"ok": True, **result}

    def _ping(self, host: str, count: int) -> dict[str, Any]:
        host = validate_host(host)
        count = validate_int(count, "count", 1, 10)
        self.limiter.acquire("ping")
        program, args = ping.build_args(runner.current_os(), host, count)
        res = runner.run(program, args, timeout=ping.timeout_for(count))
        return ping.parse(host, count, res.stdout, res.stderr, res.timed_out)

    def _dns(self, name: str, record_type: str, server: str | None) -> dict[str, Any]:
        name = validate_host(name)
        record_type = validate_record_type(record_type)
        server = validate_host(server) if server else None
        self.limiter.acquire("dns_lookup")
        program, args = dns.build_args(name, record_type, server)
        start = time.monotonic()
        res = runner.run(program, args, timeout=dns.TIMEOUT)
        elapsed = (time.monotonic() - start) * 1000
        return dns.parse(name, record_type, res.stdout, res.stderr, elapsed, res.timed_out)

    def _trace(self, host: str, max_hops: int) -> dict[str, Any]:
        host = validate_host(host)
        max_hops = validate_int(max_hops, "max_hops", 1, 30)
        os_name = runner.current_os()
        program = _trace_program(os_name)
        self.limiter.acquire("traceroute")
        args = trace.build_args(os_name, host, max_hops, program)
        res = runner.run(program, args, timeout=trace.timeout_for(max_hops))
        return trace.parse(host, res.stdout, res.timed_out)

    def _port(self, host: str, port_number: int) -> dict[str, Any]:
        host = validate_host(host)
        port_number = validate_port(port_number)
        self.limiter.acquire("check_port")  # throttles the DNS lookup below too
        try:
            target = port.resolve(host, port_number)
        except port.ResolveFailed:
            return port.dns_failure(host, port_number)
        self.limiter.acquire_port(target.ip, port_number)
        return port.check(host, port_number, target)


def _trace_program(os_name: str) -> str:
    if os_name == "windows":
        return "tracert"
    if os_name == "linux":
        try:
            runner.find_program("traceroute", os_name)
        except runner.ProgramNotFound:
            runner.find_program("tracepath", os_name)  # raises if neither exists
            return "tracepath"
    return "traceroute"


def build_server(doctor: Doctor | None = None) -> MCPServer:
    doctor = doctor or Doctor()
    mcp = MCPServer("netdoctor", instructions=INSTRUCTIONS, version=__version__)

    @mcp.tool(name="ping", annotations=READ_ONLY)
    async def ping_tool(host: str, count: int = 4) -> dict[str, Any]:
        """Ping one host (hostname or IP) to see if it is reachable, with latency,
        jitter and packet loss. count: 1-10 pings (default 4)."""
        return await anyio.to_thread.run_sync(doctor.ping, host, count)

    @mcp.tool(annotations=READ_ONLY)
    async def dns_lookup(name: str, record_type: str = "A", server: str | None = None) -> dict[str, Any]:
        """Look up one DNS name and time the lookup. record_type: A, AAAA, CNAME, MX,
        NS or TXT. server: optional resolver to ask instead of the system one
        (e.g. 1.1.1.1), useful to tell whether the local DNS is the problem."""
        return await anyio.to_thread.run_sync(doctor.dns_lookup, name, record_type, server)

    @mcp.tool(annotations=READ_ONLY)
    async def traceroute(host: str, max_hops: int = 15) -> dict[str, Any]:
        """Trace the network path to one host and show the delay at each hop, to find
        where traffic slows down or stops. max_hops: 1-30 (default 15). Takes up to a
        minute or two."""
        return await anyio.to_thread.run_sync(doctor.traceroute, host, max_hops)

    @mcp.tool(annotations=READ_ONLY)
    async def check_port(host: str, port: int) -> dict[str, Any]:
        """Check whether ONE TCP port on ONE host accepts connections (e.g. 443 for a
        website). Opens one normal connection and closes it; sends no data. Not a port
        scanner: limited to a few different ports per host every 10 minutes."""
        return await anyio.to_thread.run_sync(doctor.check_port, host, port)

    return mcp


def main() -> None:
    build_server().run("stdio")


if __name__ == "__main__":
    main()
