"""check_port: can this computer open a TCP connection to ONE port on ONE host.

This uses one ordinary TCP connection (the same as a browser opening a page),
then closes it at once. No data is sent. It is not a port scanner: the tool
takes exactly one host and one port, and the rate limiter, keyed on the
resolved IP address, caps how many different ports and hosts can be checked.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass

from .validate import ValidationError, normalize_ip, reject_mass_address

TIMEOUT = 3.0


class ResolveFailed(Exception):
    pass


@dataclass(frozen=True)
class Target:
    ip: str
    family: int
    sockaddr: tuple


def resolve(host: str, port: int) -> Target:
    """Resolve to ONE address. Raises ResolveFailed or ValidationError."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise ResolveFailed(str(exc)) from exc
    if not infos:
        raise ResolveFailed("no addresses")
    family, _, _, _, sockaddr = infos[0]
    ip = normalize_ip(ipaddress.ip_address(sockaddr[0].split("%")[0]))
    reject_mass_address(ip)  # a DNS name must not lead to broadcast/multicast either
    return Target(str(ip), family, sockaddr)


def check(host: str, port: int, target: Target, timeout: float = TIMEOUT) -> dict:
    start = time.monotonic()
    result: dict = {"host": host, "port": port, "ip": target.ip}
    sock = socket.socket(target.family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(target.sockaddr)
        elapsed = round((time.monotonic() - start) * 1000)
        result.update(
            status="open",
            connect_ms=elapsed,
            summary=f"Port {port} on {host} ({target.ip}) is open: connected in {elapsed} ms.",
        )
    except ConnectionRefusedError:
        result.update(
            status="closed",
            summary=f"{host} ({target.ip}) answered but refused port {port}: "
            "nothing is listening there.",
        )
    except (socket.timeout, TimeoutError):
        result.update(
            status="no_response",
            summary=f"No answer from {host}:{port} within {timeout:g} s. A firewall may be "
            "silently dropping the connection, or the host is down.",
        )
    except OSError as exc:
        result.update(
            status="error",
            summary=f"Could not connect to {host}:{port}: {exc.strerror or exc}.",
        )
    finally:
        sock.close()
    return result


def dns_failure(host: str, port: int) -> dict:
    return {
        "host": host,
        "port": port,
        "status": "dns_failure",
        "summary": f"Could not resolve {host}. Try dns_lookup to check DNS.",
    }


__all__ = ["Target", "ResolveFailed", "ValidationError", "resolve", "check", "dns_failure"]
