"""check_port: can this computer open a TCP connection to ONE port on ONE host.

This uses one ordinary TCP connection (the same as a browser opening a page),
then closes it at once. No data is sent. It is not a port scanner: the tool
takes exactly one host and one port, and the rate limiter caps how many
different ports one host can be asked about.
"""

from __future__ import annotations

import socket
import time

TIMEOUT = 3.0


def check(host: str, port: int, timeout: float = TIMEOUT) -> dict:
    start = time.monotonic()
    result: dict = {"host": host, "port": port}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            elapsed = (time.monotonic() - start) * 1000
            peer = sock.getpeername()
            result.update(
                status="open",
                connected_ip=peer[0],
                connect_ms=round(elapsed),
                summary=f"Port {port} on {host} is open: connected in {round(elapsed)} ms.",
            )
    except socket.gaierror:
        result.update(
            status="dns_failure",
            summary=f"Could not resolve {host}. Try dns_lookup to check DNS.",
        )
    except ConnectionRefusedError:
        result.update(
            status="closed",
            summary=f"{host} answered but refused port {port}: nothing is listening there.",
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
    return result
