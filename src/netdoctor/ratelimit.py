"""Rate limits, so netdoctor can never be used to flood or scan.

Limits (all in-memory, reset when the server restarts):
- at least MIN_INTERVAL seconds between any two checks;
- at most PER_MINUTE checks of any kind in a rolling minute;
- port checks: at most PORT_PER_MINUTE a minute, at most
  DISTINCT_PORTS_PER_HOST different ports on one host, and at most
  DISTINCT_HOSTS different hosts, in any PORT_WINDOW seconds. Port limits are
  keyed on the resolved IP address, so other spellings of a host share its budget.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable

MIN_INTERVAL = 1.0
PER_MINUTE = 20
PORT_PER_MINUTE = 10
DISTINCT_PORTS_PER_HOST = 5
DISTINCT_HOSTS = 10
PORT_WINDOW = 600.0


class RateLimited(Exception):
    """Raised when a call would break a limit. The message is safe to show the user."""

    def __init__(self, message: str, retry_after: float):
        super().__init__(message)
        self.retry_after = max(0.0, retry_after)


class RateLimiter:
    def __init__(
        self,
        clock: Callable[[], float] = time.monotonic,
        min_interval: float = MIN_INTERVAL,
        per_minute: int = PER_MINUTE,
        port_per_minute: int = PORT_PER_MINUTE,
        distinct_ports_per_host: int = DISTINCT_PORTS_PER_HOST,
        distinct_hosts: int = DISTINCT_HOSTS,
        port_window: float = PORT_WINDOW,
    ):
        self._clock = clock
        self._min_interval = min_interval
        self._per_minute = per_minute
        self._port_per_minute = port_per_minute
        self._distinct_ports = distinct_ports_per_host
        self._distinct_hosts = distinct_hosts
        self._port_window = port_window
        self._lock = threading.Lock()
        self._calls: deque[float] = deque()
        self._port_calls: deque[tuple[float, str, int]] = deque()

    def acquire(self, tool: str) -> None:
        """General limits for every check. Records the call, or raises without recording."""
        with self._lock:
            now = self._clock()
            self._expire(now)
            if self._calls and now - self._calls[-1] < self._min_interval:
                wait = self._min_interval - (now - self._calls[-1])
                raise RateLimited(f"Please wait {wait:.1f}s between checks.", wait)
            if len(self._calls) >= self._per_minute:
                wait = 60.0 - (now - self._calls[0])
                raise RateLimited(
                    f"Limit of {self._per_minute} checks per minute reached; "
                    f"try again in {wait:.0f}s.",
                    wait,
                )
            self._calls.append(now)

    def acquire_port(self, ip: str, port: int) -> None:
        """Port-check limits, keyed on the resolved IP. Call after acquire()."""
        with self._lock:
            now = self._clock()
            self._expire(now)

            recent = [t for t, _, _ in self._port_calls if now - t < 60.0]
            if len(recent) >= self._port_per_minute:
                wait = 60.0 - (now - recent[0])
                raise RateLimited(
                    f"Limit of {self._port_per_minute} port checks per minute reached; "
                    f"try again in {wait:.0f}s.",
                    wait,
                )

            ports_on_host = {p for _, h, p in self._port_calls if h == ip}
            if port not in ports_on_host and len(ports_on_host) >= self._distinct_ports:
                oldest = min(t for t, h, _ in self._port_calls if h == ip)
                raise RateLimited(
                    f"netdoctor is not a port scanner: at most {self._distinct_ports} "
                    f"different ports per host every {self._port_window / 60:.0f} minutes.",
                    self._port_window - (now - oldest),
                )

            hosts = {h for _, h, _ in self._port_calls}
            if ip not in hosts and len(hosts) >= self._distinct_hosts:
                raise RateLimited(
                    f"netdoctor is not a network scanner: port checks are limited to "
                    f"{self._distinct_hosts} different hosts every "
                    f"{self._port_window / 60:.0f} minutes.",
                    self._port_window - (now - self._port_calls[0][0]),
                )

            self._port_calls.append((now, ip, port))

    def _expire(self, now: float) -> None:
        while self._calls and now - self._calls[0] >= 60.0:
            self._calls.popleft()
        while self._port_calls and now - self._port_calls[0][0] >= self._port_window:
            self._port_calls.popleft()
