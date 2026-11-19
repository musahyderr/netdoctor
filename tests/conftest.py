"""Offline guard: no test may start a real program or reach the network.

Tests that need command output patch netdoctor.runner.run (or subprocess.run
inside the runner tests) with canned output from tests/fixtures.

Loopback (127.0.0.1 / ::1) is allowed only because asyncio on Windows uses a
loopback socket pair internally; nothing can leave the machine.
"""

import socket
import subprocess

import pytest

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}
_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex


class RealNetworkUsed(AssertionError):
    pass


def _blocked(*args, **kwargs):
    raise RealNetworkUsed("tests must not start programs or touch the network")


def _loopback_only(real):
    def guarded(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in _LOOPBACK:
            raise RealNetworkUsed(f"tests must not connect to {host!r}")
        return real(self, address)

    return guarded


@pytest.fixture(autouse=True)
def offline_guard(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _blocked)
    monkeypatch.setattr(subprocess, "Popen", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    monkeypatch.setattr(socket.socket, "connect", _loopback_only(_real_connect))
    monkeypatch.setattr(socket.socket, "connect_ex", _loopback_only(_real_connect_ex))
    yield
