"""Offline guard: no test may start a real program or open a real network connection.

Tests that need command output patch netdoctor.runner.run (or subprocess.run
inside the runner tests) with canned output from tests/fixtures.
"""

import socket
import subprocess

import pytest


class RealNetworkUsed(AssertionError):
    pass


def _blocked(*args, **kwargs):
    raise RealNetworkUsed("tests must not start programs or touch the network")


@pytest.fixture(autouse=True)
def offline_guard(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _blocked)
    monkeypatch.setattr(subprocess, "Popen", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    yield
