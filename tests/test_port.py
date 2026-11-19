import socket

import pytest

from netdoctor import port


class FakeSock:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def getpeername(self):
        return ("93.184.215.14", 443)


def test_open(monkeypatch):
    calls = []

    def fake(addr, timeout):
        calls.append((addr, timeout))
        return FakeSock()

    monkeypatch.setattr(socket, "create_connection", fake)
    r = port.check("example.com", 443)
    assert r["status"] == "open" and r["connected_ip"] == "93.184.215.14"
    assert calls == [(("example.com", 443), 3.0)]  # exactly one connection


@pytest.mark.parametrize(
    "exc, status",
    [
        (ConnectionRefusedError(), "closed"),
        (socket.timeout(), "no_response"),
        (TimeoutError(), "no_response"),
        (socket.gaierror(), "dns_failure"),
        (OSError(51, "Network is unreachable"), "error"),
    ],
)
def test_failures(monkeypatch, exc, status):
    def fake(addr, timeout):
        raise exc

    monkeypatch.setattr(socket, "create_connection", fake)
    assert port.check("example.com", 443)["status"] == status
