import socket

import pytest

from netdoctor import port
from netdoctor.validate import ValidationError


def fake_getaddrinfo(ip, family=socket.AF_INET):
    def fake(host, p, type=0):
        return [(family, socket.SOCK_STREAM, 6, "", (ip, p))]

    return fake


class FakeSocket:
    instances = []

    def __init__(self, family, kind, exc=None):
        self.family, self.exc, self.connected, self.closed = family, exc, None, False
        FakeSocket.instances.append(self)

    def settimeout(self, t):
        self.timeout = t

    def connect(self, addr):
        if self.exc:
            raise self.exc
        self.connected = addr

    def close(self):
        self.closed = True


def patch_socket(monkeypatch, exc=None):
    FakeSocket.instances = []
    monkeypatch.setattr(port.socket, "socket", lambda f, k: FakeSocket(f, k, exc))


def test_resolve_takes_one_address(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo("93.184.215.14"))
    t = port.resolve("example.com", 443)
    assert t.ip == "93.184.215.14" and t.sockaddr == ("93.184.215.14", 443)


def test_resolve_normalises_mapped_ipv6(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo("::ffff:127.0.0.1", socket.AF_INET6))
    assert port.resolve("localhost", 80).ip == "127.0.0.1"


@pytest.mark.parametrize("ip", ["255.255.255.255", "224.0.0.1", "192.168.1.255"])
def test_resolve_refuses_names_pointing_at_broadcast(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo(ip))
    with pytest.raises(ValidationError):
        port.resolve("evil.example", 80)


def test_resolve_failure(monkeypatch):
    def fail(*a, **k):
        raise socket.gaierror("nope")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(port.ResolveFailed):
        port.resolve("nosuchhost.invalid", 80)


def test_open_makes_exactly_one_connection(monkeypatch):
    patch_socket(monkeypatch)
    target = port.Target("93.184.215.14", socket.AF_INET, ("93.184.215.14", 443))
    r = port.check("example.com", 443, target)
    assert r["status"] == "open"
    assert len(FakeSocket.instances) == 1
    s = FakeSocket.instances[0]
    assert s.connected == ("93.184.215.14", 443) and s.closed and s.timeout == 3.0


@pytest.mark.parametrize(
    "exc, status",
    [
        (ConnectionRefusedError(), "closed"),
        (socket.timeout(), "no_response"),
        (TimeoutError(), "no_response"),
        (OSError(51, "Network is unreachable"), "error"),
    ],
)
def test_failures_close_the_socket(monkeypatch, exc, status):
    patch_socket(monkeypatch, exc)
    target = port.Target("93.184.215.14", socket.AF_INET, ("93.184.215.14", 443))
    assert port.check("example.com", 443, target)["status"] == status
    assert FakeSocket.instances[0].closed
