import pytest

from netdoctor import runner, server
from netdoctor.ratelimit import RateLimiter
from netdoctor.runner import CommandResult


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        self.now += 2.0  # every call is 2s after the last, so the 1s gap never trips
        return self.now


@pytest.fixture
def calls(monkeypatch):
    seen = []

    def fake_run(name, args, timeout):
        seen.append((name, args, timeout))
        return CommandResult([name, *args], 0, "", "", False)

    monkeypatch.setattr(runner, "run", fake_run)
    monkeypatch.setattr(runner, "current_os", lambda: "windows")
    return seen


@pytest.fixture
def doctor():
    return server.Doctor(RateLimiter(clock=FakeClock()))


def test_ping_runs_fixed_command(doctor, calls):
    r = doctor.ping("1.1.1.1", 2)
    assert r["ok"] is True
    assert calls == [("ping", ["-n", "2", "-w", "2000", "1.1.1.1"], 11)]


def test_invalid_input_never_runs_anything(doctor, calls):
    for bad in ("-t 1.1.1.1", "1.1.1.0/24", "a.com,b.com", "1.1.1.1 && calc"):
        r = doctor.ping(bad)
        assert r["ok"] is False and r["error"].startswith("Rejected input")
    assert doctor.ping("1.1.1.1", 50)["ok"] is False
    assert doctor.traceroute("1.1.1.1", 99)["ok"] is False
    assert doctor.dns_lookup("example.com", "AXFR")["ok"] is False
    assert doctor.dns_lookup("example.com", "A", "-server")["ok"] is False
    assert doctor.check_port("example.com", "1-1024")["ok"] is False
    assert doctor.check_port("example.com", [80, 443])["ok"] is False
    assert calls == []


def test_rate_limit_is_enforced_end_to_end(calls):
    d = server.Doctor(RateLimiter(clock=lambda: 100.0))  # frozen clock
    assert d.ping("1.1.1.1")["ok"] is True
    r = d.ping("1.1.1.1")
    assert r["ok"] is False and "retry_after_s" in r
    assert len(calls) == 1


def test_port_scan_blocked_end_to_end_across_spellings(doctor, monkeypatch):
    # Every spelling of the machine resolves to the same IP, so they share one budget.
    monkeypatch.setattr(
        server.port, "resolve",
        lambda h, p: server.port.Target("203.0.113.5", 2, ("203.0.113.5", p)),
    )
    monkeypatch.setattr(server.port, "check", lambda h, p, t: {"host": h, "port": p, "status": "closed"})
    spellings = ["example.com", "www.example.com", "203.0.113.5", "::ffff:203.0.113.5", "alias.example"]
    for name, p in zip(spellings, (21, 22, 23, 25, 80)):
        assert doctor.check_port(name, p)["ok"] is True
    r = doctor.check_port("other-name.example", 443)
    assert r["ok"] is False and "not a port scanner" in r["error"]


def test_concurrent_checks_are_capped(doctor, calls):
    doctor._slots.acquire()
    doctor._slots.acquire()
    r = doctor.ping("1.1.1.1")
    assert r["ok"] is False and "already running" in r["error"]
    assert calls == []
    doctor._slots.release()
    doctor._slots.release()
    assert doctor.ping("1.1.1.1")["ok"] is True


def test_unexpected_value_error_is_reported_not_raised(doctor, monkeypatch):
    def boom(*a, **k):
        raise ValueError("arguments must not contain control characters")

    monkeypatch.setattr(runner, "run", boom)
    monkeypatch.setattr(runner, "current_os", lambda: "windows")
    r = doctor.ping("1.1.1.1")
    assert r["ok"] is False and "control characters" in r["error"]


def test_dns_and_trace_commands(doctor, calls):
    doctor.dns_lookup("example.com", "mx", "1.1.1.1")
    doctor.traceroute("example.com", 10)
    assert calls[0][:2] == ("nslookup", ["-type=MX", "-timeout=3", "-retry=1", "example.com", "1.1.1.1"])
    assert calls[1][:2] == ("tracert", ["-d", "-h", "10", "-w", "1000", "example.com"])


def test_missing_program_reported(doctor, monkeypatch):
    def missing(name, args, timeout):
        raise runner.ProgramNotFound("tracert was not found")

    monkeypatch.setattr(runner, "run", missing)
    monkeypatch.setattr(runner, "current_os", lambda: "windows")
    r = doctor.traceroute("example.com")
    assert r == {"ok": False, "error": "tracert was not found"}


async def test_mcp_lists_exactly_four_read_only_tools():
    mcp = server.build_server()
    tools = await mcp.list_tools()
    assert sorted(t.name for t in tools) == ["check_port", "dns_lookup", "ping", "traceroute"]
    for t in tools:
        assert t.annotations.read_only_hint is True
        assert t.annotations.destructive_hint is False


async def test_mcp_call_tool_round_trip(calls):
    mcp = server.build_server(server.Doctor(RateLimiter(clock=FakeClock())))
    result = await mcp.call_tool("ping", {"host": "1.1.1.1", "count": 1})
    assert result.structured_content["ok"] is True
    assert calls[0][0] == "ping"
