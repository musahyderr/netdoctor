import pathlib

import pytest

from netdoctor import dns, ping, trace

FIX = pathlib.Path(__file__).parent / "fixtures"


def fx(name: str) -> str:
    return (FIX / name).read_bytes().decode("utf-8").replace("\r\n", "\n")


# ---------- ping ----------

@pytest.mark.parametrize(
    "fixture, sent, received, avg",
    [
        ("windows_ping_ok.txt", 2, 2, 17.0),
        ("linux_ping_ok.txt", 4, 4, 12.0),
        ("macos_ping_ok.txt", 3, 3, 14.5),
    ],
)
def test_ping_ok(fixture, sent, received, avg):
    r = ping.parse("1.1.1.1", sent, fx(fixture), "")
    assert r["sent"] == sent and r["received"] == received
    assert r["loss_percent"] == 0
    assert r["rtt_ms"]["avg"] == avg
    assert r["verdict"] == "good"


def test_ping_timeout_windows():
    r = ping.parse("10.255.255.1", 2, fx("windows_ping_timeout.txt"), "")
    assert r["received"] == 0 and r["loss_percent"] == 100
    assert r["verdict"] == "unreachable"


def test_ping_windows_unreachable_replies_are_not_successes():
    # Windows counts "Destination host unreachable" as Received; netdoctor must not.
    r = ping.parse("10.0.0.99", 4, fx("windows_ping_unreachable.txt"), "")
    assert r["received"] == 0 and r["verdict"] == "unreachable"


def test_ping_loss_and_latency_degraded():
    r = ping.parse("example.com", 4, fx("linux_ping_loss.txt"), "")
    assert r["loss_percent"] == 50
    assert r["verdict"] == "degraded"
    assert "packet loss" in r["summary"] and "high latency" in r["summary"]


@pytest.mark.parametrize(
    "stdout, stderr",
    [
        (fx("windows_ping_unknown_host.txt"), ""),
        ("", fx("linux_ping_unknown_host.stderr.txt")),
        ("", fx("macos_ping_unknown_host.stderr.txt")),
    ],
)
def test_ping_unknown_host(stdout, stderr):
    r = ping.parse("nosuchhost.invalid", 4, stdout, stderr)
    assert r["verdict"] == "dns_failure"


def test_ping_args():
    assert ping.build_args("windows", "1.1.1.1", 4) == ("ping", ["-n", "4", "-w", "2000", "1.1.1.1"])
    assert ping.build_args("linux", "1.1.1.1", 3) == ("ping", ["-n", "-c", "3", "-W", "2", "1.1.1.1"])
    assert ping.build_args("macos", "1.1.1.1", 3)[0] == "ping"
    assert ping.build_args("macos", "2606:4700:4700::1111", 3)[0] == "ping6"
    for os_name in ("windows", "linux", "macos"):
        assert ping.build_args(os_name, "example.com", 4)[1][-1] == "example.com"


# ---------- dns ----------

def test_dns_windows_a():
    r = dns.parse("example.com", "A", fx("windows_nslookup_a.txt"), "", 23)
    assert r["status"] == "ok"
    assert r["answers"] == ["172.66.147.243", "104.20.23.154"]
    assert r["resolver"] == "one.one.one.one"
    assert r["resolver_address"] == "2606:4700:4700::1111"


def test_dns_linux_a_excludes_resolver_address():
    r = dns.parse("example.com", "A", fx("linux_nslookup_a.txt"), "", 12)
    assert r["answers"] == ["172.66.147.243", "104.20.23.154"]
    assert r["resolver_address"] == "127.0.0.53"


def test_dns_linux_aaaa():
    r = dns.parse("example.com", "AAAA", fx("linux_nslookup_aaaa.txt"), "", 12)
    assert r["answers"] == ["2606:4700:10::6814:179a", "2606:4700:10::ac42:93f3"]


def test_dns_windows_mx_sorted_by_preference():
    r = dns.parse("gmail.com", "MX", fx("windows_nslookup_mx.txt"), "", 30)
    assert [a["preference"] for a in r["answers"]] == [5, 10, 20, 30, 40]
    assert r["answers"][0]["exchange"] == "gmail-smtp-in.l.google.com"
    assert "gmail-smtp-in.l.google.com (pref 5)" in r["summary"] and "{" not in r["summary"]


@pytest.mark.parametrize(
    "rtype, expected",
    [
        ("MX", [{"preference": 5, "exchange": "gmail-smtp-in.l.google.com"},
                {"preference": 10, "exchange": "alt1.gmail-smtp-in.l.google.com"}]),
        ("TXT", ["v=spf1 redirect=_spf.google.com"]),
        ("NS", ["ns1.google.com"]),
        ("CNAME", ["example.org"]),
    ],
)
def test_dns_linux_other_types(rtype, expected):
    r = dns.parse("gmail.com", rtype, fx("linux_nslookup_mx_txt_ns.txt"), "", 30)
    assert r["answers"] == expected


def test_dns_nxdomain():
    r = dns.parse("doesnotexist.invalid", "A", fx("windows_nslookup_nx.txt"),
                  fx("windows_nslookup_nx.stderr.txt"), 40)
    assert r["status"] == "nxdomain" and r["answers"] == []
    r = dns.parse("doesnotexist.invalid", "A", fx("linux_nslookup_nx.txt"), "", 40)
    assert r["status"] == "nxdomain"


def test_dns_timeout():
    r = dns.parse("example.com", "A", fx("linux_nslookup_timeout.txt"), "", 6000)
    assert r["status"] == "timeout"


def test_dns_slow_lookup_flagged():
    r = dns.parse("example.com", "A", fx("windows_nslookup_a.txt"), "", 900)
    assert "slow" in r["summary"]


def test_dns_args_put_name_after_options():
    prog, args = dns.build_args("example.com", "MX", "1.1.1.1")
    assert prog == "nslookup"
    assert args == ["-type=MX", "-timeout=3", "-retry=1", "example.com", "1.1.1.1"]


# ---------- traceroute ----------

def test_trace_windows():
    r = trace.parse("1.1.1.1", fx("windows_tracert.txt"))
    assert r["hop_count"] == 4
    assert [h["ip"] for h in r["hops"]] == ["192.168.1.1", "10.0.0.1", "198.51.100.8", "203.0.113.204"]
    assert r["hops"][1]["avg_ms"] == 6.0
    assert r["reached"] is False  # trace was cut at 4 hops


def test_trace_windows_with_timeouts_and_jump():
    r = trace.parse("example.com", fx("windows_tracert_timeouts.txt"))
    assert r["destination_ip"] == "93.184.215.14"
    assert r["reached"] is True
    assert r["hops"][0]["avg_ms"] == 0.5
    assert r["hops"][1] == {"hop": 2, "ip": None, "avg_ms": None, "lost_probes": 3}
    assert r["hops"][3]["lost_probes"] == 1
    assert "Biggest delay jump" in r["summary"]


@pytest.mark.parametrize(
    "fixture, host, hops, reached",
    [
        ("linux_traceroute.txt", "example.com", 5, True),
        ("macos_traceroute.txt", "1.1.1.1", 4, True),
        ("linux_tracepath.txt", "1.1.1.1", 4, True),
    ],
)
def test_trace_unix(fixture, host, hops, reached):
    r = trace.parse(host, fx(fixture))
    assert r["hop_count"] == hops
    assert r["reached"] is reached
    assert r["hops"][0]["ip"] == "192.168.1.1"
    assert any(h["avg_ms"] is None for h in r["hops"])


def test_trace_args():
    assert trace.build_args("windows", "1.1.1.1", 15, "tracert") == ["-d", "-h", "15", "-w", "1000", "1.1.1.1"]
    assert trace.build_args("linux", "1.1.1.1", 15, "tracepath") == ["-n", "-m", "15", "1.1.1.1"]
    assert trace.build_args("macos", "1.1.1.1", 15, "traceroute")[-1] == "1.1.1.1"
    assert trace.timeout_for(30) == 120
