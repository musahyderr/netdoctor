"""ping: is a host reachable, how fast, how steady."""

from __future__ import annotations

import ipaddress
import re
import statistics

_TIME = re.compile(r"time\s*([=<])\s*([\d.]+)\s*ms", re.IGNORECASE)
_WIN_SENT = re.compile(r"Sent\s*=\s*(\d+)", re.IGNORECASE)
_UNIX_SENT = re.compile(r"(\d+)\s+packets transmitted", re.IGNORECASE)
_UNKNOWN_HOST = re.compile(
    r"could not find host|Name or service not known|cannot resolve|Unknown host|"
    r"Temporary failure in name resolution|No address associated",
    re.IGNORECASE,
)


def build_args(os_name: str, host: str, count: int) -> tuple[str, list[str]]:
    """Return (program, args). Only fixed flags; the host is the last argument."""
    if os_name == "windows":
        return "ping", ["-n", str(count), "-w", "2000", host]
    is_v6 = ":" in host and _is_ip(host)
    if os_name == "macos":
        # macOS: -W is the wait time in milliseconds; IPv6 needs ping6.
        if is_v6:
            return "ping6", ["-n", "-c", str(count), host]
        return "ping", ["-n", "-c", str(count), "-W", "2000", host]
    return "ping", ["-n", "-c", str(count), "-W", "2", host]


def timeout_for(count: int) -> float:
    return count * 3 + 5


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse(host: str, count: int, stdout: str, stderr: str, timed_out: bool = False) -> dict:
    text = f"{stdout}\n{stderr}"
    if _UNKNOWN_HOST.search(text):
        return {
            "host": host,
            "reachable": False,
            "verdict": "dns_failure",
            "summary": f"Could not resolve {host}: the name lookup failed, so no ping was sent. "
            "Try dns_lookup to see whether DNS is the problem.",
        }

    times = [float(m.group(2)) for m in _TIME.finditer(stdout)]
    sent_match = _WIN_SENT.search(stdout) or _UNIX_SENT.search(stdout)
    sent = int(sent_match.group(1)) if sent_match else count
    received = len(times)
    loss = round(100.0 * (sent - received) / sent, 1) if sent else 100.0

    result: dict = {
        "host": host,
        "sent": sent,
        "received": received,
        "loss_percent": loss,
        "reachable": received > 0,
    }
    if times:
        result["rtt_ms"] = {
            "min": round(min(times), 1),
            "avg": round(statistics.fmean(times), 1),
            "max": round(max(times), 1),
            "jitter": round(_jitter(times), 1),
        }
    result["verdict"], result["summary"] = _verdict(host, result, timed_out)
    return result


def _jitter(times: list[float]) -> float:
    if len(times) < 2:
        return 0.0
    return statistics.fmean(abs(b - a) for a, b in zip(times, times[1:]))


def _verdict(host: str, r: dict, timed_out: bool) -> tuple[str, str]:
    if not r["reachable"]:
        why = " (the check timed out)" if timed_out else ""
        return (
            "unreachable",
            f"No replies from {host}{why}. The host may be down, blocking ping (ICMP), "
            "or your connection may be broken. Try pinging your router and a public "
            "address such as 1.1.1.1 to narrow it down.",
        )
    rtt = r["rtt_ms"]
    problems = []
    if r["loss_percent"] > 0:
        problems.append(f"{r['loss_percent']:g}% packet loss")
    if rtt["avg"] > 150:
        problems.append(f"high latency (avg {rtt['avg']:g} ms)")
    if rtt["jitter"] > 30:
        problems.append(f"unstable latency (jitter {rtt['jitter']:g} ms)")
    if problems:
        return "degraded", f"{host} is reachable but with " + ", ".join(problems) + "."
    return (
        "good",
        f"{host} is reachable: {r['received']}/{r['sent']} replies, "
        f"avg {rtt['avg']:g} ms, jitter {rtt['jitter']:g} ms.",
    )
