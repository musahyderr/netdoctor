"""traceroute: where along the path does traffic slow down or stop."""

from __future__ import annotations

import ipaddress
import re
import statistics

_HOP = re.compile(r"^\s*(\d+)\??:?\s+(.*)$")
_RTT = re.compile(r"(<?)([\d.]+)\s*ms", re.IGNORECASE)
_DEST = re.compile(r"(?:Tracing route to|traceroute to)\s+\S+\s+[\[(]([^\])]+)[\])]", re.IGNORECASE)
_DEST_IP_ONLY = re.compile(r"(?:Tracing route to|traceroute to)\s+(\S+)", re.IGNORECASE)


def build_args(os_name: str, host: str, max_hops: int, program: str) -> list[str]:
    """Fixed flags only: numeric output (no reverse lookups), hop limit, 1 s wait."""
    if os_name == "windows":
        return ["-d", "-h", str(max_hops), "-w", "1000", host]
    if program == "tracepath":
        return ["-n", "-m", str(max_hops), host]
    return ["-n", "-m", str(max_hops), "-w", "1", "-q", "3", host]


def timeout_for(max_hops: int) -> float:
    return min(120.0, max_hops * 4 + 10)


def parse(host: str, stdout: str, timed_out: bool = False) -> dict:
    dest_ip = _destination(stdout)
    hops: dict[int, dict] = {}
    for line in stdout.split("\n"):
        if "LOCALHOST" in line or line.strip().startswith("Resume"):
            continue
        m = _HOP.match(line)
        if not m:
            continue
        number, rest = int(m.group(1)), m.group(2)
        ip = _first_ip(rest)
        rtts = [0.5 if lt else float(v) for lt, v in _RTT.findall(rest)]
        lost = rest.count("*") + (1 if "no reply" in rest.lower() else 0)
        hop = hops.setdefault(number, {"hop": number, "ip": None, "rtts": [], "lost": 0})
        hop["ip"] = hop["ip"] or ip
        hop["rtts"].extend(rtts)
        hop["lost"] += lost

    hop_list = []
    for number in sorted(hops):
        h = hops[number]
        entry: dict = {"hop": number, "ip": h["ip"]}
        if h["rtts"]:
            entry["avg_ms"] = round(statistics.fmean(h["rtts"]), 1)
        else:
            entry["avg_ms"] = None
        if h["lost"]:
            entry["lost_probes"] = h["lost"]
        hop_list.append(entry)

    reached = bool(
        hop_list
        and hop_list[-1]["ip"]
        and (hop_list[-1]["ip"] == dest_ip or hop_list[-1]["ip"] == host or "reached" in stdout)
    )
    result = {
        "host": host,
        "destination_ip": dest_ip,
        "reached": reached,
        "hop_count": len(hop_list),
        "hops": hop_list,
    }
    result["summary"] = _summary(host, result, timed_out)
    return result


def _destination(stdout: str) -> str | None:
    m = _DEST.search(stdout)
    if m:
        return m.group(1).strip()
    m = _DEST_IP_ONLY.search(stdout)
    if m and _first_ip(m.group(1)):
        return m.group(1)
    return None


def _first_ip(text: str) -> str | None:
    for token in re.split(r"[\s()\[\],]+", text):
        try:
            return str(ipaddress.ip_address(token))
        except ValueError:
            continue
    return None


def _summary(host: str, r: dict, timed_out: bool) -> str:
    hops = r["hops"]
    if not hops:
        return f"No route information for {host}" + (" (timed out)." if timed_out else ".")
    parts = []
    if r["reached"]:
        parts.append(f"Reached {host} in {r['hop_count']} hops.")
    else:
        parts.append(
            f"Did not reach {host} within {r['hop_count']} hops"
            + (" (timed out)" if timed_out else "")
            + ". Many servers ignore traceroute probes, so this alone is not proof of a fault."
        )
    silent = [h["hop"] for h in hops if h["avg_ms"] is None]
    if silent:
        parts.append(
            f"Hops {', '.join(map(str, silent))} did not answer; routers often skip "
            "these replies, which is normal if later hops respond."
        )
    timed = [h for h in hops if h["avg_ms"] is not None]
    jumps = [(b["avg_ms"] - a["avg_ms"], a, b) for a, b in zip(timed, timed[1:])]
    if jumps:
        rise, before, after = max(jumps, key=lambda j: j[0])
        if rise >= 50:
            parts.append(
                f"Biggest delay jump: +{rise:.0f} ms between hop {before['hop']} "
                f"and hop {after['hop']} ({after['ip']})."
            )
    first = timed[0] if timed else None
    if first and first["hop"] == 1 and first["avg_ms"] > 20:
        parts.append(
            f"The first hop (usually your router) takes {first['avg_ms']:g} ms; "
            "on a healthy home network it is under 5 ms, which points to Wi-Fi or router trouble."
        )
    return " ".join(parts)
