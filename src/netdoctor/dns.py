"""dns_lookup: does a name resolve, to what, and how quickly."""

from __future__ import annotations

import ipaddress
import re

_SERVER = re.compile(r"^Server:\s+(\S+)", re.MULTILINE)
_SERVER_ADDR = re.compile(r"^Server:.*\n\s*Address(?:es)?:\s+(\S+)", re.MULTILINE)
_MX_WIN = re.compile(r"MX preference\s*=\s*(\d+),\s*mail exchanger\s*=\s*(\S+)", re.IGNORECASE)
_MX_UNIX = re.compile(r"mail exchanger\s*=\s*(\d+)\s+(\S+)", re.IGNORECASE)
_TXT = re.compile(r'text\s*=\s*\n?\s*"(.*)"', re.IGNORECASE)
_NS = re.compile(r"nameserver\s*=\s*(\S+)", re.IGNORECASE)
_CNAME = re.compile(r"canonical name\s*=\s*(\S+)", re.IGNORECASE)
_NXDOMAIN = re.compile(r"Non-existent domain|NXDOMAIN", re.IGNORECASE)
_TIMEOUT = re.compile(r"timed out|no servers could be reached|DNS request timed out", re.IGNORECASE)
_SERVFAIL = re.compile(r"SERVFAIL|Server failed", re.IGNORECASE)
_NO_DATA = re.compile(r"No answer|has no \S+ record|No \S+ records? available", re.IGNORECASE)


def build_args(name: str, record_type: str, server: str | None) -> tuple[str, list[str]]:
    """Same flags on Windows, macOS and Linux nslookup. The name comes after all options."""
    args = [f"-type={record_type}", "-timeout=3", "-retry=1", name]
    if server:
        args.append(server)
    return "nslookup", args


TIMEOUT = 15.0


def parse(
    name: str,
    record_type: str,
    stdout: str,
    stderr: str,
    elapsed_ms: float,
    timed_out: bool = False,
) -> dict:
    text = f"{stdout}\n{stderr}"
    server = _SERVER.search(stdout)
    server_addr = _SERVER_ADDR.search(stdout)
    result: dict = {
        "name": name,
        "record_type": record_type,
        "resolver": server.group(1) if server else None,
        "resolver_address": server_addr.group(1).split("#")[0] if server_addr else None,
        "query_time_ms": round(elapsed_ms),
    }

    answers = _answers(record_type, stdout)
    if answers:
        result["answers"] = answers
        result["status"] = "ok"
        slow = elapsed_ms > 500
        shown = [
            f"{a['exchange']} (pref {a['preference']})" if isinstance(a, dict) else str(a)
            for a in answers[:5]
        ]
        result["summary"] = (
            f"{name} resolved ({record_type}) to {', '.join(shown)}"
            + (" and more" if len(answers) > 5 else "")
            + f" in {round(elapsed_ms)} ms"
            + (" — slow; a lookup normally takes under 100 ms." if slow else ".")
        )
        return result

    result["answers"] = []
    if _NXDOMAIN.search(text):
        result["status"] = "nxdomain"
        result["summary"] = f"{name} does not exist (NXDOMAIN). Check the spelling."
    elif timed_out or _TIMEOUT.search(text):
        result["status"] = "timeout"
        result["summary"] = (
            "The DNS server did not answer. DNS may be broken on this network; "
            "try again with server='1.1.1.1' to compare with a public resolver."
        )
    elif _SERVFAIL.search(text):
        result["status"] = "servfail"
        result["summary"] = f"The DNS server failed to answer for {name} (SERVFAIL)."
    else:
        result["status"] = "no_records"
        result["summary"] = f"{name} exists but has no {record_type} records."
    return result


def _answers(record_type: str, stdout: str) -> list:
    body = _strip_server_block(stdout)
    if record_type in ("A", "AAAA"):
        return _addresses(body, 6 if record_type == "AAAA" else 4)
    if record_type == "MX":
        found = _MX_WIN.findall(body) or _MX_UNIX.findall(body)
        mx = sorted({(int(pref), host.rstrip(".")) for pref, host in found})
        return [{"preference": pref, "exchange": host} for pref, host in mx]
    if record_type == "TXT":
        return _TXT.findall(body)
    if record_type == "NS":
        return sorted({h.rstrip(".") for h in _NS.findall(body)})
    if record_type == "CNAME":
        return [h.rstrip(".") for h in _CNAME.findall(body)]
    return []


def _strip_server_block(stdout: str) -> str:
    lines = stdout.split("\n")
    out = []
    skip_next_address = False
    for line in lines:
        if line.startswith("Server:"):
            skip_next_address = True
            continue
        if skip_next_address and line.lstrip().startswith("Address"):
            skip_next_address = False
            continue
        skip_next_address = False
        out.append(line)
    return "\n".join(out)


def _addresses(body: str, version: int) -> list[str]:
    found: list[str] = []
    in_answer = False
    for line in body.split("\n"):
        if line.startswith("Name:") or "has AAAA address" in line or "has address" in line:
            in_answer = True
        if line.startswith("Aliases:"):
            in_answer = False
        if not in_answer:
            continue
        for token in re.split(r"[\s,]+", line):
            try:
                ip = ipaddress.ip_address(token)
            except ValueError:
                continue
            if ip.version == version and str(ip) not in found:
                found.append(str(ip))
    return found
