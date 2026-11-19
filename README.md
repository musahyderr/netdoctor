# netdoctor

[![CI](https://github.com/musahyderr/netdoctor/actions/workflows/ci.yml/badge.svg)](https://github.com/musahyderr/netdoctor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Windows | macOS | Linux](https://img.shields.io/badge/os-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

**Ask Claude why your internet is slow, and let it check.**

netdoctor is a small [MCP](https://modelcontextprotocol.io) server that gives Claude four
safe, read-only network checks: `ping`, `dns_lookup`, `traceroute` and `check_port`.
Claude runs them on your computer, reads the summarised results, and tells you where the
problem is: your Wi-Fi, your router, your ISP, DNS, or the site itself.

<!-- Demo GIF goes here: ![netdoctor demo](docs/demo.gif) -->

```text
You:    My internet feels really slow today.
Claude: (pings your router, then 1.1.1.1, looks up a name, traces the route)
        Your router answers in 2 ms, so Wi-Fi is fine. Latency jumps from 9 ms to
        180 ms at hop 3, inside your ISP's network, and 1.1.1.1 shows 20% packet
        loss. DNS is fast. The slowdown is on your ISP's side.
```

## Safe by design

| Promise | How it is kept |
|---|---|
| **Runs locally** | The server runs on your computer over stdio. It has no web server and listens on no port. |
| **Sends nothing anywhere** | No telemetry, no analytics, no update checks, no server owned by this project. The only traffic is the check you asked for. Results go only to your own Claude session. A test fails the build if any web or HTTP library is imported. |
| **Read-only** | It never changes settings, installs anything or writes files. It has no "fix it" features: no DNS changes, no adapter resets. |
| **No admin rights** | Every check works as a normal user. |
| **Not a scanning tool** | `check_port` takes exactly one host and one port. Ranges, lists and CIDR blocks are rejected. One host can be asked about at most 5 different ports every 10 minutes. |
| **Can't flood** | All tools are rate-limited: at least 1 second between checks, at most 20 a minute, port checks at most 10 a minute. `ping` sends at most 10 packets. |
| **Can't run other commands** | Only the programs listed below can run, from fixed system folders (never from `PATH`), with fixed arguments and `shell=False`. Inputs that start with `-` (command options) are rejected. Tests check all of this. |

### Why it is not a port scanner

Port scanning means knocking on many doors to see which ones open. Network owners treat
it as a sign of attack, and it can get you blocked or in trouble. netdoctor only answers
"can I reach *this one* service?" (for example, "is port 443 on my website reachable?").
It opens one normal TCP connection, the same as a browser does, closes it at once and
sends no data. The rate limiter refuses requests that look like a scan, so it can't be
turned into one, even by mistake.

## Every command netdoctor can run

These are the only programs it can start. `<host>` is always one validated hostname or IP
address, and the numbers are bounded.

| Tool | Windows | macOS | Linux |
|---|---|---|---|
| `ping` | `C:\Windows\System32\PING.EXE -n <1-10> -w 2000 <host>` | `/sbin/ping -n -c <1-10> -W 2000 <host>` (IPv6: `/sbin/ping6 -n -c <1-10> <host>`) | `/usr/bin/ping -n -c <1-10> -W 2 <host>` |
| `dns_lookup` | `C:\Windows\System32\nslookup.exe -type=<T> -timeout=3 -retry=1 <name> [server]` | `/usr/bin/nslookup` (same flags) | `/usr/bin/nslookup` (same flags) |
| `traceroute` | `C:\Windows\System32\TRACERT.EXE -d -h <1-30> -w 1000 <host>` | `/usr/sbin/traceroute -n -m <1-30> -w 1 -q 3 <host>` | `traceroute -n -m <1-30> -w 1 -q 3 <host>`, or `tracepath -n -m <1-30> <host>` if traceroute is missing |
| `check_port` | no program: one TCP connection from Python, 3-second timeout | same | same |

`<T>` is one of `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`. On Linux the program may also be
found in `/bin` or `/usr/sbin`; the full list is in
[`src/netdoctor/runner.py`](src/netdoctor/runner.py).

## Install

You need Python 3.10+ and [uv](https://docs.astral.sh/uv/) (for `uvx`).

**Claude Code** (one line):

```bash
claude mcp add netdoctor -- uvx --from git+https://github.com/musahyderr/netdoctor netdoctor
```

**Claude Desktop**: add this to `claude_desktop_config.json` (Settings → Developer → Edit Config), then restart Claude Desktop:

```json
{
  "mcpServers": {
    "netdoctor": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/musahyderr/netdoctor", "netdoctor"]
    }
  }
}
```

**Without uv** (using pipx):

```bash
pipx install git+https://github.com/musahyderr/netdoctor
```

```bash
claude mcp add netdoctor -- netdoctor
```

## Tools

| Tool | Arguments | What you get back |
|---|---|---|
| `ping` | `host`, `count` (1-10, default 4) | replies, packet loss, min/avg/max latency, jitter, a verdict (`good`, `degraded`, `unreachable`, `dns_failure`) and a one-line summary |
| `dns_lookup` | `name`, `record_type` (default `A`), `server` (optional, e.g. `1.1.1.1`) | answers, which resolver replied, lookup time, status (`ok`, `nxdomain`, `timeout`, `servfail`, `no_records`) |
| `traceroute` | `host`, `max_hops` (1-30, default 15) | each hop's IP and average delay, silent hops, whether the target was reached, the biggest delay jump |
| `check_port` | `host`, `port` (one port, 1-65535) | `open`, `closed`, `no_response`, `dns_failure` or `error`, connect time |

Every result has `ok: true/false`. Rejected or rate-limited calls come back with
`ok: false` and a plain-English `error`, and nothing is run.

Try asking Claude things like:

- "My internet is slow. Can you figure out why?"
- "Is it my DNS? Compare my DNS with 1.1.1.1."
- "Why can't I reach github.com?"
- "Is port 443 open on example.com?"

## Development

```bash
python -m venv .venv
```

```bash
.venv/bin/pip install -e ".[test]"      # Windows: .venv\Scripts\pip
```

```bash
.venv/bin/pytest -q
```

The tests never touch the network or start a real program. A guard in
`tests/conftest.py` makes any such attempt fail, and command output comes from captured
samples in `tests/fixtures/`. `tests/test_safety.py` reads the source code itself to
prove the safety rules: only `runner.py` may import `subprocess`, `shell=True` never
appears, there is no `eval`/`exec`/`os.system`, and no web libraries are used. CI runs
on Ubuntu, Windows and macOS.

Known limitation: the parsers expect English command output. On Windows set to another
language, results still come back but some fields may be empty.

## Security

See [SECURITY.md](SECURITY.md) to report a problem privately.

## License

[MIT](LICENSE) © Syed Musa Hyder. Provided "as is", without warranty of any kind.
