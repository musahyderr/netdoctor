# Lessons

One entry per surprise or real bug: what happened, root cause, fix, and the rule that prevents it.

## 2026-11-19: `mcp` 2.x renamed FastMCP
- **What happened:** `from mcp.server.fastmcp import FastMCP` raised `ModuleNotFoundError` on a fresh install.
- **Root cause:** `mcp` 2.0 renamed `FastMCP` to `MCPServer` (`mcp.server.mcpserver`). Most tutorials still show the 1.x import.
- **Fix:** use `MCPServer`, pin `mcp>=2.3,<3`.
- **Rule:** check the installed SDK version and its API before writing code from memory or tutorials.

## 2026-11-19: bare `dict` return gives no structured output
- **What happened:** a tool annotated `-> dict` returned `structured_content=None`; only JSON text came back.
- **Root cause:** `MCPServer` builds an output schema only from parameterised types such as `dict[str, Any]`.
- **Fix:** annotate tools with `-> dict[str, Any]`; a test asserts `structured_content` is set.
- **Rule:** test the MCP round trip (`call_tool`), not just the Python function behind it.

## 2026-11-19: offline test guard broke asyncio on Windows
- **What happened:** async tests failed with "tests must not touch the network" before any tool ran.
- **Root cause:** the Windows Proactor event loop connects a loopback socket pair to itself; the guard blocked every `connect`.
- **Fix:** the guard allows 127.0.0.1 / ::1 only and still blocks every other address, `create_connection`, `getaddrinfo` and subprocess.
- **Rule:** an offline guard must block what leaves the machine, not the runtime's own loopback plumbing.

## 2026-11-19: real command output contains private addresses
- **What happened:** captured `tracert` output for fixtures held the developer's home router and ISP-internal IPs.
- **Fix:** replaced them with documentation ranges (192.168.1.1, 10.0.0.1, 198.51.100.0/24, 203.0.113.0/24) before committing.
- **Rule:** sanitise every captured fixture before it goes into a public repo.

## 2026-11-19: new repo picked up a personal email as commit author
- **What happened:** the first commits used the machine's global git email (a personal address), unlike the owner's other public repos.
- **Root cause:** `git init` inherits the global `user.email`; the other repos set a GitHub noreply address locally.
- **Fix:** set the noreply address in this repo's config and rewrote the unpushed commits with `--reset-author`.
- **Rule:** before the first push of a public repo, check `git log --format='%an <%ae>'`.

## 2026-11-19: security review found validation and rate-limit bypasses
- **What happened:** an independent review showed `0xffffffff`, `0x7f.0x1` and `127.1.a` passed as "hostnames" (resolvers read them as broadcast/loopback), IPv6 zone IDs like `fe80::1%-h` were accepted, the per-host port cap was keyed on the spelling (so `127.0.0.1`, `::ffff:127.0.0.1` and `localhost` each had their own budget), and up to ~20 checks could run at once.
- **Root cause:** validating the *text* of a host, and rate-limiting on that text, instead of on what it resolves to.
- **Fix:** last label must start with a letter and be 2+ characters; ASCII only; `%` rejected; IPv4-mapped IPv6 unwrapped; `check_port` resolves first, refuses broadcast/multicast results, keys limits on the resolved IP and connects to one address; caps on distinct hosts (10 per 10 min) and concurrent checks (2).
- **Rule:** enforce safety limits on the resolved target, never on user-supplied spelling. Get a second reviewer to attack the validator before release.

## 2026-11-19: the PyPI name was already taken
- **What happened:** `netdoctor` on PyPI belongs to an unrelated network-debugging tool, discovered only at publish time.
- **Fix:** publish as `netdoctor-mcp` (repo, import name and `netdoctor` command unchanged; added a `netdoctor-mcp` command so `uvx netdoctor-mcp` works).
- **Rule:** check the package-registry name (`https://pypi.org/pypi/<name>/json` returns 404 when free) before naming a project.
