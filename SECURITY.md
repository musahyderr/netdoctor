# Security policy

netdoctor's whole point is to be safe to run: read-only, local-only, no admin rights,
and unable to scan or flood. If you find a way around any of that, please tell me.

## What counts as a security problem

- Running any program, or any arguments, other than those listed in the README.
- Getting a tool to change settings, write files, or need admin rights.
- Getting around input validation (for example sneaking in a command option, a host list
  or a port range).
- Getting around the rate limits, or using `check_port` as a port scanner.
- netdoctor sending data anywhere other than the check the user asked for.

## How to report

Please **do not open a public issue** for security problems.

Report privately through GitHub:
[**Report a vulnerability**](https://github.com/musahyderr/netdoctor/security/advisories/new)
(the repository's Security tab → "Report a vulnerability").

Please include what you did, what happened, your OS and Python version, and the netdoctor
version (`pip show netdoctor-mcp`).

## What to expect

- An acknowledgement within 7 days.
- A fix or a clear plan within 30 days for confirmed problems.
- Credit in the release notes if you want it.

## Supported versions

Only the latest release gets security fixes.
