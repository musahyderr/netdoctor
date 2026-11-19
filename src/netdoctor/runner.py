"""The only module in netdoctor that starts other programs.

Safety properties (each one is checked by tests/test_safety.py):
- Only programs in ALLOWED_PROGRAMS can run, and only from fixed system
  folders, never from PATH, so a look-alike program cannot be swapped in.
- Arguments are a list; the shell is never used (shell=False).
- No input is given to the program, a timeout always applies, and output
  is capped in size.
- On Windows no console window is shown.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass

MAX_OUTPUT_BYTES = 64 * 1024


def current_os() -> str:
    """Return 'windows', 'macos' or 'linux'."""
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _windows_system32() -> str:
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return os.path.join(root, "System32")


def allowed_programs(os_name: str) -> dict[str, list[str]]:
    """Every program netdoctor may run, with the only paths it may run them from."""
    if os_name == "windows":
        sys32 = _windows_system32()
        return {
            "ping": [os.path.join(sys32, "PING.EXE")],
            "tracert": [os.path.join(sys32, "TRACERT.EXE")],
            "nslookup": [os.path.join(sys32, "nslookup.exe")],
        }
    if os_name == "macos":
        return {
            "ping": ["/sbin/ping"],
            "ping6": ["/sbin/ping6"],
            "traceroute": ["/usr/sbin/traceroute"],
            "nslookup": ["/usr/bin/nslookup"],
        }
    return {
        "ping": ["/usr/bin/ping", "/bin/ping"],
        "traceroute": ["/usr/bin/traceroute", "/usr/sbin/traceroute", "/bin/traceroute"],
        "tracepath": ["/usr/bin/tracepath", "/usr/sbin/tracepath", "/bin/tracepath"],
        "nslookup": ["/usr/bin/nslookup", "/bin/nslookup"],
    }


class ProgramNotFound(Exception):
    """The OS does not have this program in its usual place."""


@dataclass(frozen=True)
class CommandResult:
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool


def find_program(name: str, os_name: str | None = None) -> str:
    os_name = os_name or current_os()
    candidates = allowed_programs(os_name).get(name)
    if candidates is None:
        raise PermissionError(f"{name!r} is not on netdoctor's list of allowed programs")
    for path in candidates:
        if os.path.isfile(path):
            return path
    raise ProgramNotFound(f"{name} was not found on this computer (looked in: {', '.join(candidates)})")


def run(name: str, args: list[str], timeout: float) -> CommandResult:
    """Run one allowed program with a fixed list of arguments."""
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise TypeError("args must be a list of strings")
    for arg in args:
        if "\x00" in arg or "\n" in arg or "\r" in arg:
            raise ValueError("arguments must not contain control characters")
    if not 0 < timeout <= 120:
        raise ValueError("timeout must be between 0 and 120 seconds")

    os_name = current_os()
    argv = [find_program(name, os_name), *args]

    env = dict(os.environ)
    kwargs: dict = {}
    if os_name == "windows":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    else:
        env["LC_ALL"] = "C"  # English, predictable output for the parsers
        env["LANG"] = "C"

    try:
        proc = subprocess.run(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            env=env,
            check=False,
            **kwargs,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(argv, None, _decode(exc.stdout), _decode(exc.stderr), True)
    return CommandResult(argv, proc.returncode, _decode(proc.stdout), _decode(proc.stderr), False)


def _decode(data: bytes | None) -> str:
    if not data:
        return ""
    data = data[:MAX_OUTPUT_BYTES]
    encoding = "oem" if current_os() == "windows" else "utf-8"
    try:
        text = data.decode(encoding, errors="replace")
    except LookupError:
        text = data.decode("utf-8", errors="replace")
    return text.replace("\r\n", "\n")
