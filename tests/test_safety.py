"""Tests that prove the safety rules hold across the whole source tree."""

import ast
import pathlib
import subprocess

import pytest

from netdoctor import runner

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "netdoctor"
SOURCES = sorted(SRC.rglob("*.py"))


def _trees():
    for path in SOURCES:
        yield path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imported_modules(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            yield node.module.split(".")[0]


def test_sources_found():
    assert len(SOURCES) >= 3


def test_only_runner_imports_subprocess():
    users = {p.name for p, t in _trees() if "subprocess" in set(_imported_modules(t))}
    assert users == {"runner.py"}


def test_shell_true_never_used():
    for path, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "shell":
                        assert isinstance(kw.value, ast.Constant) and kw.value.value is False, (
                            f"{path.name}:{node.lineno} passes shell= something other than False"
                        )


def test_no_dangerous_calls():
    banned_attrs = {("os", "system"), ("os", "popen"), ("os", "startfile")}
    banned_names = {"eval", "exec", "compile", "__import__"}
    for path, tree in _trees():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if isinstance(fn, ast.Name):
                assert fn.id not in banned_names, f"{path.name}:{node.lineno} calls {fn.id}"
            if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                assert (fn.value.id, fn.attr) not in banned_attrs, (
                    f"{path.name}:{node.lineno} calls {fn.value.id}.{fn.attr}"
                )
            if isinstance(fn, ast.Attribute) and fn.attr.startswith("exec") and isinstance(
                fn.value, ast.Name
            ) and fn.value.id == "os":
                pytest.fail(f"{path.name}:{node.lineno} calls os.{fn.attr}")


def test_no_web_or_telemetry_libraries():
    banned = {"urllib", "http", "requests", "httpx", "aiohttp", "urllib3", "ftplib", "smtplib"}
    for path, tree in _trees():
        found = banned & set(_imported_modules(tree))
        assert not found, f"{path.name} imports {found}: netdoctor must not call home"


def test_only_port_check_imports_socket():
    users = {p.name for p, t in _trees() if "socket" in set(_imported_modules(t))}
    assert users <= {"port.py"}


def test_runner_rejects_programs_not_on_allowlist():
    for name in ("cmd", "powershell", "sh", "bash", "netsh", "ipconfig", "curl", "nmap"):
        with pytest.raises(PermissionError):
            runner.find_program(name)


@pytest.mark.parametrize("os_name", ["windows", "macos", "linux"])
def test_allowlist_is_small_and_absolute(os_name):
    progs = runner.allowed_programs(os_name)
    assert set(progs) <= {"ping", "tracert", "traceroute", "tracepath", "nslookup"}
    for paths in progs.values():
        for path in paths:
            assert path.startswith("/") or path[1:3] == ":\\", path


def test_runner_rejects_bad_args():
    with pytest.raises(TypeError):
        runner.run("ping", "example.com", timeout=5)
    with pytest.raises(TypeError):
        runner.run("ping", [b"example.com"], timeout=5)
    with pytest.raises(ValueError):
        runner.run("ping", ["example.com\ncalc"], timeout=5)
    with pytest.raises(ValueError):
        runner.run("ping", ["example.com"], timeout=0)
    with pytest.raises(ValueError):
        runner.run("ping", ["example.com"], timeout=999)


def test_runner_calls_subprocess_safely(monkeypatch):
    seen = {}

    class Done:
        returncode = 0
        stdout = b"ok"
        stderr = b""

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen.update(kwargs)
        return Done()

    monkeypatch.setattr(runner, "find_program", lambda name, os_name=None: "/fixed/ping")
    monkeypatch.setattr(subprocess, "run", fake_run)
    result = runner.run("ping", ["-c", "1", "example.com"], timeout=5)

    assert seen["argv"] == ["/fixed/ping", "-c", "1", "example.com"]
    assert seen["shell"] is False
    assert seen["stdin"] is subprocess.DEVNULL
    assert seen["timeout"] == 5
    assert result.stdout == "ok" and not result.timed_out


def test_runner_reports_timeout(monkeypatch):
    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=b"partial")

    monkeypatch.setattr(runner, "find_program", lambda name, os_name=None: "/fixed/ping")
    monkeypatch.setattr(subprocess, "run", fake_run)
    result = runner.run("ping", ["example.com"], timeout=5)
    assert result.timed_out and result.returncode is None and result.stdout == "partial"


def test_runner_caps_output(monkeypatch):
    class Done:
        returncode = 0
        stdout = b"x" * (runner.MAX_OUTPUT_BYTES * 3)
        stderr = b""

    monkeypatch.setattr(runner, "find_program", lambda name, os_name=None: "/fixed/ping")
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: Done())
    assert len(runner.run("ping", [], timeout=5).stdout) == runner.MAX_OUTPUT_BYTES
