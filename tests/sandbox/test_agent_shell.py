"""Real command-execution sandbox — hermetic tests (v4 R4).

No real Docker daemon required: `subprocess.run`/`shutil.which` are
monkeypatched, matching this project's established recon-tool-wrapper test
pattern (`tests/phase3/test_recon_tools.py`). Covers argv construction
(array, never a shell string), the unavailable/error paths, and the
context-manager lifecycle. A separate live test (gated, real Docker) is run
manually per the v4 plan's own R4 verification step.
"""

from __future__ import annotations

import subprocess

import pytest

from reachagent.execution.scope import ScopeGuard
from reachagent.sandbox import agent_shell
from reachagent.sandbox.agent_shell import (
    AgentSandbox,
    SandboxResult,
    SandboxUnavailableError,
)


class _Completed:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _sandbox() -> AgentSandbox:
    return AgentSandbox("scan-123")


# === start() ==================================================================


def test_start_builds_a_capped_bridge_networked_argv_array(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agent_shell.shutil, "which", lambda _b: "/usr/bin/docker")
    calls: list[tuple[list[str], dict[str, object]]] = []

    def _run(argv: list[str], **kwargs: object) -> _Completed:
        calls.append((argv, kwargs))
        return _Completed(returncode=0)

    monkeypatch.setattr(agent_shell.subprocess, "run", _run)
    sandbox = _sandbox()

    sandbox.start()

    run_argv, run_kwargs = calls[0]
    assert run_argv == [
        "docker",
        "run",
        "-d",
        "--name",
        "reachagent-sandbox-scan-123",
        "--network",
        "bridge",
        "--cap-add",
        "NET_ADMIN",
        "--memory",
        agent_shell._MEMORY_LIMIT,
        "--pids-limit",
        agent_shell._PIDS_LIMIT,
        "--cpus",
        agent_shell._CPU_LIMIT,
        "--rm",
        agent_shell.DEFAULT_IMAGE,
    ]
    assert run_kwargs["shell"] is False
    assert "--network" in run_argv and "host" not in run_argv
    assert not any(flag in run_argv for flag in ("-v", "--mount", "--privileged"))


def test_start_with_no_scope_locks_egress_to_loopback_and_dns_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agent_shell.shutil, "which", lambda _b: "/usr/bin/docker")
    calls: list[list[str]] = []

    def _run(argv: list[str], **_kwargs: object) -> _Completed:
        calls.append(argv)
        return _Completed(returncode=0)

    monkeypatch.setattr(agent_shell.subprocess, "run", _run)

    _sandbox().start()  # no scope= passed

    exec_argv = calls[1]
    assert exec_argv[:4] == ["docker", "exec", "reachagent-sandbox-scan-123", "sh"]
    script = exec_argv[-1]
    assert "-o lo -j ACCEPT" in script
    assert "--dport 53 -j ACCEPT" in script
    assert "-P OUTPUT DROP" in script
    assert "-d " not in script  # no per-IP ACCEPT rules when there's nothing to allow


def test_start_resolves_scope_hosts_and_allows_only_their_ips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agent_shell.shutil, "which", lambda _b: "/usr/bin/docker")
    monkeypatch.setattr(agent_shell.subprocess, "run", lambda *_a, **_k: _Completed())

    def _fake_getaddrinfo(host: str, _port: object) -> list[tuple]:
        assert host == "target.test"
        return [(agent_shell.socket.AF_INET, None, None, "", ("203.0.113.7", 0))]

    monkeypatch.setattr(agent_shell.socket, "getaddrinfo", _fake_getaddrinfo)
    scope = ScopeGuard.from_hosts(["target.test"])
    assert scope.allowed_hosts() == ["target.test"]
    calls: list[list[str]] = []
    monkeypatch.setattr(
        agent_shell.subprocess,
        "run",
        lambda argv, **_k: (calls.append(argv), _Completed(returncode=0))[1],
    )

    AgentSandbox("scan-scoped", scope=scope).start()

    script = calls[1][-1]
    assert "-d 203.0.113.7 -j ACCEPT" in script


def test_start_skips_unresolvable_hosts_without_crashing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_shell.shutil, "which", lambda _b: "/usr/bin/docker")
    monkeypatch.setattr(agent_shell.subprocess, "run", lambda *_a, **_k: _Completed())

    def _fail_lookup(_host: str, _port: object) -> list[tuple]:
        raise OSError("name or service not known")

    monkeypatch.setattr(agent_shell.socket, "getaddrinfo", _fail_lookup)
    scope = ScopeGuard.from_hosts(["nonexistent.invalid"])

    AgentSandbox("scan-badhost", scope=scope).start()  # no raise


def test_start_fails_closed_and_tears_down_if_scope_setup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agent_shell.shutil, "which", lambda _b: "/usr/bin/docker")
    calls: list[str] = []

    def _run(argv: list[str], **_kwargs: object) -> _Completed:
        calls.append(argv[1])
        if argv[1] == "exec":
            return _Completed(returncode=1, stderr="iptables: command not found")
        return _Completed(returncode=0)

    monkeypatch.setattr(agent_shell.subprocess, "run", _run)

    with pytest.raises(SandboxUnavailableError, match="network scope"):
        _sandbox().start()

    assert calls == ["run", "exec", "rm"]  # torn down, never left running open


def test_start_raises_when_docker_binary_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_shell.shutil, "which", lambda _b: None)
    monkeypatch.setattr(
        agent_shell.subprocess,
        "run",
        lambda *_a, **_k: pytest.fail("subprocess.run must not be reached without docker"),
    )

    with pytest.raises(SandboxUnavailableError, match="docker binary"):
        _sandbox().start()


def test_start_raises_on_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_shell.shutil, "which", lambda _b: "/usr/bin/docker")
    monkeypatch.setattr(
        agent_shell.subprocess,
        "run",
        lambda *_a, **_k: _Completed(returncode=1, stderr="no such image"),
    )

    with pytest.raises(SandboxUnavailableError, match="docker run failed"):
        _sandbox().start()


def test_start_raises_on_subprocess_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_shell.shutil, "which", lambda _b: "/usr/bin/docker")

    def _boom(*_a: object, **_k: object) -> _Completed:
        raise OSError("daemon not running")

    monkeypatch.setattr(agent_shell.subprocess, "run", _boom)

    with pytest.raises(SandboxUnavailableError, match="daemon not running"):
        _sandbox().start()


# === run_command() ============================================================


def test_run_command_requires_start_first() -> None:
    with pytest.raises(SandboxUnavailableError, match="not started"):
        _sandbox().run_command("whoami")


def test_run_command_builds_exec_argv_with_command_verbatim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agent_shell.shutil, "which", lambda _b: "/usr/bin/docker")
    monkeypatch.setattr(agent_shell.subprocess, "run", lambda *_a, **_k: _Completed())
    sandbox = _sandbox()
    sandbox.start()
    seen: dict[str, object] = {}

    def _run(argv: list[str], **kwargs: object) -> _Completed:
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return _Completed(returncode=0, stdout="root\n")

    monkeypatch.setattr(agent_shell.subprocess, "run", _run)

    result = sandbox.run_command("nmap -sV --script vuln target.test")

    assert seen["argv"] == [
        "docker",
        "exec",
        "reachagent-sandbox-scan-123",
        "sh",
        "-c",
        "nmap -sV --script vuln target.test",
    ]
    assert seen["kwargs"]["shell"] is False
    assert result == SandboxResult(
        command="nmap -sV --script vuln target.test", exit_code=0, output="root\n"
    )


def test_run_command_reports_timeout_without_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_shell.shutil, "which", lambda _b: "/usr/bin/docker")
    monkeypatch.setattr(agent_shell.subprocess, "run", lambda *_a, **_k: _Completed())
    sandbox = _sandbox()
    sandbox.start()

    def _timeout(*_a: object, **_k: object) -> _Completed:
        raise subprocess.TimeoutExpired(cmd="sleep 999", timeout=1.0)

    monkeypatch.setattr(agent_shell.subprocess, "run", _timeout)

    result = sandbox.run_command("sleep 999", timeout=1.0)

    assert result.timed_out is True
    assert result.exit_code == -1


def test_run_command_reports_exec_failure_without_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agent_shell.shutil, "which", lambda _b: "/usr/bin/docker")
    monkeypatch.setattr(agent_shell.subprocess, "run", lambda *_a, **_k: _Completed())
    sandbox = _sandbox()
    sandbox.start()

    def _boom(*_a: object, **_k: object) -> _Completed:
        raise OSError("exec failed")

    monkeypatch.setattr(agent_shell.subprocess, "run", _boom)

    result = sandbox.run_command("whoami")

    assert result.exit_code == -1
    assert result.timed_out is False


def test_run_command_output_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_shell.shutil, "which", lambda _b: "/usr/bin/docker")
    monkeypatch.setattr(agent_shell.subprocess, "run", lambda *_a, **_k: _Completed())
    sandbox = _sandbox()
    sandbox.start()
    huge = "A" * (agent_shell._MAX_OUTPUT_CHARS + 5_000)
    monkeypatch.setattr(agent_shell.subprocess, "run", lambda *_a, **_k: _Completed(stdout=huge))

    result = sandbox.run_command("cat bigfile")

    assert len(result.output) == agent_shell._MAX_OUTPUT_CHARS


# === stop() ====================================================================


def test_stop_is_a_no_op_when_never_started(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        agent_shell.subprocess,
        "run",
        lambda *_a, **_k: pytest.fail("subprocess.run must not be reached"),
    )

    _sandbox().stop()  # no raise


def test_stop_builds_rm_force_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_shell.shutil, "which", lambda _b: "/usr/bin/docker")
    monkeypatch.setattr(agent_shell.subprocess, "run", lambda *_a, **_k: _Completed())
    sandbox = _sandbox()
    sandbox.start()
    seen: dict[str, object] = {}

    def _run(argv: list[str], **kwargs: object) -> _Completed:
        seen["argv"] = argv
        return _Completed(returncode=0)

    monkeypatch.setattr(agent_shell.subprocess, "run", _run)

    sandbox.stop()

    assert seen["argv"] == ["docker", "rm", "-f", "reachagent-sandbox-scan-123"]


def test_stop_swallows_teardown_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_shell.shutil, "which", lambda _b: "/usr/bin/docker")
    monkeypatch.setattr(agent_shell.subprocess, "run", lambda *_a, **_k: _Completed())
    sandbox = _sandbox()
    sandbox.start()

    def _boom(*_a: object, **_k: object) -> _Completed:
        raise OSError("container already gone")

    monkeypatch.setattr(agent_shell.subprocess, "run", _boom)

    sandbox.stop()  # no raise


def test_run_command_after_stop_requires_start_again(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_shell.shutil, "which", lambda _b: "/usr/bin/docker")
    monkeypatch.setattr(agent_shell.subprocess, "run", lambda *_a, **_k: _Completed())
    sandbox = _sandbox()
    sandbox.start()
    sandbox.stop()

    with pytest.raises(SandboxUnavailableError, match="not started"):
        sandbox.run_command("whoami")


# === context manager ===========================================================


def test_context_manager_starts_and_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_shell.shutil, "which", lambda _b: "/usr/bin/docker")
    calls: list[str] = []

    def _run(argv: list[str], **_kwargs: object) -> _Completed:
        calls.append(argv[1])  # "run" or "exec" or "rm"
        return _Completed(returncode=0, stdout="ok")

    monkeypatch.setattr(agent_shell.subprocess, "run", _run)

    with AgentSandbox("scan-ctx") as sandbox:
        result = sandbox.run_command("echo hi")
        assert result.output == "ok"

    assert calls == ["run", "exec", "exec", "rm"]  # run, network-scope setup, echo hi, teardown
