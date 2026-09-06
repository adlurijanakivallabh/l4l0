"""Tests for the run_command agent tool wiring (hermetic -- no real Docker)."""

from __future__ import annotations

from dataclasses import dataclass

from lalo.agent.tools import ToolRegistry
from lalo.runtime import build_run_command_tool


@dataclass
class _FakeExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class _FakeContainer:
    def __init__(self, result: _FakeExecResult) -> None:
        self._result = result
        self.last_command: str | list[str] | None = None
        self.last_timeout: float | None = None

    def exec(self, command: str | list[str], *, timeout: float = 120.0) -> _FakeExecResult:
        self.last_command = command
        self.last_timeout = timeout
        return self._result


def test_run_command_dispatches_to_the_container_and_reports_success() -> None:
    container = _FakeContainer(_FakeExecResult(exit_code=0, stdout="hello\n", stderr=""))
    tool = build_run_command_tool(container)
    registry = ToolRegistry([tool])

    result = registry.dispatch("run_command", {"command": "echo hello"})

    assert result.ok is True
    assert "hello" in result.observation
    assert container.last_command == "echo hello"


def test_run_command_reports_nonzero_exit_as_not_ok() -> None:
    container = _FakeContainer(_FakeExecResult(exit_code=1, stdout="", stderr="not found"))
    tool = build_run_command_tool(container)
    registry = ToolRegistry([tool])

    result = registry.dispatch("run_command", {"command": "nope"})

    assert result.ok is False
    assert "not found" in result.observation


def test_run_command_reports_timeout() -> None:
    container = _FakeContainer(_FakeExecResult(exit_code=124, stdout="", stderr="", timed_out=True))
    tool = build_run_command_tool(container, timeout=5.0)
    registry = ToolRegistry([tool])

    result = registry.dispatch("run_command", {"command": "sleep 100"})

    assert result.ok is False
    assert "timed out" in result.observation
    assert container.last_timeout == 5.0


def test_run_command_requires_a_non_empty_command() -> None:
    container = _FakeContainer(_FakeExecResult(exit_code=0, stdout="", stderr=""))
    tool = build_run_command_tool(container)
    registry = ToolRegistry([tool])

    result = registry.dispatch("run_command", {"command": ""})

    assert result.ok is False
    assert "required" in result.observation


def test_run_command_uses_the_default_timeout_when_none_is_requested() -> None:
    container = _FakeContainer(_FakeExecResult(exit_code=0, stdout="", stderr=""))
    tool = build_run_command_tool(container, timeout=42.0)
    ToolRegistry([tool]).dispatch("run_command", {"command": "echo hi"})
    assert container.last_timeout == 42.0


def test_run_command_lets_the_agent_request_a_longer_timeout() -> None:
    container = _FakeContainer(_FakeExecResult(exit_code=0, stdout="", stderr=""))
    tool = build_run_command_tool(container)
    ToolRegistry([tool]).dispatch("run_command", {"command": "nmap -p- x", "timeout": 300})
    assert container.last_timeout == 300.0


def test_run_command_caps_an_agent_requested_timeout_at_the_ceiling() -> None:
    container = _FakeContainer(_FakeExecResult(exit_code=0, stdout="", stderr=""))
    tool = build_run_command_tool(container, max_timeout=600.0)
    ToolRegistry([tool]).dispatch("run_command", {"command": "x", "timeout": 999999})
    assert container.last_timeout == 600.0


def test_run_command_rejects_a_non_numeric_timeout_without_touching_the_container() -> None:
    container = _FakeContainer(_FakeExecResult(exit_code=0, stdout="", stderr=""))
    tool = build_run_command_tool(container)
    result = ToolRegistry([tool]).dispatch("run_command", {"command": "x", "timeout": "soon"})
    assert result.ok is False
    assert "must be a number" in result.observation
    assert container.last_timeout is None


def test_run_command_rejects_a_boolean_timeout() -> None:
    # bool is an int subclass in Python -- {"timeout": true} must not silently
    # become a real, useless 1.0s timeout.
    container = _FakeContainer(_FakeExecResult(exit_code=0, stdout="", stderr=""))
    tool = build_run_command_tool(container)
    result = ToolRegistry([tool]).dispatch("run_command", {"command": "x", "timeout": True})
    assert result.ok is False
    assert "must be a number" in result.observation


def test_run_command_rejects_a_non_positive_timeout() -> None:
    container = _FakeContainer(_FakeExecResult(exit_code=0, stdout="", stderr=""))
    tool = build_run_command_tool(container)
    result = ToolRegistry([tool]).dispatch("run_command", {"command": "x", "timeout": 0})
    assert result.ok is False
    assert "must be positive" in result.observation


def test_run_command_timeout_error_message_reflects_the_effective_timeout() -> None:
    container = _FakeContainer(_FakeExecResult(exit_code=124, stdout="", stderr="", timed_out=True))
    tool = build_run_command_tool(container, timeout=120.0)
    result = ToolRegistry([tool]).dispatch("run_command", {"command": "x", "timeout": 5})
    assert "timed out after 5" in result.observation
