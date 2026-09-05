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
