"""Tests for tool-call parsing and the registry."""

from __future__ import annotations

from lalo.agent.tools import FunctionTool, ToolRegistry, ToolResult, parse_tool_call


def test_parse_fenced_json() -> None:
    text = 'thinking...\n```json\n{"tool": "http", "args": {"url": "x"}}\n```'
    call = parse_tool_call(text)
    assert call is not None
    assert call.name == "http"
    assert call.args == {"url": "x"}


def test_parse_bare_json() -> None:
    call = parse_tool_call('{"tool": "finish", "args": {"summary": "done"}}')
    assert call is not None and call.name == "finish"


def test_parse_json_amid_prose() -> None:
    call = parse_tool_call('I will run: {"tool": "run_command", "args": {"cmd": "id"}} now')
    assert call is not None and call.name == "run_command"
    assert call.args == {"cmd": "id"}


def test_parse_no_json_returns_none() -> None:
    assert parse_tool_call("no tool call here") is None


def test_registry_dispatch_and_unknown() -> None:
    reg = ToolRegistry([FunctionTool("echo", "echo", lambda a: ToolResult(str(a.get("x"))))])
    assert reg.dispatch("echo", {"x": 1}).observation == "1"
    unknown = reg.dispatch("nope", {})
    assert unknown.ok is False
    assert "unknown tool" in unknown.observation


def test_registry_dispatch_swallows_tool_error() -> None:
    def boom(_: dict[str, object]) -> ToolResult:
        raise RuntimeError("kaboom")

    reg = ToolRegistry([FunctionTool("boom", "boom", boom)])
    result = reg.dispatch("boom", {})
    assert result.ok is False
    assert "kaboom" in result.observation
