"""Tests for the tool registry and the tolerant tool-call parser."""

from __future__ import annotations

from lalo.agent.tools import FunctionTool, ToolRegistry, ToolResult, parse_tool_call


def test_registry_dispatch_routes_to_registered_tool() -> None:
    seen: dict[str, object] = {}

    def _run(args: dict[str, object]) -> ToolResult:
        seen["args"] = args
        return ToolResult(observation="did it")

    registry = ToolRegistry([FunctionTool(name="echo", description="echoes", func=_run)])
    result = registry.dispatch("echo", {"x": 1})
    assert result.observation == "did it"
    assert seen["args"] == {"x": 1}


def test_registry_dispatch_unknown_tool_is_a_failed_result_not_an_exception() -> None:
    registry = ToolRegistry([])
    result = registry.dispatch("missing", {})
    assert result.ok is False
    assert "unknown tool" in result.observation


def test_registry_dispatch_swallows_tool_exceptions_into_a_result() -> None:
    def _boom(args: dict[str, object]) -> ToolResult:
        raise ValueError("kaboom")

    registry = ToolRegistry([FunctionTool(name="boom", description="", func=_boom)])
    result = registry.dispatch("boom", {})
    assert result.ok is False
    assert "kaboom" in result.observation


def test_registry_describe_lists_every_tool() -> None:
    registry = ToolRegistry(
        [
            FunctionTool(name="a", description="does a", func=lambda _args: ToolResult("")),
            FunctionTool(name="b", description="does b", func=lambda _args: ToolResult("")),
        ]
    )
    described = registry.describe()
    assert "a: does a" in described
    assert "b: does b" in described


def test_parse_tool_call_fenced_block_preferred() -> None:
    text = 'prose\n```json\n{"tool": "run", "args": {"x": 1}}\n```\nmore prose'
    call = parse_tool_call(text)
    assert call is not None
    assert call.name == "run"
    assert call.args == {"x": 1}


def test_parse_tool_call_bare_object_amid_prose() -> None:
    text = 'I will now act: {"tool": "scan", "args": {}} because reasons.'
    call = parse_tool_call(text)
    assert call is not None
    assert call.name == "scan"


def test_parse_tool_call_batched_objects_returns_only_first() -> None:
    # A real model sometimes emits a whole plan as concatenated JSON objects —
    # only the first is ever acted on, never the rest.
    text = '{"tool": "first", "args": {}}{"tool": "second", "args": {}}'
    call = parse_tool_call(text)
    assert call is not None
    assert call.name == "first"


def test_parse_tool_call_no_json_returns_none() -> None:
    assert parse_tool_call("just thinking out loud, no action yet") is None


def test_parse_tool_call_skips_non_tool_json_then_finds_real_call() -> None:
    text = '{"not_a_tool": true} then {"tool": "act", "args": {"k": "v"}}'
    call = parse_tool_call(text)
    assert call is not None
    assert call.name == "act"
    assert call.args == {"k": "v"}
