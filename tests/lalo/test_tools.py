"""Tests for the tool registry and the tolerant tool-call parser."""

from __future__ import annotations

from unittest.mock import patch

from lalo.agent.tools import FunctionTool, ToolRegistry, ToolResult, parse_tool_call, str_arg


def test_str_arg_returns_the_value_when_present() -> None:
    assert str_arg({"method": "post"}, "method", "GET") == "post"


def test_str_arg_returns_the_default_when_the_key_is_absent() -> None:
    assert str_arg({}, "method", "GET") == "GET"


def test_str_arg_returns_the_default_on_an_explicit_json_null_not_the_string_none() -> None:
    """The actual bug this helper exists to close: `str(args.get(key, default))`
    alone only substitutes `default` when the key is missing, not when it is
    present with a value of None - turning an intended default into the
    literal, non-empty string "None" that then passes a caller's own
    `if not value:` required-field check."""
    assert str_arg({"method": None}, "method", "GET") == "GET"
    assert str_arg({"query": None}, "query") == ""


def test_str_arg_coerces_a_non_string_present_value() -> None:
    assert str_arg({"count": 5}, "count") == "5"


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
    assert call.dropped_calls == 1


def test_parse_tool_call_a_single_call_has_zero_dropped_calls() -> None:
    call = parse_tool_call('{"tool": "solo", "args": {}}')
    assert call is not None
    assert call.dropped_calls == 0


def test_parse_tool_call_counts_every_dropped_call_not_just_whether_any_were() -> None:
    text = "".join(f'{{"tool": "t{i}", "args": {{}}}}' for i in range(5))
    call = parse_tool_call(text)
    assert call is not None
    assert call.dropped_calls == 4


def test_parse_tool_call_logs_when_a_batch_is_dropped() -> None:
    # A dropped call must be observable, not just silently discarded -- a
    # model that keeps batching would otherwise be invisible except via its
    # downstream effects.
    text = '{"tool": "first", "args": {}}{"tool": "second", "args": {}}'
    with patch("lalo.agent.tools._log") as mock_log:
        parse_tool_call(text)
    mock_log.warning.assert_called_once()


def test_parse_tool_call_does_not_log_for_a_single_call() -> None:
    with patch("lalo.agent.tools._log") as mock_log:
        parse_tool_call('{"tool": "solo", "args": {}}')
    mock_log.warning.assert_not_called()


def test_parse_tool_call_logs_when_a_fenced_batch_is_dropped() -> None:
    text = (
        '```json\n{"tool": "first", "args": {}}\n```\n```json\n{"tool": "second", "args": {}}\n```'
    )
    with patch("lalo.agent.tools._log") as mock_log:
        call = parse_tool_call(text)
    assert call is not None
    assert call.name == "first"
    assert call.dropped_calls == 1
    mock_log.warning.assert_called_once()


def test_parse_tool_call_no_json_returns_none() -> None:
    assert parse_tool_call("just thinking out loud, no action yet") is None


def test_parse_tool_call_skips_non_tool_json_then_finds_real_call() -> None:
    text = '{"not_a_tool": true} then {"tool": "act", "args": {"k": "v"}}'
    call = parse_tool_call(text)
    assert call is not None
    assert call.name == "act"
    assert call.args == {"k": "v"}
