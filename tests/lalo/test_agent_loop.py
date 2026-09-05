"""Tests for the think->act->observe agent loop's hardening behavior.

Covers the specific bugs/lessons the loop was built to avoid: acting on only
the first of several batched tool calls, retrying (not immediately giving up)
on a no-tool-call turn, skipping (not re-firing) a repeating identical call
and hard-aborting past a threshold, honoring a hard budget ceiling before ever
calling the model, and injecting a graduated wrap-up directive as budget bands
cross.
"""

from __future__ import annotations

from collections.abc import Callable

from lalo.agent.loop import AgentConfig, AgentLoop
from lalo.agent.tools import FunctionTool, ToolRegistry, ToolResult
from lalo.core.model_router import CompletionRequest, CompletionResponse
from lalo.orchestrator.budget import Budget


class _FakeRouter:
    """Scripted or callback-driven stand-in for ModelRouter.complete()."""

    def __init__(self, respond: Callable[[int, str], str]) -> None:
        self._respond = respond
        self.calls = 0
        self.prompts: list[str] = []

    def complete(self, role: str, request: CompletionRequest) -> CompletionResponse:
        self.prompts.append(request.prompt)
        text = self._respond(self.calls, request.prompt)
        self.calls += 1
        return CompletionResponse(text=text, provider="fake", model="fake-model")


def _scripted(texts: list[str]) -> _FakeRouter:
    return _FakeRouter(lambda i, _p: texts[min(i, len(texts) - 1)])


def _counting_tool(name: str) -> tuple[FunctionTool, dict[str, int]]:
    calls = {"n": 0}

    def _run(_args: dict[str, object]) -> ToolResult:
        calls["n"] += 1
        return ToolResult(observation=f"{name} ran ({calls['n']})")

    return FunctionTool(name=name, description="test tool", func=_run), calls


def test_batched_tool_calls_only_first_is_acted_on() -> None:
    tool, calls = _counting_tool("run_command")
    registry = ToolRegistry([tool])
    router = _scripted(
        [
            '{"tool": "run_command", "args": {"cmd": "ls"}} '
            '{"tool": "finish", "args": {"summary": "premature"}}',
            '{"tool": "finish", "args": {"summary": "done"}}',
        ]
    )
    loop = AgentLoop(router, registry, system_prompt="be an agent")  # type: ignore[arg-type]
    result = loop.run("find something")
    assert calls["n"] == 1  # the batched "finish" was never acted on in step 1
    assert result.stop_reason == "finished"
    assert result.summary == "done"
    assert router.calls == 2


def test_no_tool_call_is_retried_before_giving_up() -> None:
    registry = ToolRegistry([])
    router = _scripted(["just musing, no action", "still musing", "musing again"])
    loop = AgentLoop(
        router,  # type: ignore[arg-type]
        registry,
        system_prompt="",
        config=AgentConfig(max_steps=5, max_no_tool_call_retries=1),
    )
    result = loop.run("mission")
    assert result.stop_reason == "no_tool_call"
    assert result.steps == 1  # gave up on the SECOND no-tool-call turn, not the first
    assert router.calls == 2


def test_repeating_identical_call_is_skipped_then_hard_aborted() -> None:
    tool, calls = _counting_tool("probe")
    registry = ToolRegistry([tool])
    router = _scripted(['{"tool": "probe", "args": {"x": 1}}'])
    loop = AgentLoop(
        router,  # type: ignore[arg-type]
        registry,
        system_prompt="",
        config=AgentConfig(max_steps=10, repeat_soft_threshold=2, repeat_abort_threshold=3),
    )
    result = loop.run("mission")
    assert result.stop_reason == "repeating_tool_call_aborted"
    # 1st call actually dispatched; 2nd (soft-threshold) skipped, not re-fired;
    # abort happens on the 3rd repeat before a 3rd dispatch ever occurs.
    assert calls["n"] == 1


def test_budget_exhausted_stops_before_ever_calling_the_model() -> None:
    registry = ToolRegistry([])
    router = _scripted(['{"tool": "finish", "args": {}}'])
    budget = Budget(ceiling=10, spent=10)
    loop = AgentLoop(
        router,  # type: ignore[arg-type]
        registry,
        system_prompt="",
        config=AgentConfig(is_root=True),
        budget=budget,
    )
    result = loop.run("mission")
    assert result.stop_reason == "budget_exhausted"
    assert router.calls == 0


def test_budget_notice_band_injects_a_wrapup_directive_into_the_prompt() -> None:
    tool, _ = _counting_tool("noop")
    registry = ToolRegistry([tool])
    router = _scripted(['{"tool": "finish", "args": {"summary": "ok"}}'])
    budget = Budget(ceiling=100, spent=75)  # root NOTICE band starts at 70
    loop = AgentLoop(
        router,  # type: ignore[arg-type]
        registry,
        system_prompt="",
        config=AgentConfig(is_root=True),
        budget=budget,
    )
    loop.run("mission")
    assert any("Budget notice" in p for p in router.prompts)


def test_cooperative_cancellation_stops_before_calling_the_model() -> None:
    registry = ToolRegistry([])
    router = _scripted(['{"tool": "finish", "args": {}}'])
    loop = AgentLoop(
        router,  # type: ignore[arg-type]
        registry,
        system_prompt="",
        should_stop=lambda: True,
    )
    result = loop.run("mission")
    assert result.stop_reason == "cancelled"
    assert router.calls == 0


def test_max_steps_ceiling_is_respected() -> None:
    tool, _ = _counting_tool("noop")
    registry = ToolRegistry([tool])
    router = _FakeRouter(lambda i, _p: f'{{"tool": "noop", "args": {{"i": {i}}}}}')
    loop = AgentLoop(
        router,  # type: ignore[arg-type]
        registry,
        system_prompt="",
        config=AgentConfig(max_steps=2),
    )
    result = loop.run("mission")
    assert result.stop_reason == "max_steps"
    assert result.steps == 2
    assert len(result.transcript) == 2


def test_event_callbacks_fire_for_tool_call_and_finish() -> None:
    tool, _ = _counting_tool("noop")
    registry = ToolRegistry([tool])
    router = _scripted(
        ['{"tool": "noop", "args": {}}', '{"tool": "finish", "args": {"summary": "done"}}']
    )
    events: list[str] = []
    loop = AgentLoop(
        router,  # type: ignore[arg-type]
        registry,
        system_prompt="",
        on_event=lambda name, _payload: events.append(name),
    )
    loop.run("mission")
    assert events == ["tool_call", "tool_result", "finished"]
