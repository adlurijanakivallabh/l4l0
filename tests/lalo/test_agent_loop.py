"""Tests for the autonomous agent loop, driven by a scripted provider."""

from __future__ import annotations

from lalo.agent import AgentConfig, AgentLoop
from lalo.agent.tools import FunctionTool, ToolRegistry, ToolResult
from lalo.core.model_router import CompletionRequest, CompletionResponse, ModelRouter


class _ScriptedProvider:
    name = "scripted"

    def __init__(self, responses: list[str]) -> None:
        self._responses = responses
        self.calls = 0

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        text = self._responses[min(self.calls, len(self._responses) - 1)]
        self.calls += 1
        return CompletionResponse(text=text, provider=self.name, model="scripted")


def _router(responses: list[str]) -> ModelRouter:
    return ModelRouter(
        providers={"scripted": _ScriptedProvider(responses)},
        routes={"reasoning": ("scripted",)},
    )


def test_loop_runs_tools_then_finishes() -> None:
    hits: list[str] = []
    registry = ToolRegistry(
        [
            FunctionTool("http", "fire http", lambda a: ToolResult(f"status=200 {a.get('url')}")),
            FunctionTool(
                "record_finding",
                "record",
                lambda a: (hits.append(str(a.get("title"))), ToolResult("recorded"))[1],
            ),
        ]
    )
    router = _router(
        [
            '{"tool": "http", "args": {"url": "https://app.example.com/"}}',
            '{"tool": "record_finding", "args": {"title": "reflected xss"}}',
            '{"tool": "finish", "args": {"summary": "done"}}',
        ]
    )
    loop = AgentLoop(router, registry, system_prompt="you are a tester")
    result = loop.run("test https://app.example.com")

    assert result.stop_reason == "finished"
    assert result.summary == "done"
    assert len(result.transcript) == 2
    assert result.transcript[0]["tool"] == "http"
    assert hits == ["reflected xss"]


def test_loop_stops_on_no_tool_call() -> None:
    router = _router(["I am not going to emit a tool call."])
    loop = AgentLoop(router, ToolRegistry(), system_prompt="x")
    result = loop.run("mission")
    assert result.stop_reason == "no_tool_call"


def test_loop_respects_max_steps() -> None:
    # Always emits a valid non-finish call -> loop must stop at max_steps.
    router = _router(['{"tool": "noop", "args": {}}'])
    registry = ToolRegistry([FunctionTool("noop", "noop", lambda a: ToolResult("ok"))])
    loop = AgentLoop(router, registry, system_prompt="x", config=AgentConfig(max_steps=3))
    result = loop.run("mission")
    assert result.stop_reason == "max_steps"
    assert result.steps == 3
