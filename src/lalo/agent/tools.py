"""Tool protocol, registry, and the tool-call parser.

Tools are provider-agnostic: each has a name, a one-line description (rendered
into the prompt), and a ``run(args) -> ToolResult``. The LLM selects a tool by
emitting a JSON object ``{"tool": "...", "args": {...}}``; :func:`parse_tool_call`
extracts it tolerantly (fenced block preferred, else the last brace span).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

_FENCED = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_DECODER = json.JSONDecoder()


@dataclass
class ToolResult:
    observation: str
    ok: bool = True


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict[str, object] = field(default_factory=dict)


@runtime_checkable
class Tool(Protocol):
    name: str
    description: str

    def run(self, args: dict[str, object]) -> ToolResult: ...


@dataclass
class FunctionTool:
    """Wrap a plain callable as a Tool."""

    name: str
    description: str
    func: Callable[[dict[str, object]], ToolResult]

    def run(self, args: dict[str, object]) -> ToolResult:
        return self.func(args)


class ToolRegistry:
    def __init__(self, tools: Sequence[Tool] | None = None) -> None:
        self._tools: dict[str, Tool] = {}
        for tool in tools or []:
            self.register(tool)

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def describe(self) -> str:
        lines = [f"- {t.name}: {t.description}" for t in self._tools.values()]
        return "\n".join(lines)

    def dispatch(self, name: str, args: dict[str, object]) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(observation=f"error: unknown tool {name!r}", ok=False)
        try:
            return tool.run(args)
        except Exception as exc:  # noqa: BLE001 - tool errors are fed back, never fatal
            return ToolResult(
                observation=f"error running {name}: {type(exc).__name__}: {exc}", ok=False
            )


def _try_load(blob: str) -> dict[str, object] | None:
    try:
        obj = json.loads(blob)
    except (json.JSONDecodeError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None


def _to_call(obj: dict[str, object]) -> ToolCall:
    raw_args = obj.get("args", {})
    args = raw_args if isinstance(raw_args, dict) else {}
    return ToolCall(name=str(obj["tool"]), args=args)


def parse_tool_call(text: str) -> ToolCall | None:
    """Extract the FIRST ``{"tool": ..., "args": ...}`` call from model output.

    Handles a fenced block, an object amid prose, and — importantly — a response
    that concatenates several JSON objects (some models emit a whole plan at once):
    we take the first valid tool call and let the loop observe its result before
    the next action, rather than acting blind on a pre-planned batch.
    """
    for blob in _FENCED.findall(text):
        obj = _try_load(blob)
        if obj and "tool" in obj:
            return _to_call(obj)
    idx = 0
    while True:
        start = text.find("{", idx)
        if start == -1:
            return None
        try:
            obj, end = _DECODER.raw_decode(text, start)
        except (json.JSONDecodeError, ValueError):
            idx = start + 1
            continue
        if isinstance(obj, dict) and "tool" in obj:
            return _to_call(obj)
        idx = max(end, start + 1)
