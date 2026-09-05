"""Tool protocol, registry, and the tool-call parser.

Tools are provider-agnostic: each has a name, a one-line description (rendered
into the prompt), and a ``run(args) -> ToolResult``. The LLM selects a tool by
emitting a JSON object ``{"tool": "...", "args": {...}}``; :func:`parse_tool_call`
extracts it tolerantly (fenced block preferred, else the first well-formed JSON
object anywhere in the text — real models sometimes batch several objects in one
reply; only the first is ever acted on, the rest are never silently executed).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..core.logging import get_logger

_log = get_logger("lalo.agent.tools")

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

    def names(self) -> list[str]:
        return list(self._tools)

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


def _warn_if_batched(count: int, where: str) -> None:
    if count > 1:
        _log.warning(
            "model batched %d tool calls in one reply (%s); only the first is acted on",
            count - 1,
            where,
        )


def parse_tool_call(text: str) -> ToolCall | None:
    """Extract the FIRST ``{"tool": ..., "args": ...}`` call from model output.

    Handles a fenced block, an object amid prose, and a response that
    concatenates several JSON objects (some models emit a whole plan at once) —
    the first valid tool call is taken and the loop observes its result before
    the next action, rather than acting blind on a pre-planned batch. Every
    dropped call past the first is logged (not just silently discarded), so a
    model that keeps batching stays observable instead of an invisible pattern
    only noticeable from its downstream effects.
    """
    fenced = [obj for blob in _FENCED.findall(text) if (obj := _try_load(blob)) and "tool" in obj]
    if fenced:
        _warn_if_batched(len(fenced), "fenced blocks")
        return _to_call(fenced[0])

    found: list[dict[str, object]] = []
    idx = 0
    while True:
        start = text.find("{", idx)
        if start == -1:
            break
        try:
            obj, end = _DECODER.raw_decode(text, start)
        except (json.JSONDecodeError, ValueError):
            idx = start + 1
            continue
        if isinstance(obj, dict) and "tool" in obj:
            found.append(obj)
        idx = max(end, start + 1)

    if not found:
        return None
    _warn_if_batched(len(found), "inline JSON objects")
    return _to_call(found[0])
