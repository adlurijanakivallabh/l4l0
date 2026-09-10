"""The ``baseline`` tool - a shared, append-only threat-model/inventory
artifact per normalized target identity, readable and appendable by every
agent in the hierarchy via the same shared graph every other tool already
reads and writes.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..agent.tools import FunctionTool, ToolResult, str_arg
from ..core.redaction import redact
from .model import NodeKind, ReachabilityGraph

_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_target_identity(target: str) -> str:
    """``https://api.example.com:443/path`` and ``api.example.com`` both
    resolve to ``api.example.com`` - host plus a NON-default port only,
    lowercased, scheme and path dropped. A bare host with no scheme
    (``urlsplit`` needs ``//`` to parse a netloc) is handled by prefixing
    one before parsing."""
    candidate = target if "//" in target else f"//{target}"
    parts = urlsplit(candidate)
    host = (parts.hostname or target).lower()
    scheme = (parts.scheme or "https").lower()
    port = parts.port
    if port is not None and _DEFAULT_PORTS.get(scheme) == port:
        port = None
    return f"{host}:{port}" if port else host


def build_baseline_tool(graph: ReachabilityGraph, agent_id: str) -> FunctionTool:
    def _node_id(target: str) -> tuple[str, str]:
        identity = normalize_target_identity(target)
        return f"baseline-{identity}", identity

    def _baseline(args: dict[str, object]) -> ToolResult:
        action = str_arg(args, "action", "").strip()
        target = str_arg(args, "target", "").strip()
        if not target:
            return ToolResult(observation="error: 'target' is required", ok=False)
        node_id, identity = _node_id(target)

        if action == "save":
            category = str_arg(args, "category", "").strip()
            summary = str_arg(args, "summary", "").strip()
            if not category or not summary:
                return ToolResult(
                    observation="error: 'category' and 'summary' are required for action=save",
                    ok=False,
                )
            if graph.has_node(node_id):
                return ToolResult(
                    observation=f"error: a baseline already exists for {identity!r} - "
                    "use action=amend to add to it, never action=save to overwrite",
                    ok=False,
                )
            graph.add_node(
                node_id,
                NodeKind.BASELINE,
                identity=identity,
                category=category,
                summary=redact(summary),
                amendments=[],
            )
            return ToolResult(observation=f"saved baseline for {identity}")

        if action == "get":
            if not graph.has_node(node_id):
                return ToolResult(observation=f"no baseline recorded for {identity}")
            node = graph.node(node_id)
            lines = [f"category: {node.get('category')}", f"summary: {node.get('summary')}"]
            for amendment in node.get("amendments", []):
                who = amendment.get("agent_id", "unknown")
                lines.append(f"- amendment by {who}: {amendment.get('text')}")
            return ToolResult(observation="\n".join(lines))

        if action == "amend":
            text = str_arg(args, "text", "").strip()
            if not text:
                return ToolResult(
                    observation="error: 'text' is required for action=amend", ok=False
                )
            if not graph.has_node(node_id):
                return ToolResult(
                    observation=f"error: no baseline exists yet for {identity!r} - "
                    "use action=save to create the initial one first",
                    ok=False,
                )
            node = graph.node(node_id)
            amendments = [*node.get("amendments", []), {"text": redact(text), "agent_id": agent_id}]
            graph.add_node(node_id, NodeKind.BASELINE, amendments=amendments)
            count = len(amendments)
            return ToolResult(
                observation=f"amended baseline for {identity} ({count} amendment(s) total)"
            )

        return ToolResult(
            observation=f"error: unknown action {action!r} - use save|get|amend", ok=False
        )

    return FunctionTool(
        name="baseline",
        description=(
            "A shared, append-only threat-model/inventory note per target - every agent "
            "reads and adds to the SAME entry for the same target identity "
            "(host[:non-default-port], scheme/path/default-port ignored). Note: a "
            "spawned child's own save/amend calls stay on its own isolated copy and "
            "don't propagate back to the parent or siblings once it returns - this "
            "works best when the PARENT writes context before fanning children out, so "
            'they inherit it. args: {"action": "save"|"get"|"amend", "target": str, ...}. '
            'save (once per target - use amend after): {"category": str, "summary": str}. '
            "get: {}. "
            'amend (adds to an existing baseline, never overwrites it): {"text": str}.'
        ),
        func=_baseline,
    )
