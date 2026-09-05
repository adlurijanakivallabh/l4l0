"""``query_graph``/``note`` — the agent's own read access and scratchpad over its graph.

CLAUDE.md's own flat-toolset description names both alongside ``record_finding``/
``recall``, but neither had a tool wrapper built in any phase 0-18 — closed here
as part of the end-to-end integration pass rather than left as a named-but-never-
built gap. ``query_graph`` is read-only by construction (it only ever calls
:meth:`~lalo.graph.model.ReachabilityGraph.node`/``nodes_of_kind``, never
``add_node``/``add_edge``) so it can never become a side channel for mutating
the graph outside ``record_finding``/``note``'s own narrow write paths. ``note``
reuses :data:`~lalo.graph.model.NodeKind.NOTE` rather than a separate log
structure — one graph, one place an agent (or a human reading the persisted
graph later) looks for everything a scan learned, notes included.
"""

from __future__ import annotations

import uuid

from ..agent.tools import FunctionTool, ToolResult, str_arg
from .model import NodeKind, ReachabilityGraph

_MAX_NODES_LISTED = 50


def build_note_tool(graph: ReachabilityGraph) -> FunctionTool:
    def _note(args: dict[str, object]) -> ToolResult:
        text = str_arg(args, "text").strip()
        if not text:
            return ToolResult(observation="error: 'text' is required", ok=False)
        note_id = f"note-{uuid.uuid4().hex[:12]}"
        graph.add_node(note_id, NodeKind.NOTE, text=text)
        return ToolResult(observation=f"recorded {note_id}")

    return FunctionTool(
        name="note",
        description=(
            "Leave yourself (or another agent) a freeform scratch note on the shared "
            'graph - not a finding, just a reminder or observation. args: {"text": str}'
        ),
        func=_note,
    )


def build_query_graph_tool(graph: ReachabilityGraph) -> FunctionTool:
    def _query(args: dict[str, object]) -> ToolResult:
        node_id = str_arg(args, "node_id").strip()
        if node_id:
            if not graph.has_node(node_id):
                return ToolResult(observation=f"error: no node {node_id!r}", ok=False)
            return ToolResult(observation=f"{node_id}: {graph.node(node_id)}")

        kind_raw = str_arg(args, "kind").strip()
        if kind_raw:
            try:
                kind = NodeKind(kind_raw)
            except ValueError:
                valid = ", ".join(k.value for k in NodeKind)
                return ToolResult(
                    observation=f"error: unknown kind {kind_raw!r} (valid: {valid})", ok=False
                )
            ids = graph.nodes_of_kind(kind)
            shown = ids[:_MAX_NODES_LISTED]
            lines = [f"{len(ids)} {kind.value} node(s):"]
            lines += [f"- {i}: {graph.node(i)}" for i in shown]
            if len(ids) > len(shown):
                lines.append(f"... and {len(ids) - len(shown)} more (use node_id to fetch one)")
            return ToolResult(observation="\n".join(lines))

        counts = {kind.value: len(graph.nodes_of_kind(kind)) for kind in NodeKind}
        summary = ", ".join(f"{k}={v}" for k, v in counts.items() if v)
        return ToolResult(observation=summary or "(graph is empty)")

    return FunctionTool(
        name="query_graph",
        description=(
            "Inspect the reachability graph you and any spawned agents have built so far. "
            "Read-only. With no args: a count per node kind. With 'kind': list that kind's "
            "nodes. With 'node_id': one node's full attributes. args: "
            '{"kind": str (optional), "node_id": str (optional)}'
        ),
        func=_query,
    )
