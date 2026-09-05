"""Live agent-graph registry — so an agent can introspect before spawning.

Reference-informed (a reference multi-agent tool exposes a graph-snapshot tool so
an agent checks for duplicate work before spawning another specialist; Apache-2.0,
ideas-only). Tracks id/name/task/parent/status; rendered as an indented tree.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Literal

Status = Literal["running", "completed", "failed"]


@dataclass
class AgentNode:
    agent_id: str
    name: str
    task: str
    parent_id: str | None
    status: Status = "running"
    finding_ids: list[str] = field(default_factory=list)


class AgentRegistry:
    def __init__(self) -> None:
        self._nodes: dict[str, AgentNode] = {}

    def register(self, name: str, task: str, parent_id: str | None) -> AgentNode:
        node = AgentNode(agent_id=uuid.uuid4().hex[:8], name=name, task=task, parent_id=parent_id)
        self._nodes[node.agent_id] = node
        return node

    def complete(self, agent_id: str, status: Status, finding_ids: list[str]) -> None:
        node = self._nodes.get(agent_id)
        if node is not None:
            node.status = status
            node.finding_ids = finding_ids

    def snapshot(self) -> list[AgentNode]:
        return list(self._nodes.values())

    def render_tree(self) -> str:
        if not self._nodes:
            return "(no agents spawned yet)"

        def render(node_id: str, depth: int) -> list[str]:
            node = self._nodes[node_id]
            lines = [f"{'  ' * depth}- {node.name} ({node.agent_id}) [{node.status}]"]
            for child in self._nodes.values():
                if child.parent_id == node_id:
                    lines.extend(render(child.agent_id, depth + 1))
            return lines

        roots = [n.agent_id for n in self._nodes.values() if n.parent_id is None]
        lines: list[str] = []
        for root in roots:
            lines.extend(render(root, 0))
        return "\n".join(lines)
