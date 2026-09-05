"""Coordinator that spawns isolated specialist sub-agents and merges authority.

Design note (informed by studying prior multi-agent coordinators): a parent must
act on a child's *authoritative* filed findings — read from the child's graph by
id — never on the child's prose summary, which may be hallucinated. So merging is
by finding-id from the isolated sub-graph, and the completion report separates the
narrative summary from the authoritative finding ids.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from ..agent.loop import AgentConfig, AgentLoop, AgentResult
from ..agent.tools import ToolRegistry
from ..core.model_router import ModelRouter
from ..graph.store import ReachGraph
from ..models import Finding
from ..prompts import SYSTEM_PROMPT


def merge_findings(target: ReachGraph, source: ReachGraph) -> list[str]:
    """Merge findings from ``source`` into ``target`` by id. Returns merged ids."""
    existing = {f.id for f in target.findings()}
    merged: list[str] = []
    for finding in source.findings():
        if finding.id not in existing:
            target.add_finding(finding)
            merged.append(finding.id)
    return merged


@dataclass
class SubAgentSpec:
    role: str
    objective: str
    # Builds the tool registry bound to the sub-agent's OWN isolated graph.
    registry_factory: Callable[[ReachGraph], ToolRegistry]
    system_prompt: str = SYSTEM_PROMPT


@dataclass
class CompletionReport:
    role: str
    stop_reason: str
    summary: str  # prose (not authoritative)
    finding_ids: list[str] = field(default_factory=list)  # authoritative, merged by id
    steps: int = 0


class MultiAgentCoordinator:
    def __init__(
        self, router: ModelRouter, graph: ReachGraph, *, config: AgentConfig | None = None
    ) -> None:
        self.router = router
        self.graph = graph
        self.config = config

    def run_specialist(self, spec: SubAgentSpec) -> CompletionReport:
        sub_graph = self.graph.snapshot()  # isolation: no shared workspace
        registry = spec.registry_factory(sub_graph)
        loop = AgentLoop(
            self.router, registry, system_prompt=spec.system_prompt, config=self.config
        )
        result: AgentResult = loop.run(spec.objective)
        merged_ids = merge_findings(self.graph, sub_graph)  # authoritative merge by id
        return CompletionReport(
            role=spec.role,
            stop_reason=result.stop_reason,
            summary=result.summary,
            finding_ids=merged_ids,
            steps=result.steps,
        )

    def run_all(self, specs: Sequence[SubAgentSpec]) -> list[CompletionReport]:
        return [self.run_specialist(spec) for spec in specs]


def rehunt_spec(
    lead: Finding, registry_factory: Callable[[ReachGraph], ToolRegistry]
) -> SubAgentSpec:
    """Build a focused re-hunt specialist for a confirmed high-confidence lead."""
    objective = (
        f"A {lead.vuln_class} lead was confirmed at {lead.target} "
        f"(confidence {lead.confidence}). Escalate it: chain further, find related "
        f"instances, and demonstrate maximum in-scope impact."
    )
    return SubAgentSpec(
        role=f"rehunt:{lead.vuln_class}", objective=objective, registry_factory=registry_factory
    )
