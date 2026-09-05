"""Assemble and run a scan."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..agent.loop import AgentConfig, AgentLoop
from ..agents.registry import AgentRegistry
from ..core.model_router import ModelRouter
from ..execution.firer import HttpFirer
from ..execution.scope import ScopeGuard
from ..execution.target import Engagement
from ..graph.store import ReachGraph
from ..knowledge import KnowledgeStore, SkillLibrary
from ..models import Finding
from ..prompts import SYSTEM_PROMPT, mission_text
from ..runtime.container import RuntimeContainer
from .tools import ScanContext, build_registry


@dataclass
class ScanResult:
    findings: list[Finding]
    transcript: list[dict[str, object]]
    stop_reason: str
    graph: ReachGraph
    notes: list[str] = field(default_factory=list)
    agent_registry: AgentRegistry | None = None


def run_scan(
    *,
    targets: list[str],
    objective: str,
    router: ModelRouter,
    container: RuntimeContainer | None = None,
    egress_lock: bool = False,
    graph: ReachGraph | None = None,
    firer: HttpFirer | None = None,
    config: AgentConfig | None = None,
    knowledge_store: KnowledgeStore | None = None,
) -> ScanResult:
    """Run one autonomous scan mission and return its findings + transcript."""
    scope = ScopeGuard(engagement=Engagement.from_specs(targets), egress_lock=egress_lock)
    the_graph = graph or ReachGraph()
    the_firer = firer or HttpFirer(scope)
    # Router is shared with the record path so every finding gets an independent
    # adversarial confirmation review before it lands. agent_registry/skill_library
    # enable the root agent to `recall` methodology and `spawn_agent` specialists.
    ctx = ScanContext(
        graph=the_graph,
        firer=the_firer,
        container=container,
        router=router,
        agent_registry=AgentRegistry(),
        skill_library=SkillLibrary(),
        knowledge_store=knowledge_store,
    )
    registry = build_registry(ctx)
    loop = AgentLoop(router, registry, system_prompt=SYSTEM_PROMPT, config=config)
    result = loop.run(mission_text(targets, objective))
    return ScanResult(
        findings=the_graph.findings(),
        transcript=result.transcript,
        stop_reason=result.stop_reason,
        graph=the_graph,
        notes=ctx.notes,
        agent_registry=ctx.agent_registry,
    )
