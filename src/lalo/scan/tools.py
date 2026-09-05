"""Concrete scan tools bound to the real services (firer, runtime, graph)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import cast

from ..agent.loop import AgentConfig, AgentLoop
from ..agent.tools import FunctionTool, ToolRegistry, ToolResult
from ..agents.coordinator import merge_findings
from ..agents.registry import AgentRegistry
from ..confirmation.review import adversarial_review, apply_review
from ..confirmation.scoring import score_finding
from ..core.model_router import ModelRouter
from ..core.redaction import redact
from ..execution.firer import HttpFirer
from ..graph.store import ReachGraph
from ..knowledge import KnowledgeStore, SkillLibrary
from ..knowledge.store import recall as knowledge_recall
from ..models import Evidence, EvidenceKind, Finding, Severity
from ..prompts import SYSTEM_PROMPT
from ..runtime.container import RuntimeContainer

ToolFunc = Callable[[dict[str, object]], ToolResult]

_MAX_OBS = 800
_DEFAULT_MAX_SPAWN_DEPTH = 3
_DEFAULT_CHILD_MAX_STEPS = 12


@dataclass
class ScanContext:
    graph: ReachGraph
    firer: HttpFirer
    container: RuntimeContainer | None = None
    captures: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    # When set, every recorded finding gets an independent adversarial review
    # (assume-false, disprove from captured evidence) before it lands.
    router: ModelRouter | None = None
    # Multi-agent spawning: shared across the whole tree (parent + every child).
    agent_registry: AgentRegistry | None = None
    skill_library: SkillLibrary | None = None
    knowledge_store: KnowledgeStore | None = None
    agent_id: str | None = None  # this agent's own id in agent_registry (None = root)
    depth: int = 0
    max_depth: int = _DEFAULT_MAX_SPAWN_DEPTH
    _fire_seq: int = 0


def _severity(value: object) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError:
        return Severity.MEDIUM


def _evidence_kind(value: object) -> EvidenceKind:
    try:
        return EvidenceKind(str(value).lower())
    except ValueError:
        return EvidenceKind.STRUCTURAL


def _http_tool(ctx: ScanContext) -> ToolFunc:
    def run(args: dict[str, object]) -> ToolResult:
        method = str(args.get("method", "GET")).upper()
        url = str(args.get("url", ""))
        raw_headers = args.get("headers")
        headers = (
            {str(k): str(v) for k, v in raw_headers.items()}
            if isinstance(raw_headers, dict)
            else None
        )
        body = args.get("body")
        content = body.encode("utf-8") if isinstance(body, str) else None
        result = ctx.firer.fire(method, url, headers=headers, content=content)
        ctx.graph.add_endpoint(url, method)
        if not result.fired:
            return ToolResult(f"not fired (scope: {result.scope_reason})", ok=False)
        if result.error:
            return ToolResult(f"transport error: {result.error}", ok=False)
        ref = f"fire{ctx._fire_seq}"
        ctx._fire_seq += 1
        body_text = result.body.decode("utf-8", "replace")
        ctx.captures[ref] = body_text
        snippet = redact(body_text[:_MAX_OBS])
        return ToolResult(
            f"[fire_ref={ref}] status={result.status} len={len(result.body)}\n{snippet}"
        )

    return run


def _record_tool(ctx: ScanContext) -> ToolFunc:
    def run(args: dict[str, object]) -> ToolResult:
        raw_evidence = args.get("evidence")
        evidence: list[Evidence] = []
        if isinstance(raw_evidence, list):
            for item in raw_evidence:
                if not isinstance(item, dict):
                    continue
                entry = cast("dict[str, object]", item)
                fire_ref = entry.get("fire_ref")
                evidence.append(
                    Evidence(
                        kind=_evidence_kind(entry.get("kind")),
                        summary=str(entry.get("summary", "")),
                        fire_ref=str(fire_ref) if fire_ref else None,
                        observed=str(entry.get("observed", "")),
                    )
                )
        finding = Finding.create(
            title=str(args.get("title", "untitled")),
            vuln_class=str(args.get("vuln_class", "unknown")),
            severity=_severity(args.get("severity")),
            target=str(args.get("target", "")),
            evidence=evidence,
        )
        finding.counterevidence = str(args.get("counterevidence", ""))
        finding.severity_change_conditions = str(args.get("severity_change_conditions", ""))
        breakdown = score_finding(finding, captures=ctx.captures)
        review_note = ""
        if ctx.router is not None:
            verdict = adversarial_review(finding, ctx.captures, ctx.router)
            apply_review(finding, verdict)
            review_note = f" review={verdict.verdict}(L{verdict.proof_level})"
        ctx.graph.add_finding(finding)
        flags = f" flags={breakdown.flags}" if breakdown.flags else ""
        return ToolResult(
            f"recorded finding {finding.id[:8]} '{finding.title}' "
            f"confidence={finding.confidence}{flags}{review_note}"
        )

    return run


def _run_command_tool(ctx: ScanContext) -> ToolFunc:
    # Intentional free shell (the core L4L0 execution model): the agent may run
    # ANY command — no allowlist, no argv restriction — because that freedom never
    # reaches the host. `exec` runs ONLY inside the disposable, host-isolated
    # runtime container (no host mounts, no docker socket, cap-drop ALL,
    # no-new-privileges; see runtime/container.py). There is deliberately no
    # host-shell path: the tool is unavailable unless such a container exists, so a
    # prompt-injected command from a target response can at worst dirty the
    # throwaway container, never the operator's machine. See CLAUDE.md "Safety
    # posture". This is the accepted, operator-chosen tradeoff, not an oversight.
    def run(args: dict[str, object]) -> ToolResult:
        if ctx.container is None:
            return ToolResult("run_command unavailable: no runtime container", ok=False)
        cmd = str(args.get("cmd", ""))
        result = ctx.container.exec(cmd)  # contained: runs inside the isolated container only
        output = redact((result.stdout + result.stderr)[:_MAX_OBS])
        return ToolResult(f"exit={result.exit_code}\n{output}", ok=result.ok)

    return run


def _note_tool(ctx: ScanContext) -> ToolFunc:
    def run(args: dict[str, object]) -> ToolResult:
        ctx.notes.append(str(args.get("text", "")))
        return ToolResult("noted")

    return run


def _recall_tool(ctx: ScanContext) -> ToolFunc:
    def run(args: dict[str, object]) -> ToolResult:
        query = str(args.get("query", ""))
        if not query:
            return ToolResult("recall requires a query", ok=False)
        text = knowledge_recall(query, library=ctx.skill_library, store=ctx.knowledge_store, k=3)
        return ToolResult(text)

    return run


def _child_context(ctx: ScanContext, agent_id: str) -> ScanContext:
    """Build an isolated child context: own graph snapshot, shared everything else."""
    return ScanContext(
        graph=ctx.graph.snapshot(),
        firer=ctx.firer,
        container=ctx.container,
        router=ctx.router,
        agent_registry=ctx.agent_registry,
        skill_library=ctx.skill_library,
        knowledge_store=ctx.knowledge_store,
        agent_id=agent_id,
        depth=ctx.depth + 1,
        max_depth=ctx.max_depth,
    )


def _spawn_agent_tool(ctx: ScanContext) -> ToolFunc:
    # Reference-informed: an agent-callable spawn tool (not host-only), matching
    # the reference "specialist gets 1-3 skills, parent merges its AUTHORITATIVE
    # findings by id, never trusts the child's prose" pattern -- improved here by
    # merging from a genuinely isolated deep-copied graph (the reference shares one
    # global report store instead) and a hard depth ceiling against runaway
    # recursive spawning (ponytail: fixed ceiling, raise via max_depth if needed).
    def run(args: dict[str, object]) -> ToolResult:
        if ctx.router is None or ctx.agent_registry is None:
            return ToolResult("spawn_agent unavailable: no router/registry configured", ok=False)
        if ctx.depth >= ctx.max_depth:
            return ToolResult(
                f"spawn_agent refused: max spawn depth {ctx.max_depth} reached", ok=False
            )
        name = str(args.get("name", "specialist"))
        task = str(args.get("task", ""))
        if not task:
            return ToolResult("spawn_agent requires a task", ok=False)
        raw_skills = args.get("skills")
        skill_names = [str(s) for s in raw_skills] if isinstance(raw_skills, list) else []

        node = ctx.agent_registry.register(name, task, parent_id=ctx.agent_id)
        child_ctx = _child_context(ctx, node.agent_id)

        skill_text = ""
        if skill_names and ctx.skill_library is not None:
            found = [ctx.skill_library.get(n) for n in skill_names]
            skill_text = "\n\n".join(f"SKILL[{s.name}]:\n{s.text}" for s in found if s)
        mission = f"{task}\n\n{skill_text}" if skill_text else task

        registry = build_registry(child_ctx)
        loop = AgentLoop(
            ctx.router,
            registry,
            system_prompt=SYSTEM_PROMPT,
            config=AgentConfig(max_steps=_DEFAULT_CHILD_MAX_STEPS),
        )
        try:
            result = loop.run(mission)
        except Exception as exc:  # noqa: BLE001 - a child crash never takes down the parent
            ctx.agent_registry.complete(node.agent_id, "failed", [])
            return ToolResult(f"child {name} ({node.agent_id}) crashed: {exc}", ok=False)

        merged_ids = merge_findings(ctx.graph, child_ctx.graph)
        ctx.agent_registry.complete(node.agent_id, "completed", merged_ids)
        return ToolResult(
            f"child {name} ({node.agent_id}) {result.stop_reason} after {result.steps} steps.\n"
            f"Authoritative finding ids (use these, not the prose below): {merged_ids}\n"
            f"Child's own summary (non-authoritative): {result.summary}"
        )

    return run


def _view_agent_graph_tool(ctx: ScanContext) -> ToolFunc:
    def run(args: dict[str, object]) -> ToolResult:
        if ctx.agent_registry is None:
            return ToolResult("no agents spawned yet")
        return ToolResult(ctx.agent_registry.render_tree())

    return run


def build_registry(ctx: ScanContext) -> ToolRegistry:
    tools = [
        FunctionTool(
            "http",
            "Fire an HTTP request against an in-scope target. "
            "args: method, url, headers?(obj), body?(str). Returns status, length, "
            "a body snippet, and a fire_ref to cite as evidence.",
            _http_tool(ctx),
        ),
        FunctionTool(
            "record_finding",
            "Record a vulnerability. args: title, vuln_class, "
            "severity(info|low|medium|high|critical), target, "
            "evidence:[{kind,summary,fire_ref,observed}], counterevidence (the "
            "strongest case AGAINST it), severity_change_conditions. Confidence is "
            "scored against captured traffic; nothing is withheld.",
            _record_tool(ctx),
        ),
        FunctionTool("note", "Save a short note. args: text", _note_tool(ctx)),
        FunctionTool(
            "recall",
            "Retrieve the methodology skill and any past findings relevant to a "
            "vuln class or question. args: query. Call this before testing a class "
            "you haven't recalled yet.",
            _recall_tool(ctx),
        ),
    ]
    if ctx.container is not None:
        tools.append(
            FunctionTool(
                "run_command",
                "Run a shell command in the isolated sandbox (any tool). args: cmd",
                _run_command_tool(ctx),
            )
        )
    if ctx.router is not None and ctx.agent_registry is not None:
        tools.append(
            FunctionTool(
                "spawn_agent",
                "Spawn a specialist child agent for a focused subtask (e.g. one "
                "vuln class). args: name, task, skills:[skill names]. Check "
                "view_agent_graph first to avoid duplicating work. The child's "
                "authoritative findings are merged back automatically.",
                _spawn_agent_tool(ctx),
            )
        )
        tools.append(
            FunctionTool(
                "view_agent_graph",
                "See every spawned agent, its status, and its parent — check "
                "before spawning to avoid duplicate work.",
                _view_agent_graph_tool(ctx),
            )
        )
    return ToolRegistry(tools)
