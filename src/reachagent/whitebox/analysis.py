"""White-box analysis entrypoint (Build Order 7).

Runs every static tool against one operator-supplied repo path and writes
their facts directly into the SAME graph the live black-box scan uses —
additive only, never a replacement (§1, §9). Nothing here ever touches
``Finding``/``run_oracle``, with the one narrow, structurally-separate
exception already documented on :class:`~reachagent.graph.nodes.StaticAdvisory`.
"""

from __future__ import annotations

from reachagent.execution.audit import AuditLog
from reachagent.graph.store import ReachabilityGraph
from reachagent.whitebox.sca import scan_dependencies
from reachagent.whitebox.tools.secrets import TruffleHogRunner
from reachagent.whitebox.tools.semgrep import SemgrepRunner


def run_whitebox_analysis(
    *,
    repo_path: str,
    graph: ReachabilityGraph,
    audit: AuditLog | None = None,
) -> dict[str, int]:
    """Run semgrep + TruffleHog + manifest/NVD SCA against ``repo_path``.

    Each tool's own gates (path-exists, missing-binary, live-env, memory)
    already make this safe to call unconditionally — a missing binary or a
    disabled live-tool flag degrades to zero facts for that tool, never an
    error. Returns a small summary count dict for narration.
    """
    audit = audit or AuditLog()
    SemgrepRunner(graph=graph, audit=audit).run(repo_path)
    TruffleHogRunner(graph=graph, audit=audit).run(repo_path)
    scan_dependencies(repo_path, graph)
    return {
        "source_files": len(graph.source_files()),
        "secrets": len(graph.secrets()),
        "package_dependencies": len(graph.package_dependencies()),
        "static_advisories": len(graph.static_advisories()),
    }
