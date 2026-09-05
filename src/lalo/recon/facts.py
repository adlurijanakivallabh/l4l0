"""Typed recon facts, merged into the graph only after a host-side scope check.

Confirmed against every reference's opposite failure mode: none of the five
enforces scope at the request layer at all (Phase 3's own finding), so none
of them has anything to say about a *discovery result* granting scope either
— there is simply no gate to bypass in their designs. This module builds
the gate a spec/tool result must pass through regardless of which runner
produced it: a fact's claimed URL is checked with the exact same
:class:`~lalo.execution.scope.ScopeGuard` the firer uses, and only an
in-engagement fact ever becomes a graph node. Nothing about a fact's own
content — a spec's `servers` field, a tool's own claim about a host — can
self-grant scope; the merge step here is the only thing empowered to do so,
and it uses the same allowlist the firer would.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum

from ..execution.scope import ScopeGuard
from ..graph import NodeKind, ReachabilityGraph


class FactKind(StrEnum):
    ENDPOINT = "endpoint"
    HOST = "host"
    TECHNOLOGY = "technology"


_NODE_KIND_FOR: dict[FactKind, NodeKind] = {
    FactKind.ENDPOINT: NodeKind.ENDPOINT,
    FactKind.HOST: NodeKind.SERVICE,
    FactKind.TECHNOLOGY: NodeKind.FINGERPRINT,
}


@dataclass(frozen=True)
class ReconFact:
    """One discovery claim: 'this URL is reachable, per this source.'"""

    kind: FactKind
    url: str
    source: str
    extra: dict[str, object] = field(default_factory=dict)


@dataclass
class MergeReport:
    accepted: list[ReconFact] = field(default_factory=list)
    rejected: list[tuple[ReconFact, str]] = field(default_factory=list)


def merge_facts(
    graph: ReachabilityGraph, scope: ScopeGuard, facts: Iterable[ReconFact]
) -> MergeReport:
    """Scope-check every fact before writing it to the graph; never silently drop a rejection."""
    report = MergeReport()
    for fact in facts:
        decision = scope.check(fact.url)
        if not decision.allowed:
            report.rejected.append((fact, decision.reason))
            continue
        if not graph.has_node(fact.url):
            graph.add_node(fact.url, _NODE_KIND_FOR[fact.kind], source=fact.source, **fact.extra)
        report.accepted.append(fact)
    return report
