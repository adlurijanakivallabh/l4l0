"""Assemble report-ready finding records from the reachability graph.

Reference reads for this phase (all five, real source). A reference agent's
own ``report/writer.py`` and ``report/coverage.py`` (both read in full) and
its ``report/sarif.py`` (read for structure — the concrete document builders,
not its SAST/code-location-specific machinery) supplied the ideas cited
throughout :mod:`lalo.report`. This module specifically adopts the severity
ordering convention (``critical`` < ``high`` < ``medium`` < ``low`` < ``info``,
a generic, non-reference-specific sort key) and confirms, independently, a
principle two other references converge on directly from their own real
source: a reference SAST platform's ``findings-renderer.ts``/``sarif-exporter.ts``
("No LLM in the loop — every field maps directly from a JSON key") and a
reference platform's own ``generateReport`` ("pure Markdown string
concatenation") both state that report rendering must never itself be an
LLM decision point. This module and its siblings only ever transform
already-computed, already-persisted data (the Finding graph node plus
:mod:`lalo.findings.confidence`'s deterministic score) — an LLM adversarial
review result, if one has already been run, is read back from wherever
:func:`~lalo.findings.review.run_adversarial_review` persisted it onto the
node (``review_verdict``/``review_proof_level``), never something a
report-generation call triggers on its own. A finding never reviewed simply
has neither key set, and both fields fall back to ``None`` — rendered as no
review section at all, not a fabricated "not reviewed" verdict.

Dedup is not re-implemented here: :mod:`lalo.findings.dedup` already merges
same-(class, target, param) evidence into one graph node the moment a
second ``record_finding`` call for it arrives (Phase 12a) — one node per
distinct finding is a structural invariant of the graph by the time a
report ever reads it, not something this module has to re-derive.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..findings.confidence import ConfidenceScore, compute_confidence
from ..graph.model import NodeKind, ReachabilityGraph

SEVERITY_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class FindingRecord:
    """One finding, ready to render — the graph node's data plus its computed score."""

    finding_id: str
    title: str
    description: str
    vuln_class: str
    target: str
    param: str | None
    evidence: list[str]
    evidence_excerpt: str
    evidence_grounded: bool
    counterevidence: str
    severity_change_conditions: str
    cvss_score: float
    cvss_severity: str
    cvss_vector: str
    confidence: ConfidenceScore
    reproduced: bool
    identities_confirmed: list[str]
    display_severity: str | None = None
    override_reason: str | None = None
    review_verdict: str | None = None
    review_proof_level: str | None = None

    @property
    def effective_severity(self) -> str:
        return self.display_severity or self.cvss_severity


def collect_findings(graph: ReachabilityGraph) -> list[FindingRecord]:
    """Every finding on ``graph`` as a report-ready record, with its confidence computed."""
    records: list[FindingRecord] = []
    for finding_id in graph.nodes_of_kind(NodeKind.FINDING):
        node = graph.node(finding_id)
        confidence = compute_confidence(graph, finding_id)
        records.append(
            FindingRecord(
                finding_id=finding_id,
                title=str(node.get("title", "")),
                description=str(node.get("description", "")),
                vuln_class=str(node.get("vuln_class", "")),
                target=str(node.get("target", "")),
                param=node.get("param"),
                evidence=list(node.get("evidence", [])),
                evidence_excerpt=str(node.get("evidence_excerpt", "")),
                evidence_grounded=bool(node.get("evidence_grounded", False)),
                counterevidence=str(node.get("counterevidence", "")),
                severity_change_conditions=str(node.get("severity_change_conditions", "")),
                cvss_score=float(node.get("cvss_score", 0.0)),
                cvss_severity=str(node.get("cvss_severity", "info")),
                cvss_vector=str(node.get("cvss_vector", "")),
                confidence=confidence,
                reproduced=bool(node.get("reproduced", False)),
                identities_confirmed=list(node.get("identities_confirmed", [])),
                review_verdict=node.get("review_verdict"),
                review_proof_level=node.get("review_proof_level"),
            )
        )
    return records


def sort_findings(records: list[FindingRecord]) -> list[FindingRecord]:
    """Severity first (critical to info), then confidence score descending."""
    return sorted(
        records,
        key=lambda r: (
            SEVERITY_ORDER.get(r.effective_severity, len(SEVERITY_ORDER)),
            -r.confidence.score,
        ),
    )
