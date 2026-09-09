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

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field

from ..findings.confidence import ConfidenceScore, compute_confidence
from ..findings.dedup import dedup_key
from ..findings.review import ReviewVerdict
from ..graph.model import Chain, NodeKind, ReachabilityGraph

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
    remediation: str
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
    dedup_key: str = ""
    status: str = "open"
    source_location: str | list[dict[str, str]] | None = None
    prerequisites: str = ""
    impact: str = ""
    exploitation_steps: list[str] = field(default_factory=list)

    @property
    def effective_severity(self) -> str:
        return self.display_severity or self.cvss_severity


def collect_findings(graph: ReachabilityGraph) -> list[FindingRecord]:
    """Every finding on ``graph`` as a report-ready record, with its confidence computed."""
    records: list[FindingRecord] = []
    for finding_id in graph.nodes_of_kind(NodeKind.FINDING):
        node = graph.node(finding_id)
        confidence = compute_confidence(graph, finding_id)
        vuln_class = str(node.get("vuln_class", ""))
        target = str(node.get("target", ""))
        param = node.get("param")
        records.append(
            FindingRecord(
                finding_id=finding_id,
                title=str(node.get("title", "")),
                description=str(node.get("description", "")),
                vuln_class=vuln_class,
                target=target,
                param=param,
                evidence=list(node.get("evidence", [])),
                evidence_excerpt=str(node.get("evidence_excerpt", "")),
                evidence_grounded=bool(node.get("evidence_grounded", False)),
                counterevidence=str(node.get("counterevidence", "")),
                severity_change_conditions=str(node.get("severity_change_conditions", "")),
                remediation=str(node.get("remediation", "")),
                cvss_score=float(node.get("cvss_score", 0.0)),
                cvss_severity=str(node.get("cvss_severity", "info")),
                cvss_vector=str(node.get("cvss_vector", "")),
                confidence=confidence,
                reproduced=bool(node.get("reproduced", False)),
                identities_confirmed=list(node.get("identities_confirmed", [])),
                review_verdict=node.get("review_verdict"),
                review_proof_level=node.get("review_proof_level"),
                dedup_key=dedup_key(vuln_class, target, param),
                source_location=node.get("source_location"),
                prerequisites=str(node.get("prerequisites", "")),
                impact=str(node.get("impact", "")),
                exploitation_steps=list(node.get("exploitation_steps", [])),
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


@dataclass(frozen=True)
class ExecutiveSummary:
    """A pure roll-up of already-collected records - counts only, never an
    LLM decision point, matching this module's own "no LLM in the loop"
    principle for every other report-assembly step."""

    total_findings: int
    by_severity: dict[str, int]
    by_vuln_class: dict[str, int]
    highest_severity: str | None
    by_confidence: dict[str, int] = field(default_factory=dict)
    critical_findings: list[str] = field(default_factory=list)


def build_executive_summary(records: list[FindingRecord]) -> ExecutiveSummary:
    severity_counts = Counter(record.effective_severity for record in records)
    by_severity = dict(
        sorted(
            severity_counts.items(),
            key=lambda kv: SEVERITY_ORDER.get(kv[0], len(SEVERITY_ORDER)),
        )
    )
    by_vuln_class = dict(sorted(Counter(record.vuln_class for record in records).items()))
    by_confidence: dict[str, int] = {}
    for record in records:
        score = record.confidence.score
        band = "high" if score >= 80 else "medium" if score >= 50 else "low"
        by_confidence[band] = by_confidence.get(band, 0) + 1
    critical_findings = [
        record.title for record in records if record.effective_severity == "critical"
    ]
    return ExecutiveSummary(
        total_findings=len(records),
        by_severity=by_severity,
        by_vuln_class=by_vuln_class,
        highest_severity=next(iter(by_severity), None),
        by_confidence=by_confidence,
        critical_findings=critical_findings,
    )


@dataclass(frozen=True)
class ReportUsage:
    """LLM usage for the run, surfaced in the delivered report rather than
    only ever reaching the operator as a transient GUI toast (the gap an
    audit found: core/usage.py's own UsageStats was real and durably
    persisted, but report/writer.py, html.py, and pdf.py had zero references
    to it anywhere). ``total_cost_usd`` is ``None`` when no pricing table was
    configured for the run - "unknown", never a fabricated ``$0.00``,
    matching core/pricing.py's own "cost for an unrecognized model is
    unknown, not zero" design principle.
    """

    total_requests: int
    total_input_tokens: int
    total_output_tokens: int
    total_cost_usd: float | None
    # False when core/usage.py's own usage_accounting_status() reported a
    # record_usage() write failure during this run - the totals above may
    # be an undercount from that point on. True (the default) preserves
    # every existing ReportUsage(...) construction's exact prior behavior.
    accounting_complete: bool = True


@dataclass(frozen=True)
class ReportMetadata:
    """Which engagement and which model actually produced this report.

    Unlike :class:`ReportUsage` (populated only when the operator opts into
    usage_path tracking - off by default), both fields here are always real
    and available at the one real write_report() call site: the engagement
    scope is already computed for the agent system prompt
    (``Engagement.describe()``, see scan.py's own render_prompt call), and
    the resolved provider chain is already a precondition of starting the
    scan at all (load_settings() is checked non-empty before anything else
    runs). Kept as its own dataclass rather than folded into ReportUsage -
    target/scope has nothing to do with LLM token spend, and bundling them
    would silently hide the engagement/model info on every scan that
    doesn't opt into usage tracking, which is most of them.
    """

    engagement_scope: str
    model_provider: str


@dataclass(frozen=True)
class ChainRecord:
    """One resolved attack chain, ready to render — the graph's raw finding
    ids (:data:`~lalo.graph.model.EdgeKind.ENABLES` order) plus their
    human-readable titles, so a renderer never has to look anything up."""

    finding_ids: list[str]
    titles: list[str]


def build_chain_records(chains: Sequence[Chain], records: list[FindingRecord]) -> list[ChainRecord]:
    """Resolve each :class:`~lalo.graph.model.Chain`'s bare finding ids to
    the matching :class:`FindingRecord`'s own title, falling back to the id
    itself for a finding somehow absent from ``records`` (should not happen
    in practice, but a report render must never crash over it)."""
    title_by_id = {record.finding_id: (record.title or record.finding_id) for record in records}
    return [
        ChainRecord(
            finding_ids=list(chain.node_ids),
            titles=[title_by_id.get(node_id, node_id) for node_id in chain.node_ids],
        )
        for chain in chains
    ]


# One section per real ReviewVerdict value, plus a 4th bucket for a finding
# that was never reviewed at all (review_verdict is None - the review step
# is opt-in and non-blocking per CLAUDE.md, so plenty of real findings will
# never carry one). Order is "most immediately actionable first": CONFIRMED,
# then the ones the review step never weighed in on, then the two verdicts a
# reviewer actually returned doubt about - RULED_OUT last since CLAUDE.md's
# "neither layer ever removes a finding" means it still has to be shown,
# just not first.
VERDICT_SECTIONS: list[tuple[str | None, str]] = [
    (ReviewVerdict.CONFIRMED.value, "Confirmed"),
    (None, "Not Reviewed"),
    (ReviewVerdict.OPEN_PROOF_GAP.value, "Open Proof Gap"),
    (ReviewVerdict.RULED_OUT.value, "Ruled Out"),
]


def group_by_verdict(
    records: list[FindingRecord],
) -> list[tuple[str, list[FindingRecord]]]:
    """Bucket ``records`` by ``review_verdict``, in :data:`VERDICT_SECTIONS`
    order - every section is present in the result even when its bucket is
    empty, so a renderer can print its header unconditionally and nothing
    ever looks silently hidden. Filtering (not re-sorting) preserves
    whatever order ``records`` already came in - callers that pre-sort via
    :func:`sort_findings` keep that severity ordering within each bucket."""
    return [
        (label, [record for record in records if record.review_verdict == verdict_value])
        for verdict_value, label in VERDICT_SECTIONS
    ]


@dataclass(frozen=True)
class AttackSurfaceSummary:
    """Recon-level facts, independent of any specific finding - what was
    actually probed, so a tested-but-clean surface is visible in the
    delivered report rather than only ever showing up if it produced a
    finding."""

    endpoints: list[str]
    services: list[str]
    fingerprints: list[str]


def _describe_recon_node(graph: ReachabilityGraph, node_id: str) -> str:
    """``recon/facts.py``'s ``merge_facts`` stores every fact's own
    per-source metadata under an open ``extra`` bag with no fixed schema
    (any runner can put any key in it - confirmed by reading that module in
    full) - so this reads whatever keys are actually present rather than
    guessing a fixed set like ``name``/``port``/``technology``/``version``
    that would silently produce an empty description the moment a runner
    used different keys."""
    extra = graph.node(node_id).get("extra") or {}
    if not isinstance(extra, dict) or not extra:
        return node_id
    detail = ", ".join(f"{key}={value}" for key, value in extra.items())
    return f"{node_id} ({detail})"


def build_attack_surface_summary(graph: ReachabilityGraph) -> AttackSurfaceSummary:
    """Every ``ENDPOINT``/``SERVICE``/``FINGERPRINT`` node
    ``recon.facts.merge_facts`` has already scope-checked onto the graph -
    surfaced as its own report section, independent of whether it also
    happened to produce a finding."""
    endpoints = sorted(graph.nodes_of_kind(NodeKind.ENDPOINT))
    services = sorted(
        _describe_recon_node(graph, node_id) for node_id in graph.nodes_of_kind(NodeKind.SERVICE)
    )
    fingerprints = sorted(
        _describe_recon_node(graph, node_id)
        for node_id in graph.nodes_of_kind(NodeKind.FINGERPRINT)
    )
    return AttackSurfaceSummary(endpoints=endpoints, services=services, fingerprints=fingerprints)


def first_finding_id_by_vuln_class(records: list[FindingRecord]) -> dict[str, str]:
    """The id of the first (in ``records`` order) finding for each
    ``vuln_class`` - the anchor target a "Summary by Vulnerability Type"
    quick-index link jumps to. Only ever the first occurrence: once
    :func:`group_by_verdict` scatters same-category findings across
    different verdict sections, a single in-page anchor can't reach all of
    them at once - landing on the first is enough for a reader to find the
    rest from there."""
    first_id: dict[str, str] = {}
    for record in records:
        first_id.setdefault(record.vuln_class, record.finding_id)
    return first_id
