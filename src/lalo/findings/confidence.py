"""The deterministic Confidence Score (0-100) — CLAUDE.md's first non-blocking layer.

No reference agent computes anything like this: each reduces "is this
finding real" to a single self-declared enum (a reference's own
``confidence: high|medium|low`` field, filled in by the same agent that
found the bug) or a single LLM role's narration. CLAUDE.md's design is
different in kind, not just degree — a score computed from properties of
the finding itself, independent of what the finder claims to believe.
Six components, each capped, summed to 0-100. Unverifiable evidence never
drops the finding (:mod:`~lalo.findings.tool` already lands it
unconditionally) — it earns zero points on ``evidence_provenance_match``
and is named in ``flags``, which is the "flagged, never dropped" behavior
CLAUDE.md specifies.

A small, named calibration catalogue (below, ``_CALIBRATION_RULES``) layers
two corrective heuristics on top of the base components — both purely
additive to the SCORE's calculation, never to whether a finding is reported
or which verdict :mod:`~lalo.findings.review` reaches:

- ``duplicate_evidence_discount``: an identical evidence blob cited more
  than once earns corroboration credit for only its first, distinct
  occurrence. Nothing before this stopped an agent (or a merge) from
  inflating ``corroboration_count`` by citing the exact same captured text
  several times, which is not independent corroboration of anything.
- ``unconfirmed_chain_discount``: a declared attack-chain link
  (:data:`~lalo.graph.model.EdgeKind.ENABLES`) earns full
  ``chained_impact_success`` credit only if the finding it connects to is
  ITSELF grounded and reproduced — chaining through a weak, unconfirmed
  finding is weaker evidence than the raw "an edge exists" check alone
  implied.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..graph.model import EdgeKind, ReachabilityGraph

_MAX_CORROBORATION_ITEMS = 4
_MIN_SPECIFIC_EXCERPT_CHARS = 20
_MIN_PARTIAL_EXCERPT_CHARS = 8

_CALIBRATION_RULES = {
    "duplicate_evidence_discount": (
        "identical evidence blobs cited more than once earn corroboration "
        "credit for only their first, distinct occurrence"
    ),
    "unconfirmed_chain_discount": (
        "a chain link to a finding that is not itself grounded and "
        "reproduced earns half chained_impact_success credit, not full"
    ),
}

_WEIGHTS = {
    "evidence_provenance_match": 25,
    "reproducibility": 20,
    "corroboration_count": 20,
    "specificity": 15,
    "cross_context_reproduction": 10,
    "chained_impact_success": 10,
}


@dataclass(frozen=True)
class ConfidenceScore:
    score: int
    breakdown: dict[str, int]
    flags: list[str] = field(default_factory=list)


def _specificity_points(excerpt: str) -> int:
    length = len(excerpt.strip())
    if length >= _MIN_SPECIFIC_EXCERPT_CHARS:
        return _WEIGHTS["specificity"]
    if length >= _MIN_PARTIAL_EXCERPT_CHARS:
        return _WEIGHTS["specificity"] // 2
    return 0


def compute_confidence(graph: ReachabilityGraph, finding_id: str) -> ConfidenceScore:
    node = graph.node(finding_id)
    breakdown: dict[str, int] = {}
    flags: list[str] = []

    grounded = bool(node.get("evidence_grounded", False))
    breakdown["evidence_provenance_match"] = (
        _WEIGHTS["evidence_provenance_match"] if grounded else 0
    )
    if not grounded:
        flags.append("evidence_excerpt was not found verbatim in any evidence blob - unverifiable")

    reproduced = bool(node.get("reproduced", False))
    breakdown["reproducibility"] = _WEIGHTS["reproducibility"] if reproduced else 0
    if not reproduced:
        flags.append("not marked as reproduced - only a single observation")

    raw_evidence = node.get("evidence", [])
    distinct_evidence_count = len(set(raw_evidence))
    breakdown["corroboration_count"] = (
        min(distinct_evidence_count, _MAX_CORROBORATION_ITEMS)
        * _WEIGHTS["corroboration_count"]
        // _MAX_CORROBORATION_ITEMS
    )
    if distinct_evidence_count < len(raw_evidence):
        rule = _CALIBRATION_RULES["duplicate_evidence_discount"]
        flags.append(
            f"calibration[duplicate_evidence_discount]: {rule} "
            f"({len(raw_evidence)} cited, {distinct_evidence_count} distinct)"
        )

    breakdown["specificity"] = _specificity_points(str(node.get("evidence_excerpt", "")))
    if breakdown["specificity"] < _WEIGHTS["specificity"]:
        flags.append("evidence_excerpt is short/generic - weak specificity signal")

    identities = node.get("identities_confirmed", [])
    cross_context = len(set(identities)) >= 2
    breakdown["cross_context_reproduction"] = (
        _WEIGHTS["cross_context_reproduction"] if cross_context else 0
    )

    chain_links = (
        graph.connected_via(finding_id, EdgeKind.ENABLES) if graph.has_node(finding_id) else []
    )
    if not chain_links:
        breakdown["chained_impact_success"] = 0
    else:
        chain_confirmed = any(
            bool(graph.node(link).get("evidence_grounded", False))
            and bool(graph.node(link).get("reproduced", False))
            for link in chain_links
            if graph.has_node(link)
        )
        if chain_confirmed:
            breakdown["chained_impact_success"] = _WEIGHTS["chained_impact_success"]
        else:
            breakdown["chained_impact_success"] = _WEIGHTS["chained_impact_success"] // 2
            rule = _CALIBRATION_RULES["unconfirmed_chain_discount"]
            flags.append(f"calibration[unconfirmed_chain_discount]: {rule}")

    return ConfidenceScore(score=sum(breakdown.values()), breakdown=breakdown, flags=flags)
