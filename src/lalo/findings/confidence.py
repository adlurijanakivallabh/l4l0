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
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..graph.model import EdgeKind, ReachabilityGraph

_MAX_CORROBORATION_ITEMS = 4
_MIN_SPECIFIC_EXCERPT_CHARS = 20
_MIN_PARTIAL_EXCERPT_CHARS = 8

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

    evidence_count = len(node.get("evidence", []))
    breakdown["corroboration_count"] = (
        min(evidence_count, _MAX_CORROBORATION_ITEMS)
        * _WEIGHTS["corroboration_count"]
        // _MAX_CORROBORATION_ITEMS
    )

    breakdown["specificity"] = _specificity_points(str(node.get("evidence_excerpt", "")))
    if breakdown["specificity"] < _WEIGHTS["specificity"]:
        flags.append("evidence_excerpt is short/generic - weak specificity signal")

    identities = node.get("identities_confirmed", [])
    cross_context = len(set(identities)) >= 2
    breakdown["cross_context_reproduction"] = (
        _WEIGHTS["cross_context_reproduction"] if cross_context else 0
    )

    chained = graph.has_node(finding_id) and graph.has_edge_of_kind(finding_id, EdgeKind.ENABLES)
    breakdown["chained_impact_success"] = _WEIGHTS["chained_impact_success"] if chained else 0

    return ConfidenceScore(score=sum(breakdown.values()), breakdown=breakdown, flags=flags)
