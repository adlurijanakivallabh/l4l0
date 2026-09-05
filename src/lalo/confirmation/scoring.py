"""Non-blocking confidence scoring.

Every finding is written regardless; this attaches a deterministic Confidence
Score (0–100) from six independent components:

- **reproducibility** — how many repeated fires agreed (finding metadata).
- **corroboration** — how many distinct evidence families agree.
- **specificity** — magnitude of deviation from baseline (diff), or direct proof.
- **cross_context** — reproduced under a second identity/session.
- **chained_impact** — an exploit chain / RCE PoC actually executed.
- **provenance** — is cited evidence text verifiably in the captured traffic. If
  not, this *lowers* the score and raises the ``evidence_unverified`` flag — the
  finding still ships, never dropped.

The LLM never sets these directly; they are computed from captured facts.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from ..models import EvidenceKind, Finding

# Component weights (sum to 1.0).
_WEIGHTS: dict[str, float] = {
    "reproducibility": 0.15,
    "corroboration": 0.20,
    "specificity": 0.20,
    "cross_context": 0.15,
    "chained_impact": 0.15,
    "provenance": 0.15,
}

# Per-kind baseline specificity when no explicit diff magnitude is present.
_KIND_SPECIFICITY: dict[EvidenceKind, float] = {
    EvidenceKind.EXECUTION: 1.0,
    EvidenceKind.OOB_CALLBACK: 1.0,
    EvidenceKind.DIFFERENTIAL: 0.6,
    EvidenceKind.STRUCTURAL: 0.6,
    EvidenceKind.BUSINESS_RULE: 0.6,
    EvidenceKind.TIMING: 0.5,
}


@dataclass
class ScoreBreakdown:
    components: dict[str, float]
    total: float
    flags: list[str] = field(default_factory=list)


class ConfidenceScorer:
    def __init__(self, weights: Mapping[str, float] | None = None) -> None:
        self.weights = dict(weights) if weights is not None else dict(_WEIGHTS)

    def score(
        self, finding: Finding, *, captures: Mapping[str, str] | None = None
    ) -> ScoreBreakdown:
        flags: list[str] = []
        meta = finding.metadata
        components = {
            "reproducibility": _reproducibility(meta),
            "corroboration": _corroboration(finding),
            "specificity": _specificity(finding),
            "cross_context": 1.0 if meta.get("cross_context_reproduced") else 0.0,
            "chained_impact": _chained_impact(finding),
            "provenance": _provenance(finding, captures, flags),
        }
        total = round(
            sum(self.weights.get(name, 0.0) * value for name, value in components.items()) * 100.0,
            1,
        )
        return ScoreBreakdown(
            components={k: round(v, 3) for k, v in components.items()},
            total=total,
            flags=flags,
        )


def _reproducibility(meta: Mapping[str, object]) -> float:
    agreed = meta.get("repeats_agreed", 1)
    if isinstance(agreed, int | float):
        n = int(agreed)
    elif isinstance(agreed, str) and agreed.isdigit():
        n = int(agreed)
    else:
        n = 1
    return min(1.0, max(0, n) / 3.0)


def _corroboration(finding: Finding) -> float:
    kinds = {e.kind for e in finding.evidence}
    return min(1.0, len(kinds) / 3.0)


def _specificity(finding: Finding) -> float:
    best = 0.0
    for e in finding.evidence:
        magnitude = e.metadata.get("diff_magnitude")
        if isinstance(magnitude, int | float):
            best = max(best, float(magnitude))
        else:
            best = max(best, _KIND_SPECIFICITY.get(e.kind, 0.4))
    return min(1.0, best)


def _chained_impact(finding: Finding) -> float:
    if finding.metadata.get("chained_impact"):
        return 1.0
    for e in finding.evidence:
        if e.kind is EvidenceKind.EXECUTION and e.metadata.get("succeeded"):
            return 1.0
    return 0.0


def _provenance(finding: Finding, captures: Mapping[str, str] | None, flags: list[str]) -> float:
    observed = [e for e in finding.evidence if e.observed]
    if not observed:
        return 0.5  # nothing to verify -> neutral
    verified = 0
    for e in observed:
        body = captures.get(e.fire_ref or "") if captures else None
        if body is not None and e.observed in body:
            verified += 1
    fraction = verified / len(observed)
    if fraction < 1.0:
        flags.append("evidence_unverified")
    return fraction


def score_finding(finding: Finding, *, captures: Mapping[str, str] | None = None) -> ScoreBreakdown:
    """Score a finding and write ``confidence`` + ``confidence_breakdown`` onto it."""
    breakdown = ConfidenceScorer().score(finding, captures=captures)
    finding.confidence = breakdown.total
    finding.confidence_breakdown = dict(breakdown.components)
    if breakdown.flags:
        finding.metadata.setdefault("confidence_flags", breakdown.flags)
    return breakdown
