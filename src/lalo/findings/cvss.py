"""CVSS v3.1 base-score computation — compute, don't trust a self-reported severity.

A reference agent's own reporting tool (``tools/reporting/tool.py``, read in
full) takes exactly this stance: an 8-metric breakdown is validated, built
into a ``CVSS:3.1/...`` vector string, and scored via the real ``cvss``
library rather than letting the filer state a severity directly. Adopted
directly — CVSS3 is a public standard, not reference-specific IP, and
"compute from a breakdown" is strictly more honest than a free-text severity
claim.
"""

from __future__ import annotations

from dataclasses import dataclass

from cvss import CVSS3

CVSS_METRICS: dict[str, tuple[str, ...]] = {
    "attack_vector": ("N", "A", "L", "P"),
    "attack_complexity": ("L", "H"),
    "privileges_required": ("N", "L", "H"),
    "user_interaction": ("N", "R"),
    "scope": ("U", "C"),
    "confidentiality": ("N", "L", "H"),
    "integrity": ("N", "L", "H"),
    "availability": ("N", "L", "H"),
}

_VECTOR_ABBREVIATIONS = {
    "attack_vector": "AV",
    "attack_complexity": "AC",
    "privileges_required": "PR",
    "user_interaction": "UI",
    "scope": "S",
    "confidentiality": "C",
    "integrity": "I",
    "availability": "A",
}


@dataclass(frozen=True)
class CvssResult:
    score: float
    severity: str
    vector: str


def validate_cvss_breakdown(breakdown: object) -> list[str]:
    """Every one of the 8 metrics must be present with a legal value."""
    if not isinstance(breakdown, dict) or not breakdown:
        return ["cvss_breakdown must be an object with all 8 CVSS metrics"]
    return [
        f"invalid {name}: {breakdown.get(name)!r} (must be one of {valid})"
        for name, valid in CVSS_METRICS.items()
        if breakdown.get(name) not in valid
    ]


def compute_cvss(breakdown: dict[str, str]) -> CvssResult:
    """Build the CVSS:3.1 vector from a validated breakdown and score it.

    Callers MUST run :func:`validate_cvss_breakdown` first — this assumes a
    breakdown with all 8 legal metric values already confirmed present.
    """
    vector = "CVSS:3.1/" + "/".join(
        f"{_VECTOR_ABBREVIATIONS[name]}:{breakdown[name]}" for name in CVSS_METRICS
    )
    scored = CVSS3(vector)
    base_severity = scored.severities()[0].lower()
    severity = "info" if base_severity == "none" else base_severity
    return CvssResult(score=scored.scores()[0], severity=severity, vector=vector)
