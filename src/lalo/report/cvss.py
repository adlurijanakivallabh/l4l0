"""Nominal CVSS base scores (computed from severity, never operator-trusted).

A deliberately simple severity->base mapping; a full CVSS-vector calculator can
replace it behind ``nominal_cvss`` later. Labeled nominal so it is never mistaken
for a hand-tuned score.
"""

from __future__ import annotations

from ..models import Severity

_BASE: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 3.1,
    Severity.MEDIUM: 5.3,
    Severity.HIGH: 7.5,
    Severity.CRITICAL: 9.8,
}


def nominal_cvss(severity: Severity) -> float:
    return _BASE.get(severity, 0.0)
