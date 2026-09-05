"""CVSS scoring — computed, never operator-trusted.

Two entry points, both compute-don't-trust:
- ``compute_cvss3(metrics)`` builds a CVSS:3.1 vector from the 8 base metrics and
  computes the real score/severity/vector via the ``cvss`` library (the rigorous
  path — the score follows the metrics; you fix the metric, not the number).
- ``nominal_cvss(severity)`` is the fallback base estimate when no metric
  breakdown is available.
"""

from __future__ import annotations

from cvss import CVSS3

from ..models import Severity

_BASE: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 3.1,
    Severity.MEDIUM: 5.3,
    Severity.HIGH: 7.5,
    Severity.CRITICAL: 9.8,
}

# The 8 CVSS:3.1 base metrics and their allowed values.
_METRICS: dict[str, tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "R"),
    "S": ("U", "C"),
    "C": ("N", "L", "H"),
    "I": ("N", "L", "H"),
    "A": ("N", "L", "H"),
}


def nominal_cvss(severity: Severity) -> float:
    return _BASE.get(severity, 0.0)


def compute_cvss3(metrics: dict[str, str]) -> tuple[float, str, str]:
    """Return (base_score, severity, vector) computed from the 8 base metrics.

    Raises ``ValueError`` if a metric is missing or has an invalid value — the
    score is only ever the true output of a valid vector, never a guess.
    """
    parts: list[str] = []
    for metric, allowed in _METRICS.items():
        value = metrics.get(metric)
        if value not in allowed:
            raise ValueError(f"CVSS metric {metric} must be one of {allowed}, got {value!r}")
        parts.append(f"{metric}:{value}")
    vector = "CVSS:3.1/" + "/".join(parts)
    cvss = CVSS3(vector)
    score = float(cvss.scores()[0])
    base_severity = cvss.severities()[0].lower()
    severity = "info" if base_severity == "none" else base_severity
    return score, severity, vector
