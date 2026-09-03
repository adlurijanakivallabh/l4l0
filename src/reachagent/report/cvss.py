"""CVSS v3.1 base-score calculator (v3 V7 report content gap).

The report previously showed only a bare per-severity number (``critical`` ->
``"9.5"``, from ``renderer.py``'s ``_SEVERITY_SCORE`` — kept unchanged, still
used for SARIF's own ``security-severity`` field). A professional report
needs the FULL base vector string too (``CVSS:3.1/AV:N/AC:L/...``), not just
a number — and the score must be genuinely DERIVED from that vector, never a
second, independently-chosen number that could silently drift out of sync
with it.

This module implements the official FIRST.org CVSS v3.1 base-score formula
(https://www.first.org/cvss/v3.1/specification-document, section 7.1) — a
deterministic calculation, not a heuristic — so ``vuln_class_context`` only
ever needs to supply a vector string; the score is always consistent with it
by construction.
"""

from __future__ import annotations

# Metric value weights (CVSS v3.1 spec table 7-8/7-9/7-10/7-11/7-12).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS's own specified rounding: round UP to the nearest 0.1 (spec §7.1's
    ``Roundup`` — never plain ``round()``, which would round some values down)."""
    int_value = round(value * 100_000)
    if int_value % 10_000 == 0:
        return int_value / 100_000
    return (int_value // 10_000 + 1) / 10


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a bare base-metric vector (``"AV:N/AC:L/..."``, no ``CVSS:3.1/`` prefix)."""
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if not part or ":" not in part:
            continue
        key, _, value = part.partition(":")
        metrics[key] = value
    return metrics


def base_score(vector: str) -> float:
    """Compute the CVSS v3.1 base score from a base-metric vector string.

    ``vector`` is the bare metric string (``"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"``),
    without the ``CVSS:3.1/`` prefix. Raises ``KeyError`` on a missing/invalid
    metric — callers own a fixed, reviewed vector table, so a malformed entry
    should fail loudly at test time, never silently score as 0.0.
    """
    m = parse_vector(vector)
    av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
    scope_changed = m["S"] == "C"
    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
    c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]

    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    total = impact + exploitability
    if scope_changed:
        return _roundup(min(1.08 * total, 10.0))
    return _roundup(min(total, 10.0))


def format_score(score: float) -> str:
    """CVSS scores are conventionally shown to one decimal place."""
    return f"{score:.1f}"


def full_vector_string(vector: str) -> str:
    """The complete, displayable vector including the version prefix."""
    return f"CVSS:3.1/{vector}"
