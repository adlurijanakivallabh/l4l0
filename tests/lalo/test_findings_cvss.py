"""Tests for CVSS3 computation from a metric breakdown."""

from __future__ import annotations

from lalo.findings.cvss import compute_cvss, validate_cvss_breakdown

_CRITICAL_RCE = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "C",
    "confidentiality": "H",
    "integrity": "H",
    "availability": "H",
}


def test_compute_cvss_matches_the_known_critical_vector() -> None:
    result = compute_cvss(_CRITICAL_RCE)
    assert result.vector == ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert result.severity == "critical"
    assert result.score == 10.0


def test_compute_cvss_low_impact_scores_low_severity() -> None:
    low = {**_CRITICAL_RCE, "confidentiality": "N", "integrity": "N", "availability": "L"}
    result = compute_cvss(low)
    assert result.severity in {"low", "medium"}
    assert result.score < 6.0


def test_validate_cvss_breakdown_rejects_missing_object() -> None:
    assert validate_cvss_breakdown(None) == [
        "cvss_breakdown must be an object with all 8 CVSS metrics"
    ]
    assert validate_cvss_breakdown({}) == [
        "cvss_breakdown must be an object with all 8 CVSS metrics"
    ]


def test_validate_cvss_breakdown_rejects_each_illegal_metric_value() -> None:
    bad = {**_CRITICAL_RCE, "attack_vector": "X", "scope": "?"}
    errors = validate_cvss_breakdown(bad)
    assert len(errors) == 2
    assert any("attack_vector" in e for e in errors)
    assert any("scope" in e for e in errors)


def test_validate_cvss_breakdown_accepts_a_full_legal_breakdown() -> None:
    assert validate_cvss_breakdown(_CRITICAL_RCE) == []
