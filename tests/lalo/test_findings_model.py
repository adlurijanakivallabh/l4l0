"""Tests for the Finding required-field gate (a call-shape check, not a truth gate)."""

from __future__ import annotations

from lalo.findings.model import validate_finding_fields

_VALID_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "N",
    "availability": "N",
}


def _full_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "title": "SQLi in /search",
        "description": "The q parameter is concatenated into a raw query.",
        "vuln_class": "sql-injection",
        "target": "https://x.example.com/search",
        "evidence": ["HTTP/1.1 500 Internal Server Error\nsyntax error near 'OR'"],
        "evidence_excerpt": "syntax error near 'OR'",
        "counterevidence": "No WAF observed; error is a raw DB driver message.",
        "severity_change_conditions": "Confirming data exfiltration would raise severity.",
        "remediation": "Apply input validation and least-privilege fixes.",
        "cvss_breakdown": _VALID_CVSS,
    }
    base.update(overrides)
    return base


def test_validate_finding_fields_accepts_a_fully_populated_finding() -> None:
    assert validate_finding_fields(_full_fields()) == []


def test_validate_finding_fields_reports_every_missing_required_text_field() -> None:
    errors = validate_finding_fields(_full_fields(title="", counterevidence="   "))
    assert any("title" in e for e in errors)
    assert any("counterevidence" in e for e in errors)
    assert len(errors) == 2


def test_validate_finding_fields_rejects_empty_evidence_list() -> None:
    errors = validate_finding_fields(_full_fields(evidence=[]))
    assert any("evidence cannot be empty" in e for e in errors)


def test_validate_finding_fields_rejects_evidence_of_only_blank_strings() -> None:
    errors = validate_finding_fields(_full_fields(evidence=["   ", ""]))
    assert any("evidence cannot be empty" in e for e in errors)


def test_validate_finding_fields_rejects_an_incomplete_cvss_breakdown() -> None:
    errors = validate_finding_fields(_full_fields(cvss_breakdown={"attack_vector": "N"}))
    assert any("invalid" in e for e in errors)


def test_validate_finding_fields_rejects_a_missing_cvss_breakdown() -> None:
    errors = validate_finding_fields(_full_fields(cvss_breakdown=None))
    assert any("cvss_breakdown" in e for e in errors)
