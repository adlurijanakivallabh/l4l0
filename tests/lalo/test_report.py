"""Tests for report rendering, PoC, CVSS, and exporters."""

from __future__ import annotations

import json

import pytest

from lalo.detectors.ledger import CoverageLedger
from lalo.models import Evidence, EvidenceKind, Finding, Severity
from lalo.report import (
    compute_cvss3,
    curl_poc,
    dedup_findings,
    nominal_cvss,
    to_json,
    to_markdown,
    to_sarif,
)


def _findings() -> list[Finding]:
    high = Finding.create("SQLi in id", "sqli", Severity.HIGH, "https://app/item?id=1")
    high.confidence = 82.0
    high.evidence.append(Evidence(EvidenceKind.STRUCTURAL, "db error"))
    high.metadata["parameter"] = "id"
    crit = Finding.create("RCE via ping", "cmdi", Severity.CRITICAL, "https://app/ping")
    crit.confidence = 95.0
    return [high, crit]


def test_nominal_cvss() -> None:
    assert nominal_cvss(Severity.CRITICAL) == 9.8
    assert nominal_cvss(Severity.INFO) == 0.0


def test_compute_cvss3_from_metrics() -> None:
    score, severity, vector = compute_cvss3(
        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
    )
    assert score == 9.8
    assert severity == "critical"
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_compute_cvss3_rejects_bad_metric() -> None:
    bad = {"AV": "Z", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
    with pytest.raises(ValueError, match="AV"):
        compute_cvss3(bad)


def test_dedup_findings_keeps_highest_confidence() -> None:
    a = Finding.create("sqli", "sqli", Severity.HIGH, "https://app/item")
    a.metadata["parameter"] = "id"
    a.confidence = 40.0
    b = Finding.create("sqli again", "sqli", Severity.HIGH, "https://app/item")
    b.metadata["parameter"] = "id"
    b.confidence = 80.0
    deduped = dedup_findings([a, b])
    assert len(deduped) == 1
    assert deduped[0].confidence == 80.0
    assert deduped[0].metadata["duplicates_absorbed"] == 1


def test_counterevidence_rendered() -> None:
    f = Finding.create("sqli", "sqli", Severity.HIGH, "https://app/item")
    f.counterevidence = "the parameter may be numeric-cast server-side"
    f.severity_change_conditions = "confirmed data exfiltration would raise to critical"
    md = to_markdown([f])
    assert "Counterevidence" in md
    assert "numeric-cast" in md
    assert "Severity would change if" in md


def test_curl_poc_mentions_parameter() -> None:
    f = _findings()[0]
    poc = curl_poc(f)
    assert poc.startswith("curl")
    assert "id" in poc


def test_markdown_sorts_by_severity_and_lists_not_assessed() -> None:
    ledger = CoverageLedger()
    ledger.mark_applicable("https://app/x", "xss")
    md = to_markdown(_findings(), coverage=ledger)
    # Critical appears before High.
    assert md.index("RCE via ping") < md.index("SQLi in id")
    assert "Not assessed" in md
    assert "xss" in md


def test_markdown_empty() -> None:
    assert "No findings recorded" in to_markdown([])


def test_json_export_roundtrips() -> None:
    data = json.loads(to_json(_findings()))
    assert len(data) == 2
    assert {d["vuln_class"] for d in data} == {"sqli", "cmdi"}
    assert all("poc" in d and "cvss_nominal" in d for d in data)


def test_sarif_shape() -> None:
    sarif = to_sarif(_findings())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 2
    assert sarif["runs"][0]["results"][1]["level"] in {"error", "warning", "note"}
