"""Tests for report rendering, PoC, CVSS, and exporters."""

from __future__ import annotations

import json

from lalo.detectors.ledger import CoverageLedger
from lalo.models import Evidence, EvidenceKind, Finding, Severity
from lalo.report import curl_poc, nominal_cvss, to_json, to_markdown, to_sarif


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
