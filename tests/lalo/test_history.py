"""Tests for cross-run finding diffing by dedup_key."""

from __future__ import annotations

from lalo.findings.confidence import ConfidenceScore
from lalo.report.collect import FindingRecord
from lalo.report.history import diff_findings


def _finding(dedup_key: str) -> FindingRecord:
    return FindingRecord(
        finding_id=f"finding-{dedup_key}",
        title="A finding",
        description="desc",
        remediation="fix it",
        vuln_class="sql-injection",
        target="https://x.example.com/search",
        param=None,
        evidence=["real captured proof"],
        evidence_excerpt="real captured proof",
        evidence_grounded=True,
        counterevidence="none found",
        severity_change_conditions="would change if X",
        cvss_score=7.5,
        cvss_severity="high",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        confidence=ConfidenceScore(score=80, breakdown={}),
        reproduced=True,
        identities_confirmed=[],
        dedup_key=dedup_key,
    )


def test_diff_findings_buckets_new_resolved_and_persisting() -> None:
    shared = _finding(dedup_key="k1")
    only_previous = _finding(dedup_key="k2")
    only_current = _finding(dedup_key="k3")
    diff = diff_findings(previous=[shared, only_previous], current=[shared, only_current])
    assert diff.new == [only_current]
    assert diff.resolved == [only_previous]
    assert diff.persisting == [(shared, shared)]


def test_diff_findings_with_no_previous_run_treats_everything_as_new() -> None:
    current = _finding(dedup_key="k1")
    diff = diff_findings(previous=[], current=[current])
    assert diff.new == [current]
    assert diff.resolved == []
    assert diff.persisting == []


def test_diff_findings_with_no_current_run_treats_everything_as_resolved() -> None:
    previous = _finding(dedup_key="k1")
    diff = diff_findings(previous=[previous], current=[])
    assert diff.new == []
    assert diff.resolved == [previous]
    assert diff.persisting == []


def test_diff_findings_ignores_records_with_an_unset_dedup_key() -> None:
    previous = _finding(dedup_key="")
    current = _finding(dedup_key="")
    diff = diff_findings(previous=[previous], current=[current])
    assert diff.new == []
    assert diff.resolved == []
    assert diff.persisting == []
