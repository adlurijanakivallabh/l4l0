"""Tests for CSV export of findings."""

from __future__ import annotations

import csv
import io

from lalo.agent.tools import ToolRegistry
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import ReachabilityGraph
from lalo.report.collect import FindingRecord, collect_findings
from lalo.report.csv_export import build_csv, csv_safe

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


def _record(**overrides: object) -> FindingRecord:
    graph = ReachabilityGraph()
    args: dict[str, object] = {
        "title": "SQLi in /search",
        "description": "The q parameter is concatenated raw.",
        "vuln_class": "sql-injection",
        "target": "https://x.example.com/search",
        "param": "q",
        "evidence": ["HTTP/1.1 500\nsyntax error"],
        "evidence_excerpt": "syntax error",
        "counterevidence": "No WAF observed.",
        "severity_change_conditions": "Confirmed exfil would raise severity.",
        "remediation": "Apply input validation and least-privilege fixes.",
        "cvss_breakdown": _VALID_CVSS,
    }
    args.update(overrides)
    ToolRegistry([build_record_finding_tool(graph)]).dispatch("record_finding", args)
    return collect_findings(graph)[0]


def test_csv_safe_prefixes_a_leading_formula_character() -> None:
    assert csv_safe("=cmd|' /C calc'!A1").startswith("'=")


def test_csv_safe_prefixes_every_dangerous_leading_character() -> None:
    for prefix in ("=", "+", "-", "@", "\t", "\r"):
        value = f"{prefix}dangerous"
        assert csv_safe(value) == f"'{value}"


def test_csv_safe_leaves_ordinary_text_unchanged() -> None:
    assert csv_safe("ordinary title") == "ordinary title"


def test_csv_safe_leaves_empty_string_unchanged() -> None:
    assert csv_safe("") == ""


def test_build_csv_includes_a_header_and_one_row_per_finding() -> None:
    csv_text = build_csv([_record()])
    rows = csv_text.strip().splitlines()
    assert len(rows) == 2  # header + one data row


def test_build_csv_with_no_findings_is_header_only() -> None:
    csv_text = build_csv([])
    rows = csv_text.strip().splitlines()
    assert len(rows) == 1


def test_build_csv_header_names_the_real_fields() -> None:
    csv_text = build_csv([])
    header = csv_text.strip().splitlines()[0]
    for column in ("finding_id", "title", "vuln_class", "target", "severity", "remediation"):
        assert column in header


def test_build_csv_row_contains_the_finding_data() -> None:
    record = _record()
    csv_text = build_csv([record])
    rows = list(csv.reader(io.StringIO(csv_text)))
    header, row = rows[0], rows[1]
    data = dict(zip(header, row, strict=True))
    assert data["finding_id"] == record.finding_id
    assert data["title"] == "SQLi in /search"
    assert data["vuln_class"] == "sql-injection"
    assert data["target"] == "https://x.example.com/search"
    assert data["param"] == "q"
    assert data["remediation"] == "Apply input validation and least-privilege fixes."


def test_build_csv_guards_a_formula_injection_attempt_in_a_finding_field() -> None:
    """title/remediation are attacker-influenced text (an LLM-authored
    finding title, target-observed content) - a cell that would otherwise
    open with a formula character must come back apostrophe-prefixed even
    once it has gone through the real record_finding -> collect_findings
    pipeline, not just the bare csv_safe() unit."""
    record = _record(title='=HYPERLINK("http://evil.example")')
    csv_text = build_csv([record])
    rows = list(csv.reader(io.StringIO(csv_text)))
    header, row = rows[0], rows[1]
    data = dict(zip(header, row, strict=True))
    assert data["title"] == '\'=HYPERLINK("http://evil.example")'


def test_build_csv_omits_the_param_column_placeholder_when_none() -> None:
    record = _record(param=None)
    csv_text = build_csv([record])
    rows = list(csv.reader(io.StringIO(csv_text)))
    header, row = rows[0], rows[1]
    data = dict(zip(header, row, strict=True))
    assert data["param"] == ""
