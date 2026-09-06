"""Tests for machine-observed coverage: which known vuln classes were never filed."""

from __future__ import annotations

from pathlib import Path

from lalo.agent.tools import ToolRegistry
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import ReachabilityGraph
from lalo.report.collect import collect_findings
from lalo.report.coverage import build_coverage_summary
from lalo.skills.loader import Skill, SkillCategory

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

_SKILLS = [
    Skill(
        name="sql-injection",
        category=SkillCategory.VULNERABILITY,
        description="d",
        keywords=(),
        body="b",
        path=Path("sql-injection.md"),
    ),
    Skill(
        name="xss",
        category=SkillCategory.VULNERABILITY,
        description="d",
        keywords=(),
        body="b",
        path=Path("xss.md"),
    ),
    Skill(
        name="closure-discipline",
        category=SkillCategory.METHODOLOGY,
        description="d",
        keywords=(),
        body="b",
        path=Path("closure-discipline.md"),
    ),
]


def test_build_coverage_summary_with_no_findings_marks_every_class_not_assessed() -> None:
    summary = build_coverage_summary(_SKILLS, [])
    assert summary.assessed == []
    assert summary.not_assessed == ["sql-injection", "xss"]


def test_build_coverage_summary_ignores_methodology_skills() -> None:
    summary = build_coverage_summary(_SKILLS, [])
    assert "closure-discipline" not in summary.not_assessed
    assert "closure-discipline" not in summary.assessed


def test_build_coverage_summary_marks_a_filed_class_as_assessed() -> None:
    graph = ReachabilityGraph()
    ToolRegistry([build_record_finding_tool(graph)]).dispatch(
        "record_finding",
        {
            "title": "t",
            "description": "d",
            "vuln_class": "sql-injection",
            "target": "https://x.example.com/search",
            "evidence": ["e"],
            "evidence_excerpt": "e",
            "counterevidence": "none",
            "severity_change_conditions": "x",
            "remediation": "Apply input validation and least-privilege fixes.",
            "cvss_breakdown": _VALID_CVSS,
        },
    )
    records = collect_findings(graph)
    summary = build_coverage_summary(_SKILLS, records)
    assert summary.assessed == ["sql-injection"]
    assert summary.not_assessed == ["xss"]


def test_build_coverage_summary_matching_is_case_insensitive() -> None:
    graph = ReachabilityGraph()
    ToolRegistry([build_record_finding_tool(graph)]).dispatch(
        "record_finding",
        {
            "title": "t",
            "description": "d",
            "vuln_class": "SQL-Injection",
            "target": "https://x.example.com/search",
            "evidence": ["e"],
            "evidence_excerpt": "e",
            "counterevidence": "none",
            "severity_change_conditions": "x",
            "remediation": "Apply input validation and least-privilege fixes.",
            "cvss_breakdown": _VALID_CVSS,
        },
    )
    records = collect_findings(graph)
    summary = build_coverage_summary(_SKILLS, records)
    assert "sql-injection" in summary.assessed


def test_total_known_classes_counts_both_buckets() -> None:
    summary = build_coverage_summary(_SKILLS, [])
    assert summary.total_known_classes == 2
