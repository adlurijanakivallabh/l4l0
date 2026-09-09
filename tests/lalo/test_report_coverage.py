"""Tests for machine-observed coverage: which known vuln classes were never filed."""

from __future__ import annotations

from pathlib import Path

from lalo.agent.tools import ToolRegistry
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import NodeKind, ReachabilityGraph
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


def test_a_vuln_class_with_only_a_verified_safe_node_is_assessed_and_clean() -> None:
    graph = ReachabilityGraph()
    graph.add_node(
        "safe-1",
        NodeKind.VERIFIED_SAFE,
        vuln_class="sql-injection",
        target="https://x.example.com/",
        param=None,
        defense_mechanism="parameterized query, source-confirmed",
    )
    summary = build_coverage_summary(_SKILLS, records=[], graph=graph)
    assert "sql-injection" in summary.verified_safe
    assert "sql-injection" not in summary.not_assessed
    assert "xss" in summary.not_assessed
    assert "parameterized" in summary.safe_reasons["sql-injection"]


def test_a_class_with_both_a_finding_and_a_verified_safe_node_stays_assessed_not_safe() -> None:
    """A FINDING always wins - a class isn't "confirmed clean" if a real
    finding also exists for it (e.g. a different param on the same class)."""
    graph = ReachabilityGraph()
    graph.add_node(
        "safe-1",
        NodeKind.VERIFIED_SAFE,
        vuln_class="sql-injection",
        target="https://x.example.com/other",
        param=None,
        defense_mechanism="parameterized",
    )
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
    summary = build_coverage_summary(_SKILLS, records, graph=graph)
    assert "sql-injection" in summary.assessed
    assert "sql-injection" not in summary.verified_safe


def test_build_coverage_summary_with_no_graph_behaves_exactly_as_before() -> None:
    summary = build_coverage_summary(_SKILLS, records=[])
    assert summary.verified_safe == []
    assert summary.safe_reasons == {}
    assert summary.not_assessed == ["sql-injection", "xss"]
