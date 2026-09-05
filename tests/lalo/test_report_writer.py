"""Tests for tying the report together and byte-verified finalization."""

from __future__ import annotations

import json
from pathlib import Path

from lalo.agent.tools import ToolRegistry
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import NodeKind, ReachabilityGraph
from lalo.report.overrides import SeverityOverride
from lalo.report.writer import (
    DOCX_FILENAME,
    JSON_FILENAME,
    MARKDOWN_FILENAME,
    PDF_FILENAME,
    SARIF_FILENAME,
    write_report,
)
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

_LOW_CVSS = {
    "attack_vector": "L",
    "attack_complexity": "H",
    "privileges_required": "H",
    "user_interaction": "R",
    "scope": "U",
    "confidentiality": "L",
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
]


def _graph_with_finding() -> tuple[ReachabilityGraph, str]:
    graph = ReachabilityGraph()
    ToolRegistry([build_record_finding_tool(graph)]).dispatch(
        "record_finding",
        {
            "title": "SQLi in /search",
            "description": "desc",
            "vuln_class": "sql-injection",
            "target": "https://x.example.com/search",
            "evidence": ["e"],
            "evidence_excerpt": "e",
            "counterevidence": "none",
            "severity_change_conditions": "x",
            "cvss_breakdown": _VALID_CVSS,
        },
    )
    finding_id = graph.nodes_of_kind(NodeKind.FINDING)[0]
    return graph, finding_id


def test_write_report_writes_all_five_formats(tmp_path: Path) -> None:
    graph, _ = _graph_with_finding()
    paths = write_report(tmp_path, graph, _SKILLS, generated_at="2026-01-01")
    assert paths["markdown"] == tmp_path / MARKDOWN_FILENAME
    assert paths["json"] == tmp_path / JSON_FILENAME
    assert paths["sarif"] == tmp_path / SARIF_FILENAME
    assert paths["pdf"] == tmp_path / PDF_FILENAME
    assert paths["docx"] == tmp_path / DOCX_FILENAME
    for path in paths.values():
        assert path.exists()
    assert paths["pdf"].read_bytes().startswith(b"%PDF-")
    assert paths["docx"].read_bytes().startswith(b"PK")


def test_write_report_markdown_contains_the_finding(tmp_path: Path) -> None:
    graph, _ = _graph_with_finding()
    paths = write_report(tmp_path, graph, _SKILLS)
    text = paths["markdown"].read_text(encoding="utf-8")
    assert "SQLi in /search" in text


def test_write_report_json_round_trips_the_finding_count(tmp_path: Path) -> None:
    graph, _ = _graph_with_finding()
    paths = write_report(tmp_path, graph, _SKILLS)
    doc = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert len(doc["findings"]) == 1
    assert doc["findings"][0]["vuln_class"] == "sql-injection"
    assert doc["coverage"]["assessed"] == ["sql-injection"]


def test_write_report_sarif_is_valid_json_with_one_result(tmp_path: Path) -> None:
    graph, _ = _graph_with_finding()
    paths = write_report(tmp_path, graph, _SKILLS)
    doc = json.loads(paths["sarif"].read_text(encoding="utf-8"))
    assert len(doc["runs"][0]["results"]) == 1


def test_write_report_applies_a_severity_override_in_the_rendered_output(tmp_path: Path) -> None:
    graph, finding_id = _graph_with_finding()
    paths = write_report(
        tmp_path,
        graph,
        _SKILLS,
        overrides=[SeverityOverride(finding_id, "critical", "chains to RCE", "alice")],
    )
    text = paths["markdown"].read_text(encoding="utf-8")
    assert "CRITICAL" in text
    assert "chains to RCE" in text
    # the underlying graph node itself is untouched by the override
    assert graph.node(finding_id)["cvss_severity"] != "critical"


def test_write_report_resorts_by_the_overridden_severity_not_the_original(
    tmp_path: Path,
) -> None:
    """A finding overridden UP to critical must sort ahead of an unrelated
    genuinely-high finding - sorting before applying overrides would rank
    every finding by its pre-override severity instead."""
    graph = ReachabilityGraph()
    registry = ToolRegistry([build_record_finding_tool(graph)])
    registry.dispatch(
        "record_finding",
        {
            "title": "low severity finding",
            "description": "d",
            "vuln_class": "xss",
            "target": "https://x.example.com/low",
            "evidence": ["e"],
            "evidence_excerpt": "e",
            "counterevidence": "none",
            "severity_change_conditions": "x",
            "cvss_breakdown": _LOW_CVSS,
        },
    )
    low_id = graph.nodes_of_kind(NodeKind.FINDING)[0]
    registry.dispatch(
        "record_finding",
        {
            "title": "genuinely high severity finding",
            "description": "d",
            "vuln_class": "sql-injection",
            "target": "https://x.example.com/high",
            "evidence": ["e"],
            "evidence_excerpt": "e",
            "counterevidence": "none",
            "severity_change_conditions": "x",
            "cvss_breakdown": _VALID_CVSS,
        },
    )

    paths = write_report(
        tmp_path,
        graph,
        _SKILLS,
        overrides=[SeverityOverride(low_id, "critical", "chains to RCE", "alice")],
    )
    doc = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert doc["findings"][0]["title"] == "low severity finding"
    assert doc["findings"][0]["display_severity"] == "critical"
    assert doc["findings"][1]["title"] == "genuinely high severity finding"


def test_write_report_survives_a_leftover_crashed_temp_file(tmp_path: Path) -> None:
    graph, _ = _graph_with_finding()
    write_report(tmp_path, graph, _SKILLS)
    good_markdown = (tmp_path / MARKDOWN_FILENAME).read_text(encoding="utf-8")

    # simulate a crash mid-write on a later run: an orphaned temp file sits
    # next to the real file, but the real file was never touched
    crashed_tmp = tmp_path / f".{MARKDOWN_FILENAME}.tmp-deadbeef"
    crashed_tmp.write_bytes(b"garbage from an interrupted write")

    assert (tmp_path / MARKDOWN_FILENAME).read_text(encoding="utf-8") == good_markdown

    # a fresh write afterward still succeeds and produces a complete report
    write_report(tmp_path, graph, _SKILLS)
    assert (tmp_path / MARKDOWN_FILENAME).read_text(encoding="utf-8") == good_markdown


def test_write_report_creates_missing_run_directory(tmp_path: Path) -> None:
    graph, _ = _graph_with_finding()
    nested = tmp_path / "runs" / "scan-1"
    write_report(nested, graph, _SKILLS)
    assert (nested / MARKDOWN_FILENAME).exists()
