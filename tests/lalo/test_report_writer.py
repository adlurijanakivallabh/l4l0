"""Tests for tying the report together and byte-verified finalization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import lalo.report.writer as writer_module
from lalo.agent.tools import ToolRegistry
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import NodeKind, ReachabilityGraph
from lalo.orchestrator.budget import RunStatus
from lalo.report.collect import ReportUsage
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
            "remediation": "Apply input validation and least-privilege fixes.",
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
            "remediation": "Apply input validation and least-privilege fixes.",
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
            "remediation": "Apply input validation and least-privilege fixes.",
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


def test_write_report_threads_the_scan_status_into_every_format(tmp_path: Path) -> None:
    graph, _ = _graph_with_finding()
    paths = write_report(tmp_path, graph, _SKILLS, status=RunStatus.COMPLETED)

    doc = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert doc["status"] == "completed"
    assert "**Scan Status:** completed" in paths["markdown"].read_text(encoding="utf-8")

    sarif = json.loads(paths["sarif"].read_text(encoding="utf-8"))
    assert sarif["runs"][0]["invocations"] == [{"executionSuccessful": True}]
    assert sarif["runs"][0]["automationDetails"] == {"id": tmp_path.name}


@pytest.mark.parametrize("status", [RunStatus.BUDGET_EXHAUSTED, RunStatus.UNVERIFIED_STOP])
def test_write_report_a_cut_off_run_reports_an_unsuccessful_sarif_execution(
    tmp_path: Path, status: RunStatus
) -> None:
    """A budget-exhausted or unverified-stop run genuinely stopped before it
    finished - a CI consumer reading executionSuccessful needs to know these
    results may only be a fraction of what a completed scan would report,
    same as an outright crash."""
    graph, _ = _graph_with_finding()
    paths = write_report(tmp_path, graph, _SKILLS, status=status)
    sarif = json.loads(paths["sarif"].read_text(encoding="utf-8"))
    assert sarif["runs"][0]["invocations"] == [{"executionSuccessful": False}]


def test_write_report_a_run_status_of_error_reports_an_unsuccessful_sarif_execution(
    tmp_path: Path,
) -> None:
    graph, _ = _graph_with_finding()
    paths = write_report(tmp_path, graph, _SKILLS, status=RunStatus.ERROR)
    sarif = json.loads(paths["sarif"].read_text(encoding="utf-8"))
    assert sarif["runs"][0]["invocations"] == [{"executionSuccessful": False}]


def test_write_report_includes_an_executive_summary_in_every_format(tmp_path: Path) -> None:
    graph, _ = _graph_with_finding()
    paths = write_report(tmp_path, graph, _SKILLS)

    doc = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert doc["executive_summary"] == {
        "total_findings": 1,
        "by_severity": {"high": 1},
        "by_vuln_class": {"sql-injection": 1},
        "highest_severity": "high",
    }
    assert "## Executive Summary" in paths["markdown"].read_text(encoding="utf-8")


def test_write_report_threads_usage_into_json_and_markdown(tmp_path: Path) -> None:
    """Closes a real gap: token/cost totals previously reached the operator
    only as a transient GUI toast, never the delivered report."""
    graph, _ = _graph_with_finding()
    usage = ReportUsage(
        total_requests=2, total_input_tokens=500, total_output_tokens=150, total_cost_usd=0.005
    )
    paths = write_report(tmp_path, graph, _SKILLS, usage=usage)

    doc = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert doc["usage"] == {
        "total_requests": 2,
        "total_input_tokens": 500,
        "total_output_tokens": 150,
        "total_cost_usd": 0.005,
    }
    assert "**LLM Usage:**" in paths["markdown"].read_text(encoding="utf-8")


def test_write_report_with_no_usage_omits_it_from_json(tmp_path: Path) -> None:
    graph, _ = _graph_with_finding()
    paths = write_report(tmp_path, graph, _SKILLS)
    doc = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert doc["usage"] is None


def test_write_report_with_no_status_omits_it_from_json_and_markdown(tmp_path: Path) -> None:
    graph, _ = _graph_with_finding()
    paths = write_report(tmp_path, graph, _SKILLS)
    doc = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert doc["status"] is None
    assert "Scan Status" not in paths["markdown"].read_text(encoding="utf-8")


def test_write_report_creates_missing_run_directory(tmp_path: Path) -> None:
    graph, _ = _graph_with_finding()
    nested = tmp_path / "runs" / "scan-1"
    write_report(nested, graph, _SKILLS)
    assert (nested / MARKDOWN_FILENAME).exists()


# --- PDF/DOCX are secondary re-renders: a renderer bug must never cost the
# operator the canonical markdown/json/sarif they already have -----------


def test_write_report_a_pdf_renderer_failure_still_delivers_the_canonical_formats(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _broken_pdf(_html: str) -> bytes:
        msg = "WeasyPrint blew up"
        raise RuntimeError(msg)

    monkeypatch.setattr(writer_module, "render_report_pdf", _broken_pdf)
    graph, _ = _graph_with_finding()
    paths = write_report(tmp_path, graph, _SKILLS, generated_at="2026-01-01")

    assert "pdf" not in paths
    assert paths["markdown"].exists()
    assert paths["json"].exists()
    assert paths["sarif"].exists()
    assert paths["docx"].exists()


def test_write_report_a_docx_renderer_failure_still_delivers_the_canonical_formats(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _broken_docx(_html: str) -> bytes:
        msg = "html2docx blew up"
        raise RuntimeError(msg)

    monkeypatch.setattr(writer_module, "render_report_docx", _broken_docx)
    graph, _ = _graph_with_finding()
    paths = write_report(tmp_path, graph, _SKILLS, generated_at="2026-01-01")

    assert "docx" not in paths
    assert paths["markdown"].exists()
    assert paths["json"].exists()
    assert paths["sarif"].exists()
    assert paths["pdf"].exists()


def test_write_report_includes_a_populated_attack_chains_section_end_to_end(
    tmp_path: Path,
) -> None:
    graph = ReachabilityGraph()
    registry = ToolRegistry([build_record_finding_tool(graph)])
    registry.dispatch(
        "record_finding",
        {
            "title": "IDOR in /api/orders",
            "description": "desc",
            "vuln_class": "idor",
            "target": "https://x.example.com/api/orders",
            "evidence": ["e"],
            "evidence_excerpt": "e",
            "counterevidence": "none",
            "severity_change_conditions": "x",
            "remediation": "Apply input validation and least-privilege fixes.",
            "cvss_breakdown": _VALID_CVSS,
        },
    )
    enabler_id = graph.nodes_of_kind(NodeKind.FINDING)[0]
    registry.dispatch(
        "record_finding",
        {
            "title": "Admin RCE",
            "description": "desc",
            "vuln_class": "rce",
            "target": "https://x.example.com/admin",
            "evidence": ["e"],
            "evidence_excerpt": "e",
            "counterevidence": "none",
            "severity_change_conditions": "x",
            "remediation": "Apply input validation and least-privilege fixes.",
            "cvss_breakdown": _VALID_CVSS,
            "enabled_by_finding_id": enabler_id,
        },
    )
    enabled_id = next(fid for fid in graph.nodes_of_kind(NodeKind.FINDING) if fid != enabler_id)

    paths = write_report(tmp_path, graph, _SKILLS)

    doc = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert doc["chains"] == [
        {
            "finding_ids": [enabler_id, enabled_id],
            "titles": ["IDOR in /api/orders", "Admin RCE"],
        }
    ]

    markdown = paths["markdown"].read_text(encoding="utf-8")
    assert "## Attack Chains" in markdown
    assert "IDOR in /api/orders → Admin RCE" in markdown


def test_write_report_a_markdown_failure_still_propagates_uncaught(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The canonical formats are NOT given the same soft-failure treatment as
    PDF/DOCX - a bug rendering the record of truth itself must stay terminal,
    not silently produce a partial report."""

    def _broken_md(*_args: object, **_kwargs: object) -> str:
        msg = "markdown renderer blew up"
        raise RuntimeError(msg)

    monkeypatch.setattr(writer_module, "render_report_md", _broken_md)
    graph, _ = _graph_with_finding()
    with pytest.raises(RuntimeError, match="markdown renderer blew up"):
        write_report(tmp_path, graph, _SKILLS)
