"""Tests for SARIF 2.1.0 export."""

from __future__ import annotations

from dataclasses import replace

from lalo.agent.tools import ToolRegistry
from lalo.findings.dedup import dedup_key
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import ReachabilityGraph
from lalo.report.collect import FindingRecord, collect_findings
from lalo.report.sarif import SARIF_SCHEMA, SARIF_VERSION, render_sarif

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


def _file(graph: ReachabilityGraph, **overrides: object) -> None:
    args: dict[str, object] = {
        "title": "SQLi in /search",
        "description": "desc",
        "vuln_class": "sql-injection",
        "target": "https://x.example.com/search",
        "param": "q",
        "evidence": ["e"],
        "evidence_excerpt": "e",
        "counterevidence": "none",
        "severity_change_conditions": "x",
        "remediation": "Apply input validation and least-privilege fixes.",
        "cvss_breakdown": _VALID_CVSS,
    }
    args.update(overrides)
    ToolRegistry([build_record_finding_tool(graph)]).dispatch("record_finding", args)


def _records(graph: ReachabilityGraph) -> list[FindingRecord]:
    return collect_findings(graph)


def test_render_sarif_document_shape() -> None:
    doc = render_sarif([])
    assert doc["$schema"] == SARIF_SCHEMA
    assert doc["version"] == SARIF_VERSION
    assert doc["runs"][0]["tool"]["driver"]["name"] == "L4L0"
    assert doc["runs"][0]["results"] == []


def test_render_sarif_defaults_to_a_successful_execution_with_no_automation_id() -> None:
    doc = render_sarif([])
    assert doc["runs"][0]["invocations"] == [{"executionSuccessful": True}]
    assert "automationDetails" not in doc["runs"][0]


def test_render_sarif_reports_an_unsuccessful_execution() -> None:
    doc = render_sarif([], execution_successful=False)
    assert doc["runs"][0]["invocations"] == [{"executionSuccessful": False}]


def test_render_sarif_includes_the_automation_id_when_given() -> None:
    doc = render_sarif([], automation_id="scan-42")
    assert doc["runs"][0]["automationDetails"] == {"id": "scan-42"}


def test_render_sarif_one_rule_and_result_per_finding() -> None:
    graph = ReachabilityGraph()
    _file(graph)
    doc = render_sarif(_records(graph))
    run = doc["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 1
    assert run["tool"]["driver"]["rules"][0]["id"] == "sql-injection"
    assert run["results"][0]["ruleId"] == "sql-injection"


def test_render_sarif_deduplicates_rules_for_the_same_vuln_class() -> None:
    graph = ReachabilityGraph()
    _file(graph, target="https://x.example.com/a")
    _file(graph, target="https://x.example.com/b")
    doc = render_sarif(_records(graph))
    run = doc["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2


def test_render_sarif_result_carries_the_logical_location() -> None:
    graph = ReachabilityGraph()
    _file(graph)
    doc = render_sarif(_records(graph))
    result = doc["runs"][0]["results"][0]
    logical = result["locations"][0]["logicalLocations"][0]
    assert logical["fullyQualifiedName"] == "https://x.example.com/search#q"


def test_render_sarif_result_includes_a_richer_markdown_message() -> None:
    graph = ReachabilityGraph()
    _file(graph, description="the query param is concatenated raw into SQL")
    doc = render_sarif(_records(graph))
    result = doc["runs"][0]["results"][0]
    markdown = result["message"]["markdown"]
    assert "## SQLi in /search" in markdown
    assert "the query param is concatenated raw into SQL" in markdown
    assert "**CVSS:**" in markdown
    assert "**Confidence:**" in markdown
    assert "### Remediation" in markdown
    assert "Apply input validation and least-privilege fixes." in markdown
    # the plain text message is unchanged - markdown is additive, not a replacement
    assert result["message"]["text"].startswith("SQLi in /search")


def test_render_sarif_markdown_omits_remediation_section_when_none_stated() -> None:
    graph = ReachabilityGraph()
    _file(graph)
    record = replace(_records(graph)[0], remediation="")
    doc = render_sarif([record])
    markdown = doc["runs"][0]["results"][0]["message"]["markdown"]
    assert "Remediation" not in markdown


def test_render_sarif_fingerprint_matches_the_real_dedup_key() -> None:
    graph = ReachabilityGraph()
    _file(graph)
    doc = render_sarif(_records(graph))
    result = doc["runs"][0]["results"][0]
    expected = dedup_key("sql-injection", "https://x.example.com/search", "q")
    assert result["partialFingerprints"]["lalo/dedupKey"] == expected


def test_render_sarif_severity_collapses_to_three_levels() -> None:
    graph = ReachabilityGraph()
    _file(graph)  # this breakdown computes to "high"
    doc = render_sarif(_records(graph))
    assert doc["runs"][0]["results"][0]["level"] == "error"


def test_render_sarif_security_severity_uses_the_real_cvss_score() -> None:
    graph = ReachabilityGraph()
    _file(graph)
    doc = render_sarif(_records(graph))
    result = doc["runs"][0]["results"][0]
    assert result["properties"]["security-severity"] == "7.5"


def test_render_sarif_rule_includes_cwe_relationship_when_mapped() -> None:
    graph = ReachabilityGraph()
    _file(graph)  # vuln_class="sql-injection" -> CWE-89
    doc = render_sarif(_records(graph))
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["relationships"] == [
        {"target": {"id": "CWE-89", "toolComponent": {"name": "CWE"}}, "kinds": ["relevant"]}
    ]


def test_render_sarif_rule_omits_relationships_when_unmapped() -> None:
    graph = ReachabilityGraph()
    _file(graph, vuln_class="not-a-real-class")
    doc = render_sarif(_records(graph))
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert "relationships" not in rule


def test_render_sarif_security_severity_preserves_a_real_zero_score() -> None:
    """A genuine all-'N'-impact CVSS breakdown legitimately scores 0.0 - this
    must not be confused with "no score supplied" and replaced by an
    arbitrary fallback value."""
    zero_impact_cvss = {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "N",
        "scope": "U",
        "confidentiality": "N",
        "integrity": "N",
        "availability": "N",
    }
    graph = ReachabilityGraph()
    _file(graph, cvss_breakdown=zero_impact_cvss)
    doc = render_sarif(_records(graph))
    result = doc["runs"][0]["results"][0]
    assert result["properties"]["security-severity"] == "0.0"


def test_render_sarif_result_includes_physical_location_when_source_location_present() -> None:
    graph = ReachabilityGraph()
    _file(graph, source_location="app/routes.py:42")
    doc = render_sarif(_records(graph))
    locations = doc["runs"][0]["results"][0]["locations"]
    physical = next(loc["physicalLocation"] for loc in locations if "physicalLocation" in loc)
    assert physical["artifactLocation"]["uri"] == "app/routes.py"
    assert physical["region"]["startLine"] == 42


def test_render_sarif_result_has_no_physical_location_when_source_location_absent() -> None:
    graph = ReachabilityGraph()
    _file(graph)
    doc = render_sarif(_records(graph))
    locations = doc["runs"][0]["results"][0]["locations"]
    assert all("physicalLocation" not in loc for loc in locations)


def test_render_sarif_result_degrades_gracefully_on_a_malformed_source_location() -> None:
    graph = ReachabilityGraph()
    _file(graph, source_location="app/routes.py:not-a-line-number")
    doc = render_sarif(_records(graph))
    locations = doc["runs"][0]["results"][0]["locations"]
    assert all("physicalLocation" not in loc for loc in locations)
