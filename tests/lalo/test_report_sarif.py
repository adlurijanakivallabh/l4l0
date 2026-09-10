"""Tests for SARIF 2.1.0 export."""

from __future__ import annotations

from dataclasses import replace

from lalo.agent.tools import ToolRegistry
from lalo.findings.dedup import dedup_key
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import ReachabilityGraph
from lalo.report.collect import FindingRecord, collect_findings
from lalo.report.sarif import (
    _OWASP_API_TAXONOMY_NAME,  # noqa: SLF001 - same access pattern test_report_pdf.py uses for pdf_module._deny_all_external_resources
    SARIF_SCHEMA,
    SARIF_VERSION,
    render_sarif,
)

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


def _record(**overrides: object) -> FindingRecord:
    """Build a minimal FindingRecord for render_sarif tests - a thin helper
    that creates a graph, files a finding with the given overrides, and
    returns the record. Used for direct render_sarif testing without the full
    finding-dispatch flow."""
    graph = ReachabilityGraph()
    _file(graph, **overrides)
    return _records(graph)[0]


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


def test_render_sarif_drops_traversal_source_location_but_keeps_sibling_result_intact() -> None:
    graph = ReachabilityGraph()
    _file(graph, source_location="app/routes.py:42")
    _file(graph, target="https://x.example.com/other", source_location="../../etc/hostname:5")
    doc = render_sarif(_records(graph))
    good_locations, bad_locations = (r["locations"] for r in doc["runs"][0]["results"])
    physical = next(loc["physicalLocation"] for loc in good_locations if "physicalLocation" in loc)
    assert physical["artifactLocation"]["uri"] == "app/routes.py"
    assert physical["region"]["startLine"] == 42
    assert all("physicalLocation" not in loc for loc in bad_locations)


def test_render_sarif_rule_includes_an_owasp_relationship_when_mapped() -> None:
    graph = ReachabilityGraph()
    _file(graph, vuln_class="idor")
    doc = render_sarif(_records(graph))
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    owasp_rel = next(
        r
        for r in rule["relationships"]
        if r["target"]["toolComponent"]["name"] == _OWASP_API_TAXONOMY_NAME
    )
    assert owasp_rel == {
        "target": {"id": "API1:2023", "toolComponent": {"name": _OWASP_API_TAXONOMY_NAME}},
        "kinds": ["relevant"],
    }


def test_render_sarif_rule_keeps_the_cwe_relationship_alongside_owasp() -> None:
    graph = ReachabilityGraph()
    _file(graph, vuln_class="idor")  # idor maps to both CWE-639 and API1:2023
    doc = render_sarif(_records(graph))
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    names = {r["target"]["toolComponent"]["name"] for r in rule["relationships"]}
    assert names == {"CWE", _OWASP_API_TAXONOMY_NAME}


def test_render_sarif_omits_owasp_relationship_when_unmapped() -> None:
    graph = ReachabilityGraph()
    _file(graph, vuln_class="sql-injection")  # has a CWE but no 2023 API category
    doc = render_sarif(_records(graph))
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    names = {r["target"]["toolComponent"]["name"] for r in rule["relationships"]}
    assert names == {"CWE"}


def test_render_sarif_declares_the_owasp_taxonomy_only_when_used() -> None:
    graph = ReachabilityGraph()
    _file(graph, vuln_class="sql-injection")  # never touches OWASP
    doc = render_sarif(_records(graph))
    assert "taxonomies" not in doc["runs"][0]


def test_render_sarif_declares_the_owasp_taxonomy_component_when_a_rule_uses_it() -> None:
    graph = ReachabilityGraph()
    _file(graph, vuln_class="idor")
    doc = render_sarif(_records(graph))
    taxonomies = doc["runs"][0]["taxonomies"]
    assert len(taxonomies) == 1
    assert taxonomies[0]["name"] == _OWASP_API_TAXONOMY_NAME
    assert {"id": "API1:2023", "name": "Broken Object Level Authorization"} in taxonomies[0]["taxa"]


def test_render_sarif_result_has_no_code_flows_key_for_a_single_string_source_location() -> None:
    """Zero behavior change for the existing, common case."""
    graph = ReachabilityGraph()
    _file(graph, source_location="app/routes.py:42")
    doc = render_sarif(_records(graph))
    assert "codeFlows" not in doc["runs"][0]["results"][0]


def test_render_sarif_result_emits_a_code_flow_for_a_multi_hop_source_location() -> None:
    graph = ReachabilityGraph()
    _file(graph)
    hops = [
        {"role": "source", "location": "app/routes.py:10"},
        {"role": "guard", "location": "app/auth.py:55"},
        {"role": "sink", "location": "app/db.py:88"},
    ]
    record = replace(_records(graph)[0], source_location=hops)
    doc = render_sarif([record])
    result = doc["runs"][0]["results"][0]

    thread_locations = result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [loc["location"]["message"]["text"] for loc in thread_locations] == [
        "source",
        "guard",
        "sink",
    ]
    first_physical = thread_locations[0]["location"]["physicalLocation"]
    assert first_physical["artifactLocation"]["uri"] == "app/routes.py"
    last_physical = thread_locations[-1]["location"]["physicalLocation"]
    assert last_physical["region"]["startLine"] == 88

    # the primary result location still gets a physicalLocation, pointing at
    # the last hop (the sink) - the same convention the single-string case
    # has always used for "the one point of interest"
    physical = next(
        loc["physicalLocation"] for loc in result["locations"] if "physicalLocation" in loc
    )
    assert physical["artifactLocation"]["uri"] == "app/db.py"


def test_render_sarif_result_drops_an_unparseable_hop_from_the_code_flow() -> None:
    graph = ReachabilityGraph()
    _file(graph)
    hops = [
        {"role": "source", "location": "app/routes.py:10"},
        {"role": "sink", "location": "app/db.py:not-a-line-number"},
    ]
    record = replace(_records(graph)[0], source_location=hops)
    doc = render_sarif([record])
    result = doc["runs"][0]["results"][0]
    # only one hop survived parsing - no flow worth showing
    assert "codeFlows" not in result


def test_render_sarif_includes_fixes_from_code_locations() -> None:
    record = _record(
        code_locations=[
            {"location": "app.py:42", "fix_before": "eval(x)", "fix_after": "ast.literal_eval(x)"}
        ]
    )
    doc = render_sarif([record])
    result = doc["runs"][0]["results"][0]
    assert "fixes" in result
    fix = result["fixes"][0]
    assert fix["artifactChanges"][0]["artifactLocation"]["uri"] == "app.py"
    assert fix["artifactChanges"][0]["replacements"][0]["insertedContent"]["text"] == (
        "ast.literal_eval(x)"
    )


def test_render_sarif_omits_fixes_key_when_no_code_locations() -> None:
    record = _record()
    doc = render_sarif([record])
    assert "fixes" not in doc["runs"][0]["results"][0]


def test_render_sarif_skips_an_unparseable_code_location() -> None:
    record = _record(code_locations=[{"location": "not-a-location", "fix_after": "x"}])
    doc = render_sarif([record])
    assert "fixes" not in doc["runs"][0]["results"][0]


def test_render_sarif_with_coverage_emits_a_not_applicable_result_for_verified_safe() -> None:
    from lalo.report.coverage import CoverageSummary

    coverage = CoverageSummary(
        assessed=["xss"],
        not_assessed=["ssrf"],
        verified_safe=["sql-injection"],
        safe_reasons={"sql-injection": "parameterized queries confirmed via source read"},
    )
    doc = render_sarif([], coverage=coverage)
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "sql-injection"
    assert results[0]["kind"] == "notApplicable"
    assert "parameterized queries" in results[0]["message"]["text"]


def test_render_sarif_with_coverage_never_emits_a_result_for_not_assessed() -> None:
    from lalo.report.coverage import CoverageSummary

    coverage = CoverageSummary(assessed=[], not_assessed=["ssrf"])
    doc = render_sarif([], coverage=coverage)
    assert doc["runs"][0]["results"] == []


def test_render_sarif_without_coverage_arg_is_unchanged() -> None:
    doc = render_sarif([])
    assert doc["runs"][0]["results"] == []
    assert "coverage" not in doc["runs"][0]
