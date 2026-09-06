"""Tests for scoring a benchmark case against a real graph of findings."""

from __future__ import annotations

from lalo.agent.tools import ToolRegistry
from lalo.eval.cases import BenchmarkCase, run_case
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import ReachabilityGraph

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


def _file(graph: ReachabilityGraph, vuln_class: str, target: str) -> None:
    ToolRegistry([build_record_finding_tool(graph)]).dispatch(
        "record_finding",
        {
            "title": "t",
            "description": "d",
            "vuln_class": vuln_class,
            "target": target,
            "evidence": ["e"],
            "evidence_excerpt": "e",
            "counterevidence": "none",
            "severity_change_conditions": "x",
            "remediation": "Apply input validation and least-privilege fixes.",
            "cvss_breakdown": _VALID_CVSS,
        },
    )


def test_run_case_finds_nothing_on_an_empty_graph() -> None:
    case = BenchmarkCase(name="t", description="d", ground_truth_classes=frozenset({"xss"}))
    result = run_case(case, ReachabilityGraph())
    assert result.found_classes == frozenset()
    assert result.confidence_by_class == {}


def test_run_case_matches_a_reported_class_case_insensitively() -> None:
    graph = ReachabilityGraph()
    _file(graph, "SQL-Injection", "https://x.example.com/a")
    case = BenchmarkCase(
        name="t", description="d", ground_truth_classes=frozenset({"sql-injection"})
    )
    result = run_case(case, graph)
    assert result.found_classes == frozenset({"sql-injection"})


def test_run_case_reports_a_class_not_in_ground_truth_too() -> None:
    graph = ReachabilityGraph()
    _file(graph, "xss", "https://x.example.com/a")
    case = BenchmarkCase(
        name="t", description="d", ground_truth_classes=frozenset({"sql-injection"})
    )
    result = run_case(case, graph)
    assert result.found_classes == frozenset({"xss"})


def test_run_case_keeps_the_highest_confidence_for_a_repeated_class() -> None:
    graph = ReachabilityGraph()
    _file(graph, "xss", "https://x.example.com/a")
    _file(graph, "xss", "https://x.example.com/b")
    case = BenchmarkCase(name="t", description="d", ground_truth_classes=frozenset({"xss"}))
    result = run_case(case, graph)
    assert result.confidence_by_class["xss"] > 0


def test_benchmark_case_normalizes_ground_truth_classes_to_lowercase() -> None:
    """run_case() already lowercases the found side - a ground truth entry
    that isn't already lowercase must not cause a real match to be missed."""
    case = BenchmarkCase(
        name="t", description="d", ground_truth_classes=frozenset({"XSS", " Sql-Injection "})
    )
    assert case.ground_truth_classes == frozenset({"xss", "sql-injection"})


def test_case_result_is_hashable_despite_its_dict_field() -> None:
    """CaseResult is frozen but holds a plain dict (confidence_by_class),
    which is unhashable - the default tuple-based __hash__ frozen=True would
    otherwise generate must not be used, or hashing an instance raises."""
    graph = ReachabilityGraph()
    case = BenchmarkCase(name="t", description="d", ground_truth_classes=frozenset())
    result = run_case(case, graph)
    assert hash(result) is not None
    assert result in {result}
