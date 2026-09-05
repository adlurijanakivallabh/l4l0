"""Tests for the `record_finding` agent tool."""

from __future__ import annotations

from lalo.agent.tools import ToolRegistry
from lalo.core.redaction import shared_redactor
from lalo.findings.tool import build_record_finding_tool
from lalo.graph.model import EdgeKind, NodeKind, ReachabilityGraph

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


def _args(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "title": "SQLi in /search",
        "description": "The q parameter is concatenated into a raw query.",
        "vuln_class": "sql-injection",
        "target": "https://x.example.com/search",
        "evidence": ["HTTP/1.1 500 Internal Server Error\nsyntax error near 'OR'"],
        "evidence_excerpt": "syntax error near 'OR'",
        "counterevidence": "No WAF observed; error is a raw DB driver message.",
        "severity_change_conditions": "Confirming data exfiltration would raise severity.",
        "cvss_breakdown": _VALID_CVSS,
    }
    base.update(overrides)
    return base


def _registry(graph: ReachabilityGraph) -> ToolRegistry:
    return ToolRegistry([build_record_finding_tool(graph)])


def test_record_finding_lands_immediately_with_valid_fields() -> None:
    graph = ReachabilityGraph()
    result = _registry(graph).dispatch("record_finding", _args())
    assert result.ok is True
    assert "recorded finding-" in result.observation
    finding_ids = graph.nodes_of_kind(NodeKind.FINDING)
    assert len(finding_ids) == 1
    node = graph.node(finding_ids[0])
    assert node["vuln_class"] == "sql-injection"
    assert node["evidence_grounded"] is True
    assert node["cvss_severity"] == "high"


def test_record_finding_writes_an_evidence_node_supporting_the_finding() -> None:
    graph = ReachabilityGraph()
    _registry(graph).dispatch("record_finding", _args())
    finding_id = graph.nodes_of_kind(NodeKind.FINDING)[0]
    evidence_ids = graph.nodes_of_kind(NodeKind.EVIDENCE)
    assert len(evidence_ids) == 1
    chains = graph.find_chains(evidence_ids[0], finding_id, edge_kind=EdgeKind.SUPPORTS)
    assert len(chains) == 1


def test_record_finding_rejects_missing_required_fields_without_touching_the_graph() -> None:
    graph = ReachabilityGraph()
    result = _registry(graph).dispatch("record_finding", _args(title=""))
    assert result.ok is False
    assert "title" in result.observation
    assert graph.nodes_of_kind(NodeKind.FINDING) == []


def test_record_finding_lands_even_when_evidence_excerpt_is_not_grounded() -> None:
    graph = ReachabilityGraph()
    result = _registry(graph).dispatch(
        "record_finding",
        _args(evidence_excerpt="this text was never actually captured anywhere"),
    )
    assert result.ok is True
    assert "WARNING" in result.observation
    node = graph.node(graph.nodes_of_kind(NodeKind.FINDING)[0])
    assert node["evidence_grounded"] is False


def test_record_finding_merges_a_repeat_into_the_same_class_target_param() -> None:
    graph = ReachabilityGraph()
    registry = _registry(graph)
    registry.dispatch("record_finding", _args())
    second = registry.dispatch(
        "record_finding",
        _args(evidence=["a second, independent capture: syntax error near 'OR'"]),
    )
    assert second.ok is True
    assert "merged into existing finding" in second.observation
    finding_ids = graph.nodes_of_kind(NodeKind.FINDING)
    assert len(finding_ids) == 1
    node = graph.node(finding_ids[0])
    assert len(node["evidence"]) == 2


def test_record_finding_does_not_merge_a_different_target() -> None:
    graph = ReachabilityGraph()
    registry = _registry(graph)
    registry.dispatch("record_finding", _args())
    registry.dispatch("record_finding", _args(target="https://x.example.com/other"))
    assert len(graph.nodes_of_kind(NodeKind.FINDING)) == 2


def test_record_finding_redacts_a_registered_secret_before_it_reaches_the_graph() -> None:
    shared_redactor().register_secret("unique-marker-finding-test-4f2a1")
    graph = ReachabilityGraph()
    _registry(graph).dispatch(
        "record_finding",
        _args(
            description="Leaked key: unique-marker-finding-test-4f2a1",
            evidence=["response body contains unique-marker-finding-test-4f2a1"],
            evidence_excerpt="unique-marker-finding-test-4f2a1",
        ),
    )
    node = graph.node(graph.nodes_of_kind(NodeKind.FINDING)[0])
    assert "unique-marker-finding-test-4f2a1" not in node["description"]
    assert "unique-marker-finding-test-4f2a1" not in node["evidence"][0]
