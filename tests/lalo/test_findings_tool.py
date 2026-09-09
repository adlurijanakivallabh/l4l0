"""Tests for the `record_finding` agent tool."""

from __future__ import annotations

from lalo.agent.tools import ToolRegistry
from lalo.core.redaction import shared_redactor
from lalo.findings.tool import build_record_finding_tool, build_record_safe_tool
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
        "remediation": "Apply input validation and least-privilege fixes.",
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


def test_dedup_merge_keeps_the_stronger_cvss_assessment_not_the_first_one() -> None:
    """Real bug this closes: the merge branch used to update only evidence/
    identities/reproduced/evidence_grounded, silently discarding the newly
    computed cvss_score/severity/vector on every duplicate filing after the
    first - the graph kept whichever assessment happened to arrive first,
    forever, even when a later filing is materially more (or less) severe."""
    graph = ReachabilityGraph()
    registry = _registry(graph)
    weak_cvss = {**_VALID_CVSS, "confidentiality": "N", "integrity": "N", "availability": "N"}
    strong_cvss = {**_VALID_CVSS, "confidentiality": "H", "integrity": "H", "availability": "H"}

    registry.dispatch("record_finding", _args(cvss_breakdown=weak_cvss))
    registry.dispatch(
        "record_finding",
        _args(
            evidence=["a second, independent capture confirming full impact"],
            cvss_breakdown=strong_cvss,
        ),
    )

    (finding_id,) = graph.nodes_of_kind(NodeKind.FINDING)
    node = graph.node(finding_id)
    # the STRONGER of the two computed scores must win, not the first-filed one
    assert node["cvss_severity"] in ("high", "critical")
    assert node["cvss_score"] > 0.0


def test_dedup_merge_keeps_the_first_cvss_assessment_when_it_is_already_stronger() -> None:
    """The inverse case: a later, WEAKER duplicate filing must never water
    down an already-established stronger assessment."""
    graph = ReachabilityGraph()
    registry = _registry(graph)
    strong_cvss = {**_VALID_CVSS, "confidentiality": "H", "integrity": "H", "availability": "H"}
    weak_cvss = {**_VALID_CVSS, "confidentiality": "N", "integrity": "N", "availability": "N"}

    registry.dispatch("record_finding", _args(cvss_breakdown=strong_cvss))
    registry.dispatch(
        "record_finding",
        _args(
            evidence=["a second, independent capture with weaker impact"],
            cvss_breakdown=weak_cvss,
        ),
    )

    (finding_id,) = graph.nodes_of_kind(NodeKind.FINDING)
    node = graph.node(finding_id)
    assert node["cvss_severity"] in ("high", "critical")


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


def test_record_finding_redacts_a_secret_embedded_in_the_target_url() -> None:
    """A target can itself carry a secret (a password-reset link, a session id
    in the path) - it must never reach the graph node, the dedup key, the
    tool's own observation string, or the graph's JSON-serialized form raw."""
    shared_redactor().register_secret("super-secret-reset-token-abcdef123456")
    graph = ReachabilityGraph()
    result = _registry(graph).dispatch(
        "record_finding",
        _args(
            target=("https://victim.example.com/reset?token=super-secret-reset-token-abcdef123456")
        ),
    )
    node = graph.node(graph.nodes_of_kind(NodeKind.FINDING)[0])
    assert "super-secret-reset-token-abcdef123456" not in node["target"]
    assert "super-secret-reset-token-abcdef123456" not in node["dedup_key"]
    assert "super-secret-reset-token-abcdef123456" not in result.observation
    assert b"super-secret-reset-token-abcdef123456" not in graph.to_json()
    # the target's identifiable structure survives - only the secret value is gone
    assert "victim.example.com" in node["target"]


def test_record_finding_redacts_a_secret_embedded_in_param() -> None:
    shared_redactor().register_secret("param-secret-marker-9f2c1")
    graph = ReachabilityGraph()
    _registry(graph).dispatch(
        "record_finding", _args(param="id (actual value: param-secret-marker-9f2c1)")
    )
    node = graph.node(graph.nodes_of_kind(NodeKind.FINDING)[0])
    assert "param-secret-marker-9f2c1" not in (node["param"] or "")


# --- enabled_by_finding_id: the only place an ENABLES chain edge is created -


def test_record_finding_links_a_declared_chain_predecessor() -> None:
    graph = ReachabilityGraph()
    registry = _registry(graph)
    first = registry.dispatch("record_finding", _args(target="https://x.example.com/idor"))
    first_id = graph.nodes_of_kind(NodeKind.FINDING)[0]
    assert first.ok is True

    second = registry.dispatch(
        "record_finding",
        _args(
            target="https://x.example.com/admin",
            vuln_class="access-control",
            enabled_by_finding_id=first_id,
        ),
    )
    assert second.ok is True
    assert "chained: enabled by" in second.observation
    second_id = next(fid for fid in graph.nodes_of_kind(NodeKind.FINDING) if fid != first_id)
    assert graph.has_edge_of_kind(first_id, EdgeKind.ENABLES)
    assert graph.all_enabling_chains()[0].node_ids == [first_id, second_id]


def test_record_finding_warns_but_still_lands_on_an_unknown_chain_predecessor() -> None:
    graph = ReachabilityGraph()
    result = _registry(graph).dispatch(
        "record_finding", _args(enabled_by_finding_id="finding-does-not-exist")
    )
    assert result.ok is True
    assert "WARNING" in result.observation
    assert "not a known finding" in result.observation
    assert graph.all_enabling_chains() == []


def test_record_finding_rejects_a_non_finding_node_as_a_chain_predecessor() -> None:
    graph = ReachabilityGraph()
    graph.add_node("note-1", NodeKind.NOTE, text="not a finding")
    result = _registry(graph).dispatch("record_finding", _args(enabled_by_finding_id="note-1"))
    assert result.ok is True
    assert "WARNING" in result.observation
    assert not graph.has_edge_of_kind("note-1", EdgeKind.ENABLES)


def test_record_finding_without_enabled_by_finding_id_creates_no_chain_note() -> None:
    graph = ReachabilityGraph()
    result = _registry(graph).dispatch("record_finding", _args())
    assert "chained" not in result.observation
    assert "WARNING: enabled_by_finding_id" not in result.observation


def test_record_finding_links_a_chain_predecessor_even_on_a_merge() -> None:
    graph = ReachabilityGraph()
    registry = _registry(graph)
    registry.dispatch("record_finding", _args())
    predecessor = registry.dispatch("record_finding", _args(target="https://x.example.com/other"))
    assert predecessor.ok is True
    predecessor_id = next(
        fid
        for fid in graph.nodes_of_kind(NodeKind.FINDING)
        if graph.node(fid)["target"] == "https://x.example.com/other"
    )

    merged = registry.dispatch(
        "record_finding",
        _args(evidence=["a second capture of the same bug"], enabled_by_finding_id=predecessor_id),
    )
    assert merged.ok is True
    assert "merged into existing finding" in merged.observation
    assert "chained: enabled by" in merged.observation
    assert graph.has_edge_of_kind(predecessor_id, EdgeKind.ENABLES)


def test_record_finding_stores_an_optional_source_location() -> None:
    graph = ReachabilityGraph()
    _registry(graph).dispatch("record_finding", _args(source_location="app/routes.py:42"))
    node = graph.node(graph.nodes_of_kind(NodeKind.FINDING)[0])
    assert node["source_location"] == "app/routes.py:42"


def test_record_finding_source_location_defaults_to_none() -> None:
    graph = ReachabilityGraph()
    _registry(graph).dispatch("record_finding", _args())
    node = graph.node(graph.nodes_of_kind(NodeKind.FINDING)[0])
    assert node["source_location"] is None


def test_record_finding_redacts_a_secret_embedded_in_source_location() -> None:
    shared_redactor().register_secret("unique-marker-source-loc-9c3d1")
    graph = ReachabilityGraph()
    _registry(graph).dispatch(
        "record_finding",
        _args(source_location="app/unique-marker-source-loc-9c3d1/routes.py:42"),
    )
    node = graph.node(graph.nodes_of_kind(NodeKind.FINDING)[0])
    assert "unique-marker-source-loc-9c3d1" not in node["source_location"]


def test_record_finding_drops_a_path_traversal_shaped_source_location() -> None:
    graph = ReachabilityGraph()
    result = _registry(graph).dispatch(
        "record_finding", _args(source_location="../../etc/hostname:5")
    )
    assert result.ok is True
    assert "recorded finding-" in result.observation
    assert "dropped" in result.observation
    node = graph.node(graph.nodes_of_kind(NodeKind.FINDING)[0])
    assert node["source_location"] is None
    # everything else about the finding still landed, untouched
    assert node["vuln_class"] == "sql-injection"
    assert node["cvss_severity"] == "high"


def test_record_finding_drops_an_absolute_path_source_location() -> None:
    graph = ReachabilityGraph()
    _registry(graph).dispatch("record_finding", _args(source_location="/etc/hostname:3"))
    node = graph.node(graph.nodes_of_kind(NodeKind.FINDING)[0])
    assert node["source_location"] is None


def test_record_finding_drops_a_windows_drive_letter_source_location() -> None:
    graph = ReachabilityGraph()
    _registry(graph).dispatch(
        "record_finding", _args(source_location="C:\\Windows\\System32\\config\\SAM:1")
    )
    node = graph.node(graph.nodes_of_kind(NodeKind.FINDING)[0])
    assert node["source_location"] is None


def test_record_safe_lands_a_verified_safe_node_never_a_finding() -> None:
    graph = ReachabilityGraph()
    tool = build_record_safe_tool(graph)
    result = tool.run(
        {
            "vuln_class": "sql-injection",
            "target": "https://x.example.com/search",
            "param": "q",
            "defense_mechanism": "parameterized query confirmed via source read at app/db.py:42",
        }
    )
    assert result.ok is True
    (node_id,) = graph.nodes_of_kind(NodeKind.VERIFIED_SAFE)
    node = graph.node(node_id)
    assert node["vuln_class"] == "sql-injection"
    assert node["target"] == "https://x.example.com/search"
    assert node["param"] == "q"
    assert "parameterized query" in node["defense_mechanism"]
    # Never lands as (or alongside) a FINDING - this is evidence of absence,
    # not a vulnerability record, and must never be confused with one.
    assert graph.nodes_of_kind(NodeKind.FINDING) == []


def test_record_safe_requires_vuln_class_target_and_defense_mechanism() -> None:
    graph = ReachabilityGraph()
    tool = build_record_safe_tool(graph)
    result = tool.run({"vuln_class": "sql-injection", "target": "https://x.example.com/"})
    assert result.ok is False
    assert "defense_mechanism" in result.observation


def test_record_safe_target_is_redacted_the_same_way_record_finding_is() -> None:
    graph = ReachabilityGraph()
    tool = build_record_safe_tool(graph)
    tool.run(
        {
            "vuln_class": "sql-injection",
            "target": "https://x.example.com/reset?token=verysecrettoken1234567890",
            "defense_mechanism": "parameterized",
        }
    )
    (node_id,) = graph.nodes_of_kind(NodeKind.VERIFIED_SAFE)
    assert "verysecrettoken1234567890" not in graph.node(node_id)["target"]


def test_record_finding_captures_prerequisites_and_impact() -> None:
    graph = ReachabilityGraph()
    _registry(graph).dispatch(
        "record_finding",
        _args(
            prerequisites="none - publicly accessible endpoint",
            impact="full account takeover for any user whose email is known",
        ),
    )
    (finding_id,) = graph.nodes_of_kind(NodeKind.FINDING)
    node = graph.node(finding_id)
    assert node["prerequisites"] == "none - publicly accessible endpoint"
    assert node["impact"] == "full account takeover for any user whose email is known"


def test_record_finding_defaults_prerequisites_and_impact_to_empty_string() -> None:
    graph = ReachabilityGraph()
    _registry(graph).dispatch("record_finding", _args())
    (finding_id,) = graph.nodes_of_kind(NodeKind.FINDING)
    node = graph.node(finding_id)
    assert node.get("prerequisites", "") == ""
    assert node.get("impact", "") == ""


def test_record_finding_captures_ordered_exploitation_steps() -> None:
    graph = ReachabilityGraph()
    _registry(graph).dispatch(
        "record_finding",
        _args(
            exploitation_steps=[
                "Authenticate as a low-privilege user via POST /login",
                "Request GET /api/admin/users/1 directly with the low-priv session token",
            ]
        ),
    )
    (finding_id,) = graph.nodes_of_kind(NodeKind.FINDING)
    node = graph.node(finding_id)
    assert node["exploitation_steps"] == [
        "Authenticate as a low-privilege user via POST /login",
        "Request GET /api/admin/users/1 directly with the low-priv session token",
    ]


def test_record_finding_defaults_exploitation_steps_to_empty_list() -> None:
    graph = ReachabilityGraph()
    _registry(graph).dispatch("record_finding", _args())
    (finding_id,) = graph.nodes_of_kind(NodeKind.FINDING)
    assert graph.node(finding_id).get("exploitation_steps", []) == []
