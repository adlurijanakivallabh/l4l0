"""Tests for the reachability graph store, persistence, and chain solver."""

from __future__ import annotations

import pytest

from lalo.graph import (
    EdgeType,
    NodeType,
    ReachGraph,
    find_chains,
    load_graph,
    save_graph,
)
from lalo.graph.persistence import PersistenceError
from lalo.models import Evidence, EvidenceKind, Finding, Severity


def _finding() -> Finding:
    return Finding.create(
        title="Reflected XSS in q",
        vuln_class="xss",
        severity=Severity.HIGH,
        target="https://app.example.com/search",
        evidence=[
            Evidence(kind=EvidenceKind.STRUCTURAL, summary="payload reflected", observed="<script>")
        ],
    )


def test_add_and_query_nodes() -> None:
    g = ReachGraph()
    g.add_endpoint("https://app.example.com/search")
    g.add_service("app.example.com", 5432, name="postgres")
    assert len(list(g.nodes_of_type(NodeType.ENDPOINT))) == 1
    assert len(list(g.nodes_of_type(NodeType.SERVICE))) == 1


def test_session_mirrors_onto_identity() -> None:
    g = ReachGraph()
    session_id = g.add_session("alice", "cookie")
    # session exists AND is linked to an identity node (mirror by construction).
    assert len(list(g.nodes_of_type(NodeType.SESSION))) == 1
    assert len(list(g.nodes_of_type(NodeType.IDENTITY))) == 1
    successors = list(g.graph.successors(session_id))
    assert successors == ["identity:alice"]


def test_finding_roundtrips_through_store() -> None:
    g = ReachGraph()
    g.add_finding(_finding())
    findings = g.findings()
    assert len(findings) == 1
    assert findings[0].vuln_class == "xss"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].evidence[0].kind is EvidenceKind.STRUCTURAL


def test_persistence_roundtrip(tmp_path) -> None:
    g = ReachGraph()
    g.add_endpoint("https://app.example.com/")
    g.add_finding(_finding())
    path = tmp_path / "graph.json"
    save_graph(g, path)
    loaded = load_graph(path)
    assert loaded.summary() == g.summary()
    assert loaded.findings()[0].title == "Reflected XSS in q"


def test_corrupt_graph_file_is_detected(tmp_path) -> None:
    path = tmp_path / "graph.json"
    path.write_text("{ this is not valid json")
    with pytest.raises(PersistenceError):
        load_graph(path)


def test_chain_solver_finds_multi_step_path() -> None:
    # Seed IDOR -> admin -> upload -> (RCE finding), linked by ENABLES.
    g = ReachGraph()
    idor = g.add_endpoint("https://app/idor", "GET")
    admin = g.add_endpoint("https://app/admin", "GET")
    upload = g.add_endpoint("https://app/upload", "POST")
    rce = g.add_finding(_finding())
    g.link(idor, admin, EdgeType.ENABLES)
    g.link(admin, upload, EdgeType.ENABLES)
    g.link(upload, rce, EdgeType.ENABLES)

    chains = find_chains(g)
    assert chains, "expected at least one chain ending at the finding"
    longest = chains[0]
    assert longest[0].node_id == idor
    assert longest[-1].node_id == rce
    assert len(longest) == 4
