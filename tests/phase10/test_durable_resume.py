"""Focused Phase 10 checks for durable state and continue-not-replay resume."""

from __future__ import annotations

import json
from pathlib import Path

from reachagent.execution.audit import AuditLog
from reachagent.graph.chain_solver import ChainSolver
from reachagent.graph.nodes import (
    AuthState,
    Endpoint,
    Finding,
    FindingStatus,
    Identity,
    Provenance,
)
from reachagent.graph.persistence import dump_graph, load_graph, load_phase_state
from reachagent.graph.store import ReachabilityGraph, identity_id
from reachagent.scan.entrypoint import scan_target


def _graph_with_finding() -> tuple[ReachabilityGraph, ChainSolver, AuditLog, str]:
    graph = ReachabilityGraph()
    graph.add_identity("user", Identity("user", AuthState.USER, Provenance.SEEDED))
    graph.add_endpoint(Endpoint("GET", "/items"))
    finding = graph.add_finding(
        Finding(
            vuln_class="path_traversal",
            severity="high",
            oracle_used="structural",
            evidence_ref="evidence-1",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    return graph, ChainSolver(graph), AuditLog(), finding


def test_durable_projection_scrubs_edge_audit_and_phase_secrets(tmp_path: Path) -> None:
    graph, solver, audit, _finding = _graph_with_finding()
    identity = identity_id("user")
    endpoint = next(node for node, _ in graph.endpoints())
    graph.set_can_call(
        identity,
        endpoint,
        FindingStatus.INCONCLUSIVE,
        evidence=(
            'Authorization: Bearer edge-secret {"password":"edge-secret"} '
            "fire-abc verdict-xyz"
        ),
    )
    audit.record(
        "user",
        "GET",
        "https://target.test/items?token=edge-secret",
        "password=edge-secret fire-abc browser-xyz verdict-xyz",
    )
    path = tmp_path / "state.json"
    dump_graph(
        graph,
        solver,
        audit,
        path,
        phase_state={
            "phase": "payloads",
            "status": "running",
            "last_error": "Bearer edge-secret",
            "raw_body": "must-not-persist",
        },
    )

    text = path.read_text(encoding="utf-8")
    assert "edge-secret" not in text
    assert "fire-abc" not in text
    assert "browser-xyz" not in text
    assert "verdict-xyz" not in text
    assert "raw_body" not in text
    assert load_phase_state(path) == {
        "phase": "payloads",
        "status": "running",
        "last_error": "<redacted>",
    }


def test_audit_tail_is_bounded_and_state_path_is_reused_on_resume(tmp_path: Path) -> None:
    graph, solver, audit, _finding = _graph_with_finding()
    for index in range(2_005):
        audit.record("user", "GET", f"https://target.test/{index}", f"ok:{index}")
    path = tmp_path / "state.json"
    dump_graph(graph, solver, audit, path)
    records = json.loads(path.read_text(encoding="utf-8"))
    assert len(records["audit"]) == 2_000

    # With no replacement state_path, a resumed planning call checkpoints back
    # into the resume file instead of silently discarding the updated phase state.
    result = scan_target(
        base_url="https://target.test",
        in_scope="target.test",
        dry_run=True,
        resume_path=str(path),
    )
    assert result["dry_run"] is True
    assert load_phase_state(path)["status"] == "completed"


def test_restored_advance_is_not_replayed(tmp_path: Path) -> None:
    graph, solver, audit, finding = _graph_with_finding()
    solver.advance(finding, acting_identity=identity_id("user"), path_id="scan")
    path = tmp_path / "state.json"
    dump_graph(graph, solver, audit, path)
    restored_graph, restored_solver, _audit = load_graph(path)

    assert restored_solver.advance(
        finding,
        acting_identity=identity_id("user"),
        path_id="scan",
    ) == []
    assert restored_graph.findings()[0][1].status is FindingStatus.CONFIRMED_VIOLATION
