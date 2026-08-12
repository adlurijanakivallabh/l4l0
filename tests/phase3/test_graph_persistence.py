"""Durable graph + solver + audit persistence and run resume (b-items D6/D2)."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import httpx
import pytest

from reachagent.execution.audit import AuditLog
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.chain_solver import ChainSolver
from reachagent.graph.nodes import (
    AuthState,
    Endpoint,
    Finding,
    FindingStatus,
    Host,
    Identity,
    Object,
    Parameter,
    Provenance,
    Service,
    Session,
    SinkType,
)
from reachagent.graph.persistence import dump_graph, load_graph
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.scan.entrypoint import scan_target

_TARGET = "target.test"


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts([_TARGET, "example.com"])


def _rich_graph() -> tuple[ReachabilityGraph, ChainSolver, AuditLog]:
    """A graph exercising every node kind, attribute, edge, and status."""
    g = ReachabilityGraph()
    a = AuditLog()
    solver = ChainSolver(g, path_budget=40)

    host = g.add_host(Host(address=_TARGET, source="gobuster", technology="nginx"))
    ep = g.add_endpoint(
        Endpoint(
            method="GET",
            path="/admin",
            access_restricted="403",
            technology="wildcard_shape:200/size:10",
        )
    )
    g.add_resolves_to(host, ep)
    g.add_parameter(ep, Parameter(name="id", location="query", inferred_sink_type=SinkType.SQL))
    g.add_service(host, Service(port=443, protocol="tcp", service_name="https"))
    ident = g.add_identity(
        "user_a", Identity(role="user", auth_state=AuthState.USER, provenance=Provenance.SEEDED)
    )
    g.add_session(Session(token_ref="session-ref-a", identity_ref="user_a"))
    obj = g.add_object(
        Object(
            type="Vehicle", owner_identity_ref="user_a", sensitivity_tier=2, instance_key="car-1"
        )
    )
    g.add_returns(ep, obj)
    g.set_owns(ident, obj)

    # Every can_call status.
    statuses = {
        "/allowed": FindingStatus.CONFIRMED_ALLOWED,
        "/denied": FindingStatus.CONFIRMED_DENIED,
        "/viol": FindingStatus.CONFIRMED_VIOLATION,
        "/inc": FindingStatus.INCONCLUSIVE,
    }
    for path, status in statuses.items():
        epi = g.add_endpoint(Endpoint(method="GET", path=path))
        g.set_can_call(ident, epi, status, evidence=str(status.value))

    # A confirmed finding (the only persistable status) + chain edges.
    f1 = g.add_finding(
        Finding(
            vuln_class="path_traversal",
            severity="high",
            oracle_used="structural",
            evidence_ref="ref-f1",
            status=FindingStatus.CONFIRMED_VIOLATION,
            metadata={"sentinel": "root:x:0:0"},
        )
    )
    f2 = g.add_finding(
        Finding(
            vuln_class="sqli",
            severity="high",
            oracle_used="differential",
            evidence_ref="ref-f2",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    g.add_enables(f1, f2)
    sess2 = g.add_session(Session(token_ref="session-ref-b", identity_ref="user_a"))
    g.add_derived_credential(f2, sess2)

    solver.consume_budget("scan", 3)
    a.record("scan", "RECON", _TARGET, "ingested")
    a.record("u", "GET", f"https://{_TARGET}/x", "fired:200")
    return g, solver, a


# -- D1/D2: byte-identical round-trip, no secrets ---------------------------------


def test_dump_load_round_trip_byte_identical(tmp_path: Path) -> None:
    g, solver, a = _rich_graph()
    p1 = tmp_path / "state1.json"
    dump_graph(g, solver, a, p1)
    g2, solver2, a2 = load_graph(p1)
    p2 = tmp_path / "state2.json"
    dump_graph(g2, solver2, a2, p2)
    assert p1.read_bytes() == p2.read_bytes()


def test_round_trip_preserves_attributes_and_edges(tmp_path: Path) -> None:
    g, solver, a = _rich_graph()
    p = tmp_path / "state.json"
    dump_graph(g, solver, a, p)
    g2, _solver, _a = load_graph(p)
    # Endpoint attribute + sink survive.
    ep = next(e for _, e in g2.endpoints() if e.path == "/admin")
    assert ep.access_restricted == "403"
    assert "wildcard_shape:200/size:10" in ep.technology
    params = [
        p for _, p in g2.parameters_of(next(n for n, e in g2.endpoints() if e.path == "/admin"))
    ]
    assert params[0].inferred_sink_type is SinkType.SQL
    # Host + service survive.
    assert any(h.technology == "nginx" for _, h in g2.hosts())
    assert any(s.port == 443 for _, s in g2.services())
    # All four can_call statuses survive.
    statuses = {s for _, _, s in g2.can_call_edges()}
    assert statuses == set(FindingStatus)
    # Findings + chain edges survive.
    assert len(g2.findings()) == 2
    assert g2.derived_credential_edges() and g2.enables_edges()


def test_no_token_values_in_dump(tmp_path: Path) -> None:
    g, solver, a = _rich_graph()
    p = tmp_path / "state.json"
    dump_graph(g, solver, a, p)
    text = p.read_text()
    # token_ref HANDLES are fine (they're refs), but no secret VALUE leaks.
    assert "session-ref-a" in text
    for forbidden in ("s3cr3t", "password=", "Bearer ", "token-value"):
        assert forbidden not in text


def test_unknown_node_kind_raises_never_silently_dropped(tmp_path: Path) -> None:
    g, solver, a = _rich_graph()
    p = tmp_path / "state.json"
    dump_graph(g, solver, a, p)
    data = json.loads(p.read_text())
    data["graph"]["nodes"][0]["kind"] = "does-not-exist"
    p.write_text(json.dumps(data))
    from reachagent.graph.persistence import PersistenceError

    with pytest.raises(PersistenceError):
        load_graph(p)


def test_atomic_write_no_partial_file_on_failure(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    g, solver, a = _rich_graph()
    target = tmp_path / "state.json"
    # First a valid dump, then force os.replace to fail — the target is untouched.
    dump_graph(g, solver, a, target)
    original = target.read_bytes()

    def _boom(*_a: object, **_k: object) -> None:
        raise OSError("injected replace failure")

    monkeypatch.setattr(os, "replace", _boom)
    with pytest.raises(OSError):
        dump_graph(g, solver, a, target)
    assert target.read_bytes() == original  # no partial file


# -- D2: budgets + spawned survive ------------------------------------------------


def test_solver_budgets_survive_round_trip(tmp_path: Path) -> None:
    g, solver, a = _rich_graph()
    assert solver.budget_remaining("scan") == 37  # 40 - 3 consumed
    p = tmp_path / "state.json"
    dump_graph(g, solver, a, p)
    _g2, solver2, _a = load_graph(p)
    assert solver2.budget_remaining("scan") == 37


def test_solver_spawned_survive_round_trip(tmp_path: Path) -> None:
    g = ReachabilityGraph()
    a = AuditLog()
    ident = g.add_identity(
        "user_a", Identity(role="user", auth_state=AuthState.USER, provenance=Provenance.SEEDED)
    )
    ep = g.add_endpoint(Endpoint(method="GET", path="/items"))
    g.add_parameter(ep, Parameter(name="id", location="query"))
    solver = ChainSolver(g)
    solver.recover_derived(ident, path_id="scan")  # marks spawned + returns unexplored
    p = tmp_path / "state.json"
    dump_graph(g, solver, a, p)
    _g2, solver2, _a = load_graph(p)
    assert ident in solver2.spawned_identity_nodes("scan")


# -- D3: RECOVER / errored-retried / inconclusive-skipped -------------------------


def test_recover_derived_marks_and_returns_unexplored() -> None:
    g = ReachabilityGraph()
    ident = g.add_identity(
        "derived", Identity(role="admin", auth_state=AuthState.ADMIN, provenance=Provenance.DERIVED)
    )
    ep = g.add_endpoint(Endpoint(method="GET", path="/hidden"))
    g.add_parameter(ep, Parameter(name="q", location="query"))
    solver = ChainSolver(g)
    pairs = solver.recover_derived(ident, path_id="scan")
    assert (ident, ep) in pairs
    assert ident in solver.spawned_identity_nodes("scan")
    # Continue-not-replay: a second call skips (already marked).
    assert solver.recover_derived(ident, path_id="scan") == []


def test_resume_loads_findings_and_does_not_refire_explored(tmp_path: Path) -> None:
    # Confirmed finding + its explored endpoint (can_call violation) + one
    # unexplored endpoint. On resume the explored path is never re-probed.
    g = ReachabilityGraph()
    a = AuditLog()
    solver = ChainSolver(g)
    ident = g.add_identity(
        "user_a", Identity(role="user", auth_state=AuthState.USER, provenance=Provenance.SEEDED)
    )
    ep_finding = g.add_endpoint(Endpoint(method="GET", path="/traverse"))
    g.add_parameter(ep_finding, Parameter(name="q", location="query"))
    g.set_can_call(ident, ep_finding, FindingStatus.CONFIRMED_VIOLATION, evidence="200")
    g.add_finding(
        Finding(
            vuln_class="path_traversal",
            severity="high",
            oracle_used="structural",
            evidence_ref="ref-f",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    ep_open = g.add_endpoint(Endpoint(method="GET", path="/open"))
    g.add_parameter(ep_open, Parameter(name="q", location="query"))
    p = tmp_path / "state.json"
    dump_graph(g, solver, a, p)

    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/traverse":
            raise AssertionError("confirmed finding's endpoint must not be re-fired")
        requested.append(path)
        return httpx.Response(200, text="ok")

    result = scan_target(
        base_url=f"https://{_TARGET}",
        in_scope="target.test",
        dry_run=False,
        resume_path=str(p),
        transport=httpx.MockTransport(handler),
    )
    # Finding preserved as a loaded fact — not re-confirmed.
    assert len(result["graph"].findings()) == 1
    assert "/traverse" not in requested
    assert "/open" in requested  # unexplored edge re-probed on resume


def test_inconclusive_skipped_and_errored_requeried(tmp_path: Path) -> None:
    # INCONCLUSIVE can_call → a real verdict → never re-probed. An errored edge
    # (no verdict, only an errored audit entry) → re-probed by the normal loop.
    g = ReachabilityGraph()
    a = AuditLog()
    solver = ChainSolver(g)
    ident = g.add_identity(
        "user_a", Identity(role="user", auth_state=AuthState.USER, provenance=Provenance.SEEDED)
    )
    ep_inc = g.add_endpoint(Endpoint(method="GET", path="/inconclusive"))
    g.add_parameter(ep_inc, Parameter(name="q", location="query"))
    g.set_can_call(ident, ep_inc, FindingStatus.INCONCLUSIVE, evidence="no signal")
    ep_err = g.add_endpoint(Endpoint(method="GET", path="/errored"))
    g.add_parameter(ep_err, Parameter(name="q", location="query"))
    a.record("u", "GET", f"https://{_TARGET}/errored", "error:ConnectError:unrecoverable")
    p = tmp_path / "state.json"
    dump_graph(g, solver, a, p)

    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/inconclusive":
            raise AssertionError("inconclusive verdict must not be re-probed")
        requested.append(path)
        return httpx.Response(200, text="ok")

    scan_target(
        base_url=f"https://{_TARGET}",
        in_scope="target.test",
        dry_run=False,
        resume_path=str(p),
        transport=httpx.MockTransport(handler),
    )
    assert "/inconclusive" not in requested
    assert "/errored" in requested  # errored edge (no verdict) re-queried


# -- D2: crash-sim — run → dump → resume preserves findings ----------------------


def test_crash_sim_full_run_dump_resume(tmp_path: Path) -> None:
    state = tmp_path / "state.json"

    def ok_handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        if "../" in q or "..%2f" in q.lower():
            return httpx.Response(200, text="root:x:0:0:root:/root")
        return httpx.Response(200, text="ok")

    run1 = scan_target(
        base_url=f"https://{_TARGET}",
        in_scope="target.test",
        dry_run=False,
        state_path=str(state),
        transport=httpx.MockTransport(ok_handler),
        fixtures={"gobuster": "/items (Status: 200)\n"},
    )
    assert state.exists()
    findings1 = len(run1["graph"].findings())

    # Resume: the confirmed path must not be re-fired (a raise here = replay bug).
    def strict_handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        if "../" in q or "..%2f" in q.lower():
            raise AssertionError("confirmed traversal must not be re-probed on resume")
        return httpx.Response(200, text="ok")

    run2 = scan_target(
        base_url=f"https://{_TARGET}",
        in_scope="target.test",
        dry_run=False,
        resume_path=str(state),
        transport=httpx.MockTransport(strict_handler),
    )
    assert len(run2["graph"].findings()) == findings1  # findings preserved


# -- D4: AST + six families -------------------------------------------------------


def test_persistence_imports_no_validator(tmp_path: Path) -> None:
    import reachagent.graph.persistence as mod

    tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
    forbidden = (
        "reachagent.tools.validator",
        "reachagent.tools.candidate",
        "run_oracle",
        "write_finding",
        "TokenStore",
    )
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if any(f in node.module for f in forbidden):
                offenders.append(f"from {node.module}")
            for alias in node.names:
                if any(f in alias.name for f in forbidden):
                    offenders.append(f"import {alias.name}")
        if isinstance(node, ast.Import):
            for alias in node.names:
                if any(f in alias.name for f in forbidden):
                    offenders.append(f"import {alias.name}")
    assert offenders == []


def test_six_oracle_families_unchanged() -> None:
    assert set(OracleMechanism) == {
        OracleMechanism.DIFFERENTIAL,
        OracleMechanism.STRUCTURAL,
        OracleMechanism.TIMING_STATISTICAL,
        OracleMechanism.OOB_CALLBACK,
        OracleMechanism.EXECUTION_CONFIRMATION,
        OracleMechanism.BUSINESS_RULE_INVARIANT,
    }
