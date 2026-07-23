"""Chain Solver — spawn-and-requery over the finding layer (plan §8; Phase 2 Task 4).

Asserts the Task 4 DoD invariants:

  1. **Spawn-and-requery.** A confirmed credential-yielding finding triggers one
     uniform action — spawn the Session/Identity + edge and re-run reachability
     from that node — surfacing a previously-unreachable ``can_call`` edge as a
     fresh test candidate.
  2. **Class-agnostic, one entry point.** The same ``advance`` call handles a
     mass-assignment self-escalation (no new node; re-test the acting identity's
     own edges) and a credential-yielding finding (new node, then query) — no
     per-class-pair branch.
  3. **Connected chain persisted as ``enables`` edges.** A reconstructed chain is
     one connected path linking the contributing Finding nodes — asserted by
     querying ``chain_paths``/``enables_edges``, not by report text.
  4. **Termination + budget.** Re-query never re-opens an already-verdicted
     ``(identity, endpoint)`` neighborhood, and the §11 per-path budget cap
     halts the solver.
"""

from __future__ import annotations

from reachagent.graph.chain_solver import ChainSolver
from reachagent.graph.nodes import (
    AuthState,
    Endpoint,
    Finding,
    FindingStatus,
    Identity,
    Provenance,
    Session,
)
from reachagent.graph.store import ReachabilityGraph, identity_id


def _committed_finding(graph: ReachabilityGraph, vuln_class: str, evidence_ref: str) -> str:
    return graph.add_finding(
        Finding(
            vuln_class=vuln_class,
            severity="high",
            oracle_used="differential",
            evidence_ref=evidence_ref,
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )


# -- Invariant 1: spawn-and-requery surfaces a new can_call candidate ------


def test_credential_finding_spawns_session_and_requeries_new_candidate() -> None:
    graph = ReachabilityGraph()
    admin_ep = graph.add_endpoint(Endpoint(method="GET", path="/api/admin/reports"))
    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.DERIVED))
    finding = _committed_finding(graph, "xss_stored", "xss/admin-view")

    solver = ChainSolver(graph)
    candidates = solver.advance(
        finding,
        acting_identity=identity_id("attacker"),
        spawn=Session(token_ref="tok-admin-derived", identity_ref="admin"),
    )

    # The spawned session is a first-class node reached via a derived_credential edge.
    assert (finding, "session:tok-admin-derived") in graph.derived_credential_edges()
    # The admin-only endpoint, previously unreachable, is now a test candidate.
    assert (identity_id("admin"), admin_ep) in candidates


# -- Invariant 2: one entry point, both classes, no per-class branch -------


def test_self_escalation_requeries_acting_identity_without_a_new_node() -> None:
    graph = ReachabilityGraph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/api/admin/reports"))
    graph.add_identity("user", Identity("user", AuthState.USER, Provenance.SEEDED))
    finding = _committed_finding(graph, "mass_assignment", "massassign/role")

    before = len(graph.identities()) + len(graph.sessions())
    solver = ChainSolver(graph)
    candidates = solver.advance(finding, acting_identity=identity_id("user"), spawn=None)
    after = len(graph.identities()) + len(graph.sessions())

    # No node spawned — same acting identity re-queried.
    assert after == before
    assert graph.derived_credential_edges() == []
    assert (identity_id("user"), ep) in candidates


def test_both_classes_flow_through_the_same_advance_entry_point() -> None:
    # The two cases differ only by the `spawn` argument, not by a class branch.
    graph = ReachabilityGraph()
    graph.add_endpoint(Endpoint(method="GET", path="/api/admin/reports"))
    graph.add_identity("user", Identity("user", AuthState.USER, Provenance.SEEDED))
    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.DERIVED))
    f_escalate = _committed_finding(graph, "mass_assignment", "massassign/role")
    f_cred = _committed_finding(graph, "xss_stored", "xss/admin-view")

    solver = ChainSolver(graph)
    esc = solver.advance(f_escalate, acting_identity=identity_id("user"), spawn=None)
    cred = solver.advance(
        f_cred,
        acting_identity=identity_id("attacker"),
        spawn=Session(token_ref="tok-admin", identity_ref="admin"),
    )

    assert (identity_id("user"), "endpoint:GET /api/admin/reports") in esc
    assert (identity_id("admin"), "endpoint:GET /api/admin/reports") in cred


def test_identity_spawn_requires_a_spawn_name() -> None:
    import pytest

    graph = ReachabilityGraph()
    finding = _committed_finding(graph, "ssrf", "ssrf/metadata")
    solver = ChainSolver(graph)

    with pytest.raises(ValueError, match="spawn_name is required"):
        solver.advance(
            finding,
            acting_identity=identity_id("attacker"),
            spawn=Identity("synthetic", AuthState.SYNTHETIC, Provenance.DERIVED),
        )


def test_identity_spawn_from_a_credential_token_requeries_the_new_identity() -> None:
    graph = ReachabilityGraph()
    internal_ep = graph.add_endpoint(Endpoint(method="GET", path="/internal/admin/keys"))
    finding = _committed_finding(graph, "ssrf", "ssrf/metadata")

    solver = ChainSolver(graph)
    candidates = solver.advance(
        finding,
        acting_identity=identity_id("attacker"),
        spawn=Identity("synthetic", AuthState.SYNTHETIC, Provenance.DERIVED),
        spawn_name="metadata-token",
    )

    assert (finding, identity_id("metadata-token")) in graph.derived_credential_edges()
    assert (identity_id("metadata-token"), internal_ep) in candidates


# -- Invariant 3: reconstructed chain is a connected enables path ----------


def test_reconstructed_chain_is_one_connected_enables_path() -> None:
    graph = ReachabilityGraph()
    xss = _committed_finding(graph, "xss_stored", "xss/admin-view")
    ssrf = _committed_finding(graph, "ssrf", "ssrf/internal")

    solver = ChainSolver(graph)
    solver.link(xss, ssrf)

    # Queried from the graph, not read from a report string.
    assert graph.enables_edges() == [(xss, ssrf)]
    assert graph.chain_paths(xss) == [(xss, ssrf)]


def test_chain_survives_a_derived_credential_hop_end_to_end() -> None:
    # XSS confirms → spawns admin session → admin endpoint SSRF confirms →
    # enables links the two findings into one connected path.
    graph = ReachabilityGraph()
    graph.add_endpoint(Endpoint(method="GET", path="/api/admin/reports"))
    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.DERIVED))
    xss = _committed_finding(graph, "xss_stored", "xss/admin-view")

    solver = ChainSolver(graph)
    solver.advance(
        xss,
        acting_identity=identity_id("attacker"),
        spawn=Session(token_ref="tok-admin", identity_ref="admin"),
    )
    ssrf = _committed_finding(graph, "ssrf", "ssrf/internal")
    solver.link(xss, ssrf)

    paths = graph.chain_paths(xss)
    # One connected chain that includes both the derived session and the SSRF finding.
    assert (xss, "session:tok-admin") in paths
    assert (xss, ssrf) in paths


# -- Invariant 4: termination + budget cap ---------------------------------


def test_requery_skips_already_verdicted_edges() -> None:
    graph = ReachabilityGraph()
    ep_open = graph.add_endpoint(Endpoint(method="GET", path="/api/admin/reports"))
    ep_done = graph.add_endpoint(Endpoint(method="GET", path="/api/admin/users"))
    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.DERIVED))
    finding = _committed_finding(graph, "xss_stored", "xss/admin-view")
    # ep_done already has a verdict for admin — must not be re-queried.
    graph.set_can_call(
        identity_id("admin"), ep_done, FindingStatus.CONFIRMED_DENIED, evidence="403"
    )

    solver = ChainSolver(graph)
    candidates = solver.advance(
        finding,
        acting_identity=identity_id("attacker"),
        spawn=Session(token_ref="tok-admin", identity_ref="admin"),
    )

    assert (identity_id("admin"), ep_open) in candidates
    assert (identity_id("admin"), ep_done) not in candidates


def test_budget_cap_halts_the_solver() -> None:
    graph = ReachabilityGraph()
    graph.add_endpoint(Endpoint(method="GET", path="/api/admin/reports"))
    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.DERIVED))
    finding = _committed_finding(graph, "xss_stored", "xss/admin-view")

    solver = ChainSolver(graph, path_budget=1)
    assert solver.budget_remaining("p1") == 1

    first = solver.advance(
        finding,
        acting_identity=identity_id("attacker"),
        spawn=Session(token_ref="tok-1", identity_ref="admin"),
        path_id="p1",
    )
    assert first  # spent the one unit
    assert solver.budget_remaining("p1") == 0

    # Budget exhausted: a further advance on the same path yields nothing.
    second = solver.advance(
        finding,
        acting_identity=identity_id("attacker"),
        spawn=Session(token_ref="tok-2", identity_ref="admin"),
        path_id="p1",
    )
    assert second == []


def test_budget_is_scoped_per_path() -> None:
    graph = ReachabilityGraph()
    graph.add_endpoint(Endpoint(method="GET", path="/api/admin/reports"))
    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.DERIVED))
    finding = _committed_finding(graph, "xss_stored", "xss/admin-view")

    solver = ChainSolver(graph, path_budget=1)
    solver.advance(
        finding,
        acting_identity=identity_id("attacker"),
        spawn=Session(token_ref="tok-a", identity_ref="admin"),
        path_id="path-a",
    )
    # A different path has its own fresh budget.
    assert solver.budget_remaining("path-b") == 1
    second = solver.advance(
        finding,
        acting_identity=identity_id("attacker"),
        spawn=Session(token_ref="tok-b", identity_ref="admin"),
        path_id="path-b",
    )
    assert second
