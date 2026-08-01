"""Phase 5 Coordinator scoring, budget, and chain integration (§4/§8/§11)."""

from __future__ import annotations

import ast

from reachagent.graph.chain_solver import ChainSolver
from reachagent.graph.nodes import (
    AuthState,
    Endpoint,
    Finding,
    FindingStatus,
    Identity,
    Object,
    Parameter,
    Provenance,
    Session,
    SinkType,
)
from reachagent.graph.store import ReachabilityGraph, identity_id
from reachagent.tools import coordinator
from reachagent.tools.coordinator_support import CoordinatorContext


def _finding(graph: ReachabilityGraph, vuln_class: str, ref: str) -> str:
    return graph.add_finding(
        Finding(
            vuln_class=vuln_class,
            severity="high",
            oracle_used="differential",
            evidence_ref=ref,
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )


def _context(graph: ReachabilityGraph, *, budget: int = 40) -> CoordinatorContext:
    return CoordinatorContext(graph, ChainSolver(graph, path_budget=budget), "p1")


def test_query_graph_returns_only_unprobed_edges_and_parameters() -> None:
    graph = ReachabilityGraph()
    endpoint = graph.add_endpoint(Endpoint("GET", "/admin"))
    param = graph.add_parameter(endpoint, Parameter("q", "query", SinkType.SQL))
    graph.add_identity("user", Identity("user", AuthState.USER, Provenance.SEEDED))
    graph.set_can_call(
        identity_id("user"), endpoint, FindingStatus.CONFIRMED_DENIED, evidence="403"
    )
    context = _context(graph)

    assert coordinator.query_graph(context) == []

    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.SEEDED))
    candidates = coordinator.query_graph(context)
    assert [(c.identity_node, c.endpoint_node, c.parameter_node) for c in candidates] == [
        (identity_id("admin"), endpoint, param)
    ]


def test_query_graph_keeps_inconclusive_edges_eligible() -> None:
    graph = ReachabilityGraph()
    endpoint = graph.add_endpoint(Endpoint("GET", "/probe"))
    graph.add_identity("user", Identity("user", AuthState.USER, Provenance.SEEDED))
    graph.mark_edge_inconclusive(identity_id("user"), endpoint, evidence="timeout")
    context = _context(graph)
    assert len(coordinator.query_graph(context)) == 1


def test_sink_severity_ordering_is_monotonic() -> None:
    graph = ReachabilityGraph()
    identities = []
    candidates = []
    for name, sink in (
        ("html", SinkType.HTML_REFLECTION),
        ("sql", SinkType.SQL),
        ("shell", SinkType.SHELL),
    ):
        endpoint = graph.add_endpoint(Endpoint("GET", f"/{name}"))
        param = graph.add_parameter(endpoint, Parameter("q", "query", sink))
        identity = graph.add_identity(name, Identity("user", AuthState.USER, Provenance.SEEDED))
        identities.append(identity)
        candidates.append((endpoint, param, identity))
    context = _context(graph)
    selections = [
        coordinator.score_and_select(
            [next(c for c in coordinator.query_graph(context) if c.endpoint_node == endpoint)]
        )
        for endpoint, _, _ in candidates
    ]
    assert selections[2].score > selections[1].score > selections[0].score


def test_prior_attempts_penalize_one_hop_identity_or_endpoint_neighbors() -> None:
    graph = ReachabilityGraph()
    endpoint = graph.add_endpoint(Endpoint("GET", "/target"))
    neighbor = graph.add_endpoint(Endpoint("GET", "/neighbor"))
    graph.add_identity("user", Identity("user", AuthState.USER, Provenance.SEEDED))
    graph.add_identity("other", Identity("user", AuthState.USER, Provenance.SEEDED))
    graph.set_can_call(
        identity_id("user"), neighbor, FindingStatus.CONFIRMED_DENIED, evidence="403"
    )
    graph.set_can_call(
        identity_id("other"), endpoint, FindingStatus.INCONCLUSIVE, evidence="timeout"
    )
    context = _context(graph)
    candidates = coordinator.query_graph(
        {"context": context, "identity_node": identity_id("user"), "endpoint_node": endpoint}
    )
    selected = coordinator.score_and_select(candidates)
    assert selected is not None
    assert selected.prior_attempts_in_neighborhood == 2

    graph = ReachabilityGraph()
    fresh_ep = graph.add_endpoint(Endpoint("GET", "/fresh"))
    chain_ep = graph.add_endpoint(Endpoint("GET", "/chain"))
    graph.add_returns(chain_ep, graph.add_object(Object("secret", sensitivity_tier=3)))
    graph.add_parameter(chain_ep, Parameter("url", "query", SinkType.HTML_REFLECTION))
    graph.add_parameter(fresh_ep, Parameter("q", "query", SinkType.SHELL))
    graph.add_identity("attacker", Identity("user", AuthState.USER, Provenance.SEEDED))
    finding = _finding(graph, "xss_stored", "xss/admin")
    context = _context(graph)
    context.solver.advance(
        finding,
        acting_identity=identity_id("attacker"),
        spawn=Session("derived-token", "admin"),
        path_id="p1",
    )
    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.DERIVED))
    candidates = coordinator.query_graph(context)
    selected = coordinator.score_and_select(candidates)
    assert selected is not None
    assert selected.identity_node == identity_id("admin")
    assert selected.is_newly_spawned_identity == 1
    assert selected.object_sensitivity_tier == 3
    assert selected.score == 3 * 3 + 5 + 1


def test_budget_reads_chain_solver_and_abandons_at_zero() -> None:
    graph = ReachabilityGraph()
    context = _context(graph, budget=2)
    assert coordinator.check_budget(context).remaining == 2
    assert coordinator.check_budget("p1").allowed is True

    graph.add_endpoint(Endpoint("GET", "/x"))
    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.DERIVED))
    finding = _finding(graph, "xss_stored", "xss/admin")
    context.solver.advance(
        finding,
        acting_identity=identity_id("attacker"),
        spawn=Session("tok-1", "admin"),
        path_id="p1",
    )
    assert coordinator.check_budget("p1").remaining == 1
    context.solver.advance(
        finding,
        acting_identity=identity_id("attacker"),
        spawn=Session("tok-2", "admin"),
        path_id="p1",
    )
    status = coordinator.check_budget("p1")
    assert status.remaining == 0
    assert not status
    assert (
        context.solver.advance(
            finding,
            acting_identity=identity_id("attacker"),
            spawn=Session("tok-3", "admin"),
            path_id="p1",
        )
        == []
    )


def test_score_selection_consumes_shared_budget_and_stops_at_cap() -> None:
    graph = ReachabilityGraph()
    graph.add_endpoint(Endpoint("GET", "/x"))
    graph.add_identity("user", Identity("user", AuthState.USER, Provenance.SEEDED))
    context = _context(graph, budget=1)
    candidates = coordinator.query_graph(context)
    assert coordinator.score_and_select(candidates) is not None
    assert coordinator.check_budget(context).remaining == 0
    assert coordinator.score_and_select(candidates) is None


def test_spawned_identity_bonus_selects_chain_completion_over_fresh_edge() -> None:
    graph = ReachabilityGraph()
    fresh_ep = graph.add_endpoint(Endpoint("GET", "/fresh"))
    chain_ep = graph.add_endpoint(Endpoint("GET", "/chain"))
    graph.add_returns(chain_ep, graph.add_object(Object("admin-secret", sensitivity_tier=2)))
    graph.add_parameter(chain_ep, Parameter("q", "query", SinkType.HTML_REFLECTION))
    graph.add_parameter(fresh_ep, Parameter("q", "query", SinkType.SQL))
    graph.add_identity("attacker", Identity("user", AuthState.USER, Provenance.SEEDED))
    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.DERIVED))
    finding = _finding(graph, "xss_stored", "xss/admin")
    context = _context(graph)
    context.solver.advance(
        finding,
        acting_identity=identity_id("attacker"),
        spawn=Session("tok-admin", "admin"),
        path_id="p1",
    )
    selected = coordinator.score_and_select(coordinator.query_graph(context))
    assert selected is not None
    assert selected.identity_node == identity_id("admin")
    assert selected.score == 2 * 3 + 5 + 1


def test_coordinator_loop_reconstructs_cross_class_chain() -> None:
    graph = ReachabilityGraph()
    chain_endpoint = graph.add_endpoint(Endpoint("GET", "/admin/fetch"))
    fresh_endpoint = graph.add_endpoint(Endpoint("GET", "/public/search"))
    graph.add_returns(
        chain_endpoint, graph.add_object(Object("internal-secret", sensitivity_tier=3))
    )
    graph.add_parameter(chain_endpoint, Parameter("url", "query", SinkType.URL))
    graph.add_parameter(fresh_endpoint, Parameter("q", "query", SinkType.HTML_REFLECTION))
    graph.add_identity("attacker", Identity("user", AuthState.USER, Provenance.SEEDED))
    context = _context(graph)

    first = _finding(graph, "xss_stored", "chain/xss")
    first_candidates = coordinator.query_graph(context)
    selected = coordinator.score_and_select(first_candidates)
    assert selected is not None
    assert selected.identity_node == identity_id("attacker")

    # Test harness stands in for Explorer + Validator: confirmed first hop then
    # ChainSolver advances, while Coordinator only re-queries and selects.
    context.solver.advance(
        first,
        acting_identity=identity_id("attacker"),
        spawn=Session("derived-admin-token", "admin"),
        path_id="p1",
    )
    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.DERIVED))
    next_selected = coordinator.score_and_select(coordinator.query_graph(context))
    assert next_selected is not None
    assert next_selected.identity_node == identity_id("admin")
    assert next_selected.is_newly_spawned_identity == 1

    second = _finding(graph, "ssrf", "chain/ssrf")
    context.solver.link(first, second)
    assert graph.chain_paths(first) == sorted(
        [
            (first, "session:derived-admin-token"),
            (first, second),
        ]
    )


def test_score_mapping_preserves_spawned_identity_bonus() -> None:
    graph = ReachabilityGraph()
    endpoint = graph.add_endpoint(Endpoint("GET", "/admin"))
    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.DERIVED))
    context = _context(graph)
    mapping = {
        "identity_node": identity_id("admin"),
        "endpoint_node": endpoint,
        "parameter_node": None,
        "context": context,
        "spawned_identity_nodes": [identity_id("admin")],
    }
    selected = coordinator.score_and_select([mapping])
    assert selected is not None
    assert selected.is_newly_spawned_identity == 1


def test_score_and_select_rejects_edge_tested_after_query() -> None:
    graph = ReachabilityGraph()
    endpoint = graph.add_endpoint(Endpoint("GET", "/probe"))
    graph.add_identity("user", Identity("user", AuthState.USER, Provenance.SEEDED))
    context = _context(graph)
    candidates = coordinator.query_graph(context)
    graph.set_can_call(
        identity_id("user"), endpoint, FindingStatus.CONFIRMED_DENIED, evidence="403"
    )
    assert coordinator.score_and_select(candidates) is None

    tree = ast.parse(open("src/reachagent/tools/coordinator.py", encoding="utf-8").read())
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
    assert not any(
        any(token in name for token in ("firer", "validator", "oracle", "explorer"))
        for name in imported
    )


def test_coordinator_public_surface_stays_exactly_three_tools() -> None:
    public = {
        name
        for name, value in vars(coordinator).items()
        if callable(value) and not name.startswith("_")
    }
    assert public == {"query_graph", "score_and_select", "check_budget"}
