"""BOLA detector enables-edge precondition tests (Task 8 #13 fix).

Asserts that the Chain Solver's `link()` call is gated on a genuine precondition
— hop A's finding must produce something (a credential, an identifier) that hop
B's finding consumes — not just "confirmed after A in iteration order."

The false-positive case: two independent BOLA instances on the same endpoint
(e.g. vehicle A's location, vehicle B's location) have no causal dependency and
must NOT be linked with an enables edge.

The true-positive case: a credential-yielding finding (XSS spawning an admin
session via `derived_credential`) that enables a second finding (SSRF reachable
under the admin session) must get an enables edge, because the admin credential
is the precondition.
"""

from __future__ import annotations

import httpx
import pytest

from reachagent.bola.detector import detect
from reachagent.graph.nodes import AuthState, Endpoint, Identity, Object, Provenance
from reachagent.graph.store import ReachabilityGraph, finding_id, identity_id
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient


def _stub_judgment(monkeypatch: pytest.MonkeyPatch, status=CONFIRMS) -> None:
    """Force run_oracle's LLM judgment to a fixed status (v3 architecture, CLAUDE.md).

    ``bola.detector.detect`` drives confirmation through the MCP ``run_oracle``
    tool (``_call(mcp, "run_oracle", ...)``), which exposes no ``client=`` kwarg
    to a hand-caller — so this patches the same default-provider factory
    ``judge()`` falls back to when no client is supplied, exactly like
    ``tests/phase1/test_mcp_server.py::_stub_judgment``. These tests assert the
    chain-linking WIRING (which findings get an enables edge) reacts correctly
    given a fixed verdict, not the now-removed deterministic decide() logic.
    """
    from reachagent.oracles import llm_judgment as _judgment

    monkeypatch.setattr(
        _judgment,
        "build_openai_compatible_client",
        lambda **_: FixedJudgmentClient(status.value),
    )


def test_two_independent_bola_instances_do_not_get_enables_edge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two BOLA findings on different object instances with no causal link → no enables."""
    _stub_judgment(monkeypatch)
    graph = ReachabilityGraph()
    for name, role in [("owner_a", "user"), ("owner_b", "user")]:
        graph.add_identity(
            name, Identity(role=role, auth_state=AuthState.USER, provenance=Provenance.SEEDED)
        )

    # owner_a's vehicle
    veh_a = graph.add_object(Object(type="vehicle", sensitivity_tier=2, instance_key="veh-uuid-a"))
    graph.set_owns(identity_id("owner_a"), veh_a)
    ep_a = graph.add_endpoint(Endpoint(method="GET", path="/api/vehicle/veh-uuid-a/location"))
    graph.add_returns(ep_a, veh_a)

    # owner_b's vehicle
    veh_b = graph.add_object(Object(type="vehicle", sensitivity_tier=2, instance_key="veh-uuid-b"))
    graph.set_owns(identity_id("owner_b"), veh_b)
    ep_b = graph.add_endpoint(Endpoint(method="GET", path="/api/vehicle/veh-uuid-b/location"))
    graph.add_returns(ep_b, veh_b)

    def handler(request: httpx.Request) -> httpx.Response:
        # Both endpoints are vulnerable: non-owner gets 200.
        return httpx.Response(200, json={"location": "sensitive"})

    result = detect(
        graph,
        "https://test.local",
        owner_tokens={identity_id("owner_a"): "tok-a", identity_id("owner_b"): "tok-b"},
        non_owner_tokens={identity_id("owner_a"): "tok-a", identity_id("owner_b"): "tok-b"},
        transport=httpx.MockTransport(handler),
    )

    # Both BOLA instances confirmed.
    assert len(result.confirmed_hops) == 2
    # But no enables edge: reading vehicle A's location does not enable reading vehicle B's.
    assert result.chain_edges == []
    assert graph.enables_edges() == []


def test_identifier_yielding_bola_chain_gets_enables_edge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hop A's response leaks the identifier hop B's path consumes → enables edge.

    This is the documented multi-step BOLA shape: reading resource A (owner) leaks
    a downstream identifier that resource B's path template consumes. B is only
    reachable *because* A produced its id — a genuine precondition, not adjacency.
    """
    _stub_judgment(monkeypatch)
    graph = ReachabilityGraph()
    graph.add_identity(
        "owner_a", Identity(role="user", auth_state=AuthState.USER, provenance=Provenance.SEEDED)
    )
    graph.add_identity(
        "owner_b", Identity(role="user", auth_state=AuthState.USER, provenance=Provenance.SEEDED)
    )

    veh_uuid = "11111111-1111-1111-1111-111111111111"
    report_uuid = "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"

    # Hop A: owner_a's vehicle, whose response leaks the downstream report id.
    veh = graph.add_object(Object(type="vehicle", sensitivity_tier=2, instance_key=veh_uuid))
    graph.set_owns(identity_id("owner_a"), veh)
    ep_veh = graph.add_endpoint(Endpoint(method="GET", path="/api/vehicle/{vehicleId}/location"))
    graph.add_returns(ep_veh, veh)

    # Hop B: a report object whose path consumes the downstream id A leaks.
    rpt = graph.add_object(Object(type="report", sensitivity_tier=2, instance_key=report_uuid))
    graph.set_owns(identity_id("owner_a"), rpt)
    ep_rpt = graph.add_endpoint(Endpoint(method="GET", path="/api/report/{reportId}"))
    graph.add_returns(ep_rpt, rpt)

    def handler(request: httpx.Request) -> httpx.Response:
        # The vehicle response leaks the downstream report id; the report response
        # leaks no identifier — so the data dependency is one-directional.
        if "/vehicle/" in request.url.path:
            return httpx.Response(200, json={"location": "x", "report_id": report_uuid})
        return httpx.Response(200, json={"report": "sensitive"})

    detect(
        graph,
        "https://test.local",
        owner_tokens={identity_id("owner_a"): "tok-a"},
        non_owner_tokens={identity_id("owner_b"): "tok-b"},
        transport=httpx.MockTransport(handler),
    )

    # Select the two concrete-path findings by the identifiers they resolve to.
    veh_fn = finding_id("bola", f"bola//api/vehicle/{veh_uuid}/location")
    rpt_fn = finding_id("bola", f"bola//api/report/{report_uuid}")

    # A → B: the vehicle finding enables the report finding, because the report
    # path consumed the identifier the vehicle response produced.
    assert (veh_fn, rpt_fn) in graph.enables_edges()
    assert any(veh_fn in p and rpt_fn in p for p in graph.chain_paths(veh_fn))
    # And not the spurious reverse direction — the report leaked no id to consume.
    assert (rpt_fn, veh_fn) not in graph.enables_edges()


def test_credential_yielding_chain_still_gets_enables_edge() -> None:
    """XSS spawns admin session → SSRF under admin → enables edge exists."""
    from reachagent.graph.chain_solver import ChainSolver
    from reachagent.graph.nodes import Finding, FindingStatus, Session

    graph = ReachabilityGraph()
    graph.add_identity("attacker", Identity("attacker", AuthState.USER, Provenance.SEEDED))
    graph.add_identity("admin", Identity("admin", AuthState.ADMIN, Provenance.DERIVED))
    graph.add_endpoint(Endpoint(method="GET", path="/api/user/profile"))
    graph.add_endpoint(Endpoint(method="GET", path="/api/admin/internal"))

    # XSS finding spawns an admin session.
    xss = graph.add_finding(
        Finding(
            vuln_class="xss_stored",
            severity="high",
            oracle_used="differential",
            evidence_ref="xss/profile",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    solver = ChainSolver(graph)
    solver.advance(
        xss,
        acting_identity=identity_id("attacker"),
        spawn=Session(token_ref="tok-admin-derived", identity_ref="admin"),
    )

    # SSRF finding reachable under the admin session.
    ssrf = graph.add_finding(
        Finding(
            vuln_class="ssrf",
            severity="high",
            oracle_used="differential",
            evidence_ref="ssrf/internal",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )

    # The enables edge is valid because xss → derived_credential → admin session.
    solver.link(xss, ssrf)

    assert graph.enables_edges() == [(xss, ssrf)]
    paths = graph.chain_paths(xss)
    assert any(xss in p and ssrf in p for p in paths)
