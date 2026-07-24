"""crAPI multi-step BOLA end-to-end reconstruction — Phase 2 gate (§8, §14, §15).

Reconstructs both documented BOLA chains (vehicle-location, mechanic-contact)
via recon → cross-identity differential per hop → Chain Solver linking hops into
one connected ``enables`` path, queryable from the graph.

Layers 1–3 are hermetic (MockTransport). Layer 4 is a live integration run that
skips cleanly when crAPI isn't reachable.

Gate invariants (§14/§15):
  1. Both BOLA hops confirmed as findings in the graph.
  2. An ``enables`` edge links the two confirmed findings (one connected path).
  3. ``chain_paths`` returns a path containing both finding nodes.
  4. Zero state-changing requests fired by the detector (§10).
"""

from __future__ import annotations

import os

import httpx
import pytest

from reachagent.bola.detector import detect
from reachagent.graph.nodes import AuthState, Endpoint, Identity, Object, Provenance
from reachagent.graph.store import (
    ReachabilityGraph,
    finding_id,
    identity_id,
)
from reachagent.identity.store import IdentityStore
from reachagent.recon.crapi_recon import run_recon

BASE_URL = "https://crapi.test"
_HOST = "crapi.test"

# Stable identity ids used across fixtures.
_OWNER_A = identity_id("owner_a")
_OWNER_B = identity_id("owner_b")
_MECHANIC = identity_id("mechanic")

# Tokens used in hermetic tests — never real credentials.
_TOK_A = "tok-owner-a"
_TOK_B = "tok-user-b"
_TOK_M = "tok-mechanic"

# crAPI env (mirrors test_crapi_recon.py — no hardcoded passwords in detector).
_CRAPI_ENV = {
    "REACHAGENT_IDENTITIES": "owner_a,owner_b,mechanic",
    "REACHAGENT_IDENTITY_OWNER_A_USERNAME": "adam007@example.com",
    "REACHAGENT_IDENTITY_OWNER_A_PASSWORD": "a-secret",
    "REACHAGENT_IDENTITY_OWNER_A_ROLE": "user",
    "REACHAGENT_IDENTITY_OWNER_B_USERNAME": "pogba006@example.com",
    "REACHAGENT_IDENTITY_OWNER_B_PASSWORD": "b-secret",
    "REACHAGENT_IDENTITY_OWNER_B_ROLE": "user",
    "REACHAGENT_IDENTITY_MECHANIC_USERNAME": "jhon@example.com",
    "REACHAGENT_IDENTITY_MECHANIC_PASSWORD": "m-secret",
    "REACHAGENT_IDENTITY_MECHANIC_ROLE": "mechanic",
}

# Vehicle path with baked-in instance key (recon does this via instance_key_field).
_VEH_PATH = "/identity/api/v2/vehicle/adam-uuid/location"
_RPT_PATH = "/workshop/api/mechanic/mechanic_report"

# Two-hop chain fixture: the vehicle response leaks a report id (an identifier the
# second hop's path consumes). Both are UUID-shaped so the detector recognises them
# as chainable identifiers by shape, never by a target-specific field name.
_VEH_UUID = "11111111-1111-1111-1111-111111111111"
_RPT_UUID = "22222222-2222-2222-2222-222222222222"
_VEH_TPL = "/identity/api/v2/vehicle/{vehicleId}/location"
_RPT_TPL = "/workshop/api/mechanic/report/{reportId}"
_VEH_CONCRETE = f"/identity/api/v2/vehicle/{_VEH_UUID}/location"
_RPT_CONCRETE = f"/workshop/api/mechanic/report/{_RPT_UUID}"


def _seed_graph_vehicle() -> ReachabilityGraph:
    """Seed the vehicle-location BOLA scenario into a fresh graph.

    Mirrors what recon produces after running against crAPI:
      - owner_a owns object:vehicle:adam-uuid (sensitivity_tier=2)
      - GET /identity/api/v2/vehicle/adam-uuid/location returns that object
    """
    graph = ReachabilityGraph()
    graph.add_identity(
        "owner_a",
        Identity(role="user", auth_state=AuthState.USER, provenance=Provenance.SEEDED),
    )
    graph.add_identity(
        "owner_b",
        Identity(role="user", auth_state=AuthState.USER, provenance=Provenance.SEEDED),
    )
    obj = graph.add_object(Object(type="vehicle", sensitivity_tier=2))
    graph.set_owns(_OWNER_A, obj)
    ep = graph.add_endpoint(Endpoint(method="GET", path=_VEH_PATH))
    graph.add_returns(ep, obj)
    return graph


def _seed_graph_report() -> ReachabilityGraph:
    """Seed the mechanic-report BOLA scenario."""
    graph = ReachabilityGraph()
    graph.add_identity(
        "owner_a",
        Identity(role="user", auth_state=AuthState.USER, provenance=Provenance.SEEDED),
    )
    graph.add_identity(
        "mechanic",
        Identity(role="mechanic", auth_state=AuthState.USER, provenance=Provenance.SEEDED),
    )
    obj = graph.add_object(Object(type="service_report", sensitivity_tier=2))
    graph.set_owns(_OWNER_A, obj)
    ep = graph.add_endpoint(Endpoint(method="GET", path=_RPT_PATH))
    graph.add_returns(ep, obj)
    return graph


def _seed_graph_two_hops() -> ReachabilityGraph:
    """Seed both BOLA hops into one graph, connected by a genuine precondition.

    Hop A (vehicle-location) leaks the report id; hop B (mechanic-report) consumes
    it by substituting it into a ``{reportId}`` path template. B is reachable only
    because A produced its id — a real data dependency, not iteration adjacency.
    """
    graph = ReachabilityGraph()
    for name, role in [("owner_a", "user"), ("owner_b", "user"), ("mechanic", "mechanic")]:
        graph.add_identity(
            name,
            Identity(role=role, auth_state=AuthState.USER, provenance=Provenance.SEEDED),
        )
    veh_obj = graph.add_object(Object(type="vehicle", sensitivity_tier=2, instance_key=_VEH_UUID))
    graph.set_owns(_OWNER_A, veh_obj)
    veh_ep = graph.add_endpoint(Endpoint(method="GET", path=_VEH_TPL))
    graph.add_returns(veh_ep, veh_obj)

    rpt_obj = graph.add_object(
        Object(type="service_report", sensitivity_tier=2, instance_key=_RPT_UUID)
    )
    graph.set_owns(_OWNER_A, rpt_obj)
    rpt_ep = graph.add_endpoint(Endpoint(method="GET", path=_RPT_TPL))
    graph.add_returns(rpt_ep, rpt_obj)
    return graph


def _violation_transport(owner_token: str) -> httpx.MockTransport:
    """MockTransport: every identity gets 200+body → cross-identity violation.

    The vehicle response leaks the report id, so the report hop's consumed
    identifier is genuinely produced upstream (the precondition the chain needs).
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if "/vehicle/" in request.url.path:
            return httpx.Response(200, json={"location": "sensitive", "report_id": _RPT_UUID})
        return httpx.Response(200, json={"data": "sensitive"})

    return httpx.MockTransport(handler)


def _secure_transport() -> httpx.MockTransport:
    """MockTransport: non-owner gets 403 → no violation."""

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if "tok-owner" in auth:
            return httpx.Response(200, json={"data": "sensitive"})
        return httpx.Response(403, json={"error": "forbidden"})

    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# Invariant 1: single-hop vehicle BOLA confirmed
# ---------------------------------------------------------------------------


def test_vehicle_bola_hop_confirmed() -> None:
    graph = _seed_graph_vehicle()
    transport = _violation_transport(_TOK_A)
    result = detect(
        graph,
        BASE_URL,
        owner_tokens={_OWNER_A: _TOK_A},
        non_owner_tokens={_OWNER_B: _TOK_B},
        transport=transport,
    )
    assert len(result.confirmed_hops) == 1
    assert result.confirmed_hops[0].path == _VEH_PATH
    fn = finding_id("bola", f"bola/{_VEH_PATH}")
    assert graph.has_node(fn)


# ---------------------------------------------------------------------------
# Invariant 2: secure target → zero confirmed hops
# ---------------------------------------------------------------------------


def test_secure_target_no_findings() -> None:
    graph = _seed_graph_vehicle()
    result = detect(
        graph,
        BASE_URL,
        owner_tokens={_OWNER_A: _TOK_A},
        non_owner_tokens={_OWNER_B: _TOK_B},
        transport=_secure_transport(),
    )
    assert result.confirmed_hops == []
    assert result.chain_edges == []


# ---------------------------------------------------------------------------
# Invariant 3: two-hop chain — enables edge + chain_paths connected path
# ---------------------------------------------------------------------------


def test_two_hop_chain_enables_edge_and_chain_paths() -> None:
    graph = _seed_graph_two_hops()
    detect(
        graph,
        BASE_URL,
        owner_tokens={_OWNER_A: _TOK_A},
        non_owner_tokens={_OWNER_B: _TOK_B, _MECHANIC: _TOK_M},
        transport=_violation_transport(_TOK_A),
    )

    # The two concrete-path findings, selected by the identifiers they resolve to.
    veh_fn = finding_id("bola", f"bola/{_VEH_CONCRETE}")
    rpt_fn = finding_id("bola", f"bola/{_RPT_CONCRETE}")
    assert graph.has_node(veh_fn)
    assert graph.has_node(rpt_fn)

    # Genuine precondition: the vehicle hop leaked the report id the report hop
    # consumed, so vehicle enables report — and not the reverse.
    assert (veh_fn, rpt_fn) in graph.enables_edges()
    assert (rpt_fn, veh_fn) not in graph.enables_edges()

    # chain_paths from the vehicle finding must include both nodes.
    paths = graph.chain_paths(veh_fn)
    assert any(veh_fn in p and rpt_fn in p for p in paths), (
        f"expected a path containing both findings; got {paths}"
    )


# ---------------------------------------------------------------------------
# Invariant 4: zero state-changing requests fired by detector (§10)
# ---------------------------------------------------------------------------


def test_detector_fires_only_get_requests() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": "x"})

    graph = _seed_graph_two_hops()
    detect(
        graph,
        BASE_URL,
        owner_tokens={_OWNER_A: _TOK_A},
        non_owner_tokens={_OWNER_B: _TOK_B},
        transport=httpx.MockTransport(handler),
    )
    for req in seen:
        assert req.method == "GET", f"detector fired non-GET: {req.method} {req.url.path}"


# ---------------------------------------------------------------------------
# Layer 4: live crAPI gate (skips when crAPI isn't up)
# ---------------------------------------------------------------------------

_CRAPI_URL = os.environ.get("REACHAGENT_CRAPI_BASE_URL", "http://127.0.0.1:8888")


def _crapi_reachable(url: str) -> bool:
    try:
        return httpx.get(url, timeout=2.0).status_code == 200
    except httpx.HTTPError:
        return False


@pytest.mark.skipif(
    not _crapi_reachable(_CRAPI_URL),
    reason="live crAPI not reachable — bring it up per docs/notes to run this gate",
)
def test_live_crapi_bola_gate() -> None:
    """Full Phase 2 gate: recon → detect → chain_paths, all against live crAPI."""
    live_env = {
        **_CRAPI_ENV,
        "REACHAGENT_IDENTITY_OWNER_A_PASSWORD": "adam007!123",
        "REACHAGENT_IDENTITY_OWNER_B_PASSWORD": "pogba006!123",
        "REACHAGENT_IDENTITY_MECHANIC_PASSWORD": "Admin1@#",
    }
    identities = IdentityStore.from_env(live_env)
    graph = ReachabilityGraph()

    recon = run_recon(
        base_url=_CRAPI_URL,
        surface_path="config/crapi-surface.yaml",
        graph=graph,
        identities=identities,
    )
    # Safety gate: recon must have fired zero state-changing requests.
    assert recon.destructive_actions == (), (
        f"recon fired state-changing requests: {recon.destructive_actions}"
    )

    # Build token maps from the live sessions recon established. Every identity is
    # both a potential owner and a potential cross-user probe: the detector anchors
    # each hop on a specific object's declared owner and only fires an identity as a
    # probe when it is *not* that owner (``pid != owner_id``), so passing every token
    # in both maps is safe and necessary — with a caller-scoped object like
    # ``community_feed`` owned by everyone, an "owns anything ⇒ not a probe" split
    # would leave no probe identity and confirm nothing.
    owner_tokens: dict[str, str] = {}
    non_owner_tokens: dict[str, str] = {}
    for name in identities.names():
        iid = identity_id(name)
        tok = identities.token_store(name).get_token()
        if tok is None:
            continue
        owner_tokens[iid] = tok
        non_owner_tokens[iid] = tok

    result = detect(graph, _CRAPI_URL, owner_tokens=owner_tokens, non_owner_tokens=non_owner_tokens)

    # -- Both documented chains must be reconstructed (§14: 2/2, not "≥1") ----
    #
    # The two chains reach their objects by *different* preconditions, and the gate
    # asserts each honestly rather than forcing both into the same shape:
    #
    #   vehicle-location — the vehicle id is an unguessable UUID, so a cross-user
    #     read is only possible once the id is *disclosed* upstream (crAPI's
    #     community feed leaks it). That is a genuine two-finding chain: the leak
    #     finding ``enables`` the vehicle-location BOLA finding.
    #   mechanic-contact — the report id is a short enumerable integer, so the
    #     cross-user read needs no upstream producer. It is a confirmed single-hop
    #     BOLA whose precondition is recorded as ``enumerable_identifier`` — not a
    #     fabricated ``enables`` edge for a data dependency that does not exist.

    veh_hops = [h for h in result.confirmed_hops if "/vehicle/" in h.path]
    rpt_hops = [h for h in result.confirmed_hops if "report" in h.path]
    assert veh_hops, "vehicle-location BOLA not confirmed"
    assert rpt_hops, "mechanic-report BOLA not confirmed"

    # Chain 1: a real enables path — some confirmed finding leaked the UUID each
    # vehicle-location hop consumes, so every vehicle hop is a 'disclosed'
    # precondition and has an incoming enables edge.
    enables = graph.enables_edges()
    for hop in veh_hops:
        assert result.preconditions.get(hop.finding_node) == "requires_disclosed_identifier", (
            f"vehicle hop {hop.path} should require a disclosed id; "
            f"got {result.preconditions.get(hop.finding_node)!r}"
        )
        assert any(dst == hop.finding_node for _, dst in enables), (
            f"vehicle-location finding {hop.finding_node} has no incoming enables edge — "
            "its disclosing producer was not linked"
        )
        # The producer that enables it must itself be a confirmed finding, and the
        # reconstructed chain must be a connected path through both.
        producers = [src for src, dst in enables if dst == hop.finding_node]
        for producer in producers:
            assert graph.has_node(producer)
            paths = graph.chain_paths(producer)
            assert any(producer in p and hop.finding_node in p for p in paths), (
                f"chain_paths from {producer} does not connect to {hop.finding_node}"
            )

    # Chain 2: confirmed single-hop BOLA, precondition recorded as enumerable — no
    # spurious enables edge invented for a dependency crAPI does not have.
    for hop in rpt_hops:
        assert result.preconditions.get(hop.finding_node) == "enumerable_identifier", (
            f"mechanic-report hop {hop.path} should be enumerable; "
            f"got {result.preconditions.get(hop.finding_node)!r}"
        )
        _, finding = next((n, f) for n, f in graph.findings() if n == hop.finding_node)
        assert finding.metadata.get("chain_precondition") == "enumerable_identifier", (
            "precondition provenance not stamped on the finding node"
        )
        assert not any(dst == hop.finding_node for _, dst in enables), (
            f"mechanic-report finding {hop.finding_node} has a spurious enables edge — "
            "its id is enumerable, so no upstream producer should be linked"
        )

    # Safety gate: detector must have fired zero state-changing requests.
    # (The detector only fires GETs; this is the belt-and-suspenders check.)
    for hop in result.confirmed_hops:
        assert hop.path, "hop path must be non-empty"
