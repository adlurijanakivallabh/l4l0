"""crAPI recon — surface, identities, ownership discovery, stateful safety (Phase 2 Task 6).

Asserts the Task 6 DoD invariants (plan §3, §6, §10, §14):

  1. crAPI's surface is a declarative inventory (``config/crapi-surface.yaml``,
     same shape as the VAmPI one), and the two documented BOLA flows materialize
     as ``Endpoint``/``Parameter``/``Object`` nodes with ``accepts``/``returns``.
  2. ≥2 crAPI identities across the role hierarchy (two vehicle-owning users + a
     mechanic) seed from env/secret store, never hardcoded, each isolated.
  3. ``owns`` edges reflect crAPI's ownership discovered at runtime (Task 2's
     recipe), and a caller with *no* resource (empty reveal) gets no edge.
  4. Stateful safety: recon fires only read-only probes; state-changing endpoints
     are materialized but never fired; the audit log shows zero destructive side
     effects (the precondition for the Task 7 gate's second clause).

Layers 1–4 are hermetic (a ``MockTransport`` stands in for crAPI). Layer 5 is a
live integration run that skips cleanly when crAPI isn't reachable, mirroring the
Phase 1 VAmPI live gate.
"""

from __future__ import annotations

import os
from collections.abc import Callable

import httpx
import pytest

from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.store import (
    ReachabilityGraph,
    endpoint_id,
    identity_id,
    object_id,
)
from reachagent.identity import IdentityStore
from reachagent.recon import SurfaceMapper, SurfaceSpec
from reachagent.recon.crapi_recon import run_recon

_SURFACE_PATH = "config/crapi-surface.yaml"
BASE_URL = "https://crapi.test"

# Seed identities across crAPI's role hierarchy (never hardcoded in the module
# under test — this is test config, mirroring the VAmPI test env).
CRAPI_ENV = {
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

# A vehicle as crAPI's /vehicles reveal returns it (caller-scoped, non-empty).
_ADAM_VEHICLE = [{"uuid": "adam-uuid", "vin": "VINADAM", "model": "Coupe"}]


@pytest.fixture
def identities() -> IdentityStore:
    return IdentityStore.from_env(CRAPI_ENV)


@pytest.fixture
def surface() -> SurfaceSpec:
    return SurfaceSpec.from_file(_SURFACE_PATH)


def _mapper(
    graph: ReachabilityGraph,
    identities: IdentityStore,
    handler: Callable[[httpx.Request], httpx.Response],
) -> tuple[SurfaceMapper, AuditLog]:
    audit = AuditLog()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = RequestFirer(client, ScopeGuard.from_hosts(["crapi.test"]), audit)
    return SurfaceMapper(graph, firer, identities, BASE_URL), audit


# -- Invariant 1: the two BOLA flows materialize structurally --------------


def test_bola_flow_endpoints_materialize_as_nodes(
    surface: SurfaceSpec, identities: IdentityStore
) -> None:
    graph = ReachabilityGraph()
    mapper, _ = _mapper(graph, identities, lambda r: httpx.Response(200, json=[]))
    mapper.map_structure(surface)

    # Vehicle-location flow.
    assert graph.has_node(endpoint_id("GET", "/identity/api/v2/vehicle/vehicles"))
    assert graph.has_node(endpoint_id("GET", "/identity/api/v2/vehicle/{vehicleId}/location"))
    assert graph.has_node(object_id("vehicle"))
    assert graph.has_node(object_id("vehicle_location"))
    # Mechanic-contact flow.
    assert graph.has_node(endpoint_id("GET", "/workshop/api/mechanic/mechanic_report"))
    assert graph.has_node(endpoint_id("POST", "/workshop/api/merchant/contact_mechanic"))
    assert graph.has_node(object_id("service_report"))


def test_surface_file_matches_the_vampi_shape(surface: SurfaceSpec) -> None:
    # Same declarative schema as VAmPI — proves the config, not mapper code,
    # carries the target specifics (the generic-mapper invariant).
    assert len(surface.endpoints) == 9
    veh = next(o for ep in surface.endpoints for o in ep.returns if o.type == "vehicle")
    assert veh.ownership is not None
    assert veh.ownership.reveal_path == "/identity/api/v2/vehicle/vehicles"
    assert veh.ownership.owner_field is None  # caller-scoped


# -- Invariant 2: identities across the role hierarchy, isolated -----------


def test_three_identities_across_role_hierarchy(identities: IdentityStore) -> None:
    assert set(identities.names()) == {"owner_a", "owner_b", "mechanic"}
    assert identities.identity("mechanic").role == "mechanic"
    # Isolated token stores: a token set on one never appears under another.
    identities.open_session("owner_a", "tok-a")
    assert identities.token_store("owner_a").get_token() == "tok-a"
    assert identities.token_store("owner_b").get_token() is None
    assert identities.token_store("mechanic").get_token() is None


# -- Invariant 3: owns reflects runtime ownership; empty reveal → no edge ---


def test_owns_written_only_for_a_caller_with_a_vehicle(
    surface: SurfaceSpec, identities: IdentityStore
) -> None:
    # /vehicles returns a vehicle to owner_a, an empty list to everyone else —
    # exactly crAPI's behaviour (only the vehicle's owner sees it there).
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/identity/api/v2/vehicle/vehicles":
            token = request.headers.get("Authorization", "")
            if "tok-owner-a" in token:
                return httpx.Response(200, json=_ADAM_VEHICLE)
            return httpx.Response(200, json=[])  # 2xx but no resource
        # Every other caller-scoped reveal (community feed, service requests) is
        # empty here, so this test stays focused on the single vehicle edge.
        return httpx.Response(200, json=[])

    graph = ReachabilityGraph()
    mapper, _ = _mapper(graph, identities, handler)
    # All three onboard (have sessions); only owner_a actually owns a vehicle.
    identities.open_session("owner_a", "tok-owner-a")
    identities.open_session("owner_b", "tok-owner-b")
    identities.open_session("mechanic", "tok-mechanic")

    summary = mapper.run(surface)

    # Exactly one owns edge — for owner_a, to the *per-instance* node keyed by the
    # vehicle's uuid (Task 7). The empty 2xx reveals for owner_b and the mechanic
    # are *no association*, not ownership (the live-caught bug).
    assert graph.owns_edges() == [(identity_id("owner_a"), object_id("vehicle", "adam-uuid"))]
    assert graph.owner_of(object_id("vehicle", "adam-uuid")) == identity_id("owner_a")
    assert summary.owns_discovered == 1


def test_no_session_means_no_owns_edge(surface: SurfaceSpec, identities: IdentityStore) -> None:
    # Nobody onboards → requires_session skips every identity → no edge.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ADAM_VEHICLE)

    graph = ReachabilityGraph()
    mapper, _ = _mapper(graph, identities, handler)

    summary = mapper.run(surface)

    assert graph.owns_edges() == []
    assert summary.owns_discovered == 0
    # Three session-gated ownership recipes (vehicle, service_report, community
    # feed) × three identities with no session → nine skips, no edges.
    assert summary.owns_skipped_no_session == 9


# -- Invariant 4: stateful safety — zero destructive side effects ----------


def test_recon_never_fires_a_state_changing_crapi_endpoint(
    surface: SurfaceSpec, identities: IdentityStore
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=[])

    graph = ReachabilityGraph()
    mapper, audit = _mapper(graph, identities, handler)
    identities.open_session("owner_a", "tok-owner-a")
    mapper.run(surface)

    # The signup/login/contact-mechanic POSTs must never have reached the wire.
    for req in seen:
        assert req.method == "GET", f"recon fired a non-GET: {req.method} {req.url.path}"
    # And the audit log records no fired state-changing request.
    destructive = [e for e in audit.entries if e.outcome.startswith("fired:") and e.method != "GET"]
    assert destructive == []


def test_state_changing_endpoints_are_materialized_but_unprobed(
    surface: SurfaceSpec, identities: IdentityStore
) -> None:
    graph = ReachabilityGraph()
    mapper, _ = _mapper(graph, identities, lambda r: httpx.Response(200, json=[]))
    summary = mapper.run(surface)

    # signup, login, contact_mechanic — three state-changing endpoints, all
    # present as nodes but none probed.
    assert graph.has_node(endpoint_id("POST", "/identity/api/auth/login"))
    assert summary.can_call_skipped_state_changing == 3
    login = endpoint_id("POST", "/identity/api/auth/login")
    for name in identities.names():
        assert graph.can_call_status(identity_id(name), login) is None


# -- Layer 5: live crAPI recon (skips cleanly when crAPI isn't up) ---------

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
def test_live_crapi_recon() -> None:
    # The seed passwords crAPI ships with (see config/crapi-identities.example.yaml).
    live_env = {
        **CRAPI_ENV,
        "REACHAGENT_IDENTITY_OWNER_A_PASSWORD": "adam007!123",
        "REACHAGENT_IDENTITY_OWNER_B_PASSWORD": "pogba006!123",
        "REACHAGENT_IDENTITY_MECHANIC_PASSWORD": "Admin1@#",
    }
    graph = ReachabilityGraph()
    result = run_recon(
        base_url=_CRAPI_URL,
        surface_path=_SURFACE_PATH,
        graph=graph,
        identities=IdentityStore.from_env(live_env),
    )

    # Both vehicle-owning users onboarded and each owns a vehicle. Ownership
    # discovery also writes the caller-scoped community_feed (owned by every
    # authenticated caller) and the mechanic's service reports — all read from the
    # app's own responses, never asserted. This test scopes to the *vehicle* facts.
    edges = graph.owns_edges()
    vehicle_edges = [(src, dst) for src, dst in edges if dst.startswith("object:vehicle:")]
    vehicle_owners = {src for src, _ in vehicle_edges}
    assert identity_id("owner_a") in vehicle_owners
    assert identity_id("owner_b") in vehicle_owners
    # The mechanic account owns no *vehicle* (it may own service reports / the
    # caller-scoped feed, which are separate object types).
    assert identity_id("mechanic") not in vehicle_owners
    # Task 7: the two owners' vehicles are *distinct* per-instance nodes (keyed by
    # uuid), each owned by exactly its owner — the object:vehicle collapse is gone.
    owned_vehicle_nodes = {dst for _, dst in vehicle_edges}
    assert len(owned_vehicle_nodes) == 2, "each owner's vehicle must be its own instance node"
    for src, dst in vehicle_edges:
        assert graph.owner_of(dst) == src
    # The safety gate the Task 7 run depends on: zero destructive side effects.
    assert result.destructive_actions == ()
