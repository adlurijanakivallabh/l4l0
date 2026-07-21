"""SurfaceMapper ownership extension — recon populates ``owns`` (plan §3, §6; Phase 2 Task 2).

Asserts the Task 2 DoD invariants:

  1. ``ObjectSpec``/``SurfaceSpec`` carry an ownership *discovery recipe* (not a
     static owner field), and ``discover_ownership`` writes the ``owns`` edge +
     ``owner_identity_ref`` — read back off the graph.
  2. Ownership is written from the app's *own response* after the onboarding flow
     (a session precondition), never asserted from config: before the session
     exists there is no edge; after it does, the observed 2xx reveal yields one.
  3. Ownership is never fabricated: an object with no recipe gets no ``owns`` edge
     and a ``None`` ``owner_identity_ref`` (empirical-or-absent).
  4. Named-owner reveals resolve through the app's response; an unmatched owner
     writes nothing (never a guessed owner).
  5. The mapper stays generic — no per-object/per-target branch; a grep of
     ``mapper.py`` for target-specific identifiers is clean.
  6. The Phase 1 gate is unregressed: a VAmPI-shaped surface (no ownership
     recipes) produces an unchanged graph and writes zero ``owns`` edges.

The reveal endpoint is fired through a ``MockTransport`` standing in for the
target, so the tests are hermetic but exercise the real fire → read-response →
write-edge path (same discipline as the Phase 1 surface-mapper tests).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.store import ReachabilityGraph, identity_id, object_id
from reachagent.identity import IdentityStore
from reachagent.recon import SurfaceMapper, SurfaceSpec
from reachagent.recon.mapper import OwnershipDiscovery

BASE_URL = "https://crapi.test"

# A crAPI-shaped slice: two vehicle-owning users and a mechanic, plus a
# read-only "my vehicles" reveal whose authenticated response associates a
# vehicle with the caller. Ownership is created at runtime (a session), so the
# surface declares a *recipe*, not an owner.
CRAPI_SURFACE = {
    "endpoints": [
        {
            "method": "GET",
            "path": "/identity/api/v2/vehicle/vehicles",
            "content_type": "application/json",
            "returns": [
                {
                    "type": "vehicle",
                    "sensitivity_tier": 2,
                    "ownership": {
                        "reveal_path": "/identity/api/v2/vehicle/vehicles",
                        "requires_session": True,
                    },
                }
            ],
        },
    ]
}

CRAPI_ENV = {
    "REACHAGENT_IDENTITIES": "owner_a,owner_b,mechanic",
    "REACHAGENT_IDENTITY_OWNER_A_USERNAME": "victim@crapi.test",
    "REACHAGENT_IDENTITY_OWNER_A_PASSWORD": "a-secret",
    "REACHAGENT_IDENTITY_OWNER_A_ROLE": "user",
    "REACHAGENT_IDENTITY_OWNER_B_USERNAME": "attacker@crapi.test",
    "REACHAGENT_IDENTITY_OWNER_B_PASSWORD": "b-secret",
    "REACHAGENT_IDENTITY_OWNER_B_ROLE": "user",
    "REACHAGENT_IDENTITY_MECHANIC_USERNAME": "mechanic@crapi.test",
    "REACHAGENT_IDENTITY_MECHANIC_PASSWORD": "m-secret",
    "REACHAGENT_IDENTITY_MECHANIC_ROLE": "mechanic",
}

# VAmPI-shaped surface: no ownership recipes anywhere (the Phase 1 world).
VAMPI_SURFACE = {
    "endpoints": [
        {
            "method": "GET",
            "path": "/",
            "content_type": "application/json",
            "returns": [{"type": "status_message", "sensitivity_tier": 0}],
        },
        {
            "method": "GET",
            "path": "/users/v1/_debug",
            "content_type": "application/json",
            "returns": [{"type": "user_credentials", "sensitivity_tier": 3}],
        },
    ]
}

VAMPI_ENV = {
    "REACHAGENT_IDENTITIES": "user_a,admin",
    "REACHAGENT_IDENTITY_USER_A_USERNAME": "alice",
    "REACHAGENT_IDENTITY_USER_A_PASSWORD": "alice-secret",
    "REACHAGENT_IDENTITY_USER_A_ROLE": "user",
    "REACHAGENT_IDENTITY_ADMIN_USERNAME": "root",
    "REACHAGENT_IDENTITY_ADMIN_PASSWORD": "root-secret",
    "REACHAGENT_IDENTITY_ADMIN_ROLE": "admin",
}


@pytest.fixture
def crapi_identities() -> IdentityStore:
    return IdentityStore.from_env(CRAPI_ENV)


def _mapper(
    graph: ReachabilityGraph,
    identities: IdentityStore,
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    base_url: str = BASE_URL,
    host: str = "crapi.test",
) -> SurfaceMapper:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = RequestFirer(client, ScopeGuard.from_hosts([host]))
    return SurfaceMapper(graph, firer, identities, base_url)


# -- Invariant 1: the recipe parses and is not a static owner field -------


def test_ownership_recipe_parses_from_surface() -> None:
    spec = SurfaceSpec.from_mapping(CRAPI_SURFACE)
    (obj,) = spec.endpoints[0].returns
    assert isinstance(obj.ownership, OwnershipDiscovery)
    assert obj.ownership.reveal_path == "/identity/api/v2/vehicle/vehicles"
    assert obj.ownership.requires_session is True
    # Caller-scoped: no owner is named in config, it's read from the response.
    assert obj.ownership.owner_field is None


def test_ownership_recipe_rejects_a_state_changing_reveal() -> None:
    # A reveal must be read-only — a mutating "reveal" would break read-only-first
    # the instant discovery ran (§10).
    with pytest.raises(ValueError, match="read-only"):
        OwnershipDiscovery(reveal_path="/x", reveal_method="POST")


# -- Invariant 2: edge is written from the observed response, after a session --


def test_owns_edge_written_from_response_only_after_onboarding(
    crapi_identities: IdentityStore,
) -> None:
    # The reveal returns 200 only to a caller carrying a bearer token — modelling
    # crAPI's "my vehicles" endpoint, which needs the onboarding session.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("Authorization", "").startswith("Bearer "):
            return httpx.Response(200, json=[{"vin": "1HGCM82633A004352"}])
        return httpx.Response(401, text="unauthorized")

    spec = SurfaceSpec.from_mapping(CRAPI_SURFACE)
    graph = ReachabilityGraph()
    mapper = _mapper(graph, crapi_identities, handler)

    # Onboarding: owner_a establishes a session (the workflow step). owner_b and
    # mechanic do not, so ownership can only be read for owner_a.
    crapi_identities.open_session("owner_a", "owner-a-token")

    summary = mapper.run(spec)

    vehicle = object_id("vehicle")
    # The edge exists for owner_a, written from the observed 2xx — not config.
    assert graph.owner_of(vehicle) == identity_id("owner_a")
    assert (identity_id("owner_a"), vehicle) in graph.owns_edges()
    # Exactly one owns edge was discovered; the two session-less identities were
    # skipped as "not onboarded yet", never guessed.
    assert summary.owns_discovered == 1
    assert summary.owns_skipped_no_session == 2


def test_no_session_means_no_owns_edge(crapi_identities: IdentityStore) -> None:
    # Nobody onboards. requires_session holds, so discovery reads nothing and
    # writes nothing — empirical-or-absent before the workflow step.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"vin": "x"}])

    spec = SurfaceSpec.from_mapping(CRAPI_SURFACE)
    graph = ReachabilityGraph()
    mapper = _mapper(graph, crapi_identities, handler)

    summary = mapper.run(spec)

    assert graph.owns_edges() == []
    assert graph.owner_of(object_id("vehicle")) is None
    assert summary.owns_discovered == 0
    assert summary.owns_skipped_no_session == 3


def test_owns_not_written_when_reveal_is_refused(crapi_identities: IdentityStore) -> None:
    # The identity has a session but the reveal returns 403 — no association to
    # read, so no edge (a served-and-associated reveal is the only trigger).
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    spec = SurfaceSpec.from_mapping(CRAPI_SURFACE)
    graph = ReachabilityGraph()
    mapper = _mapper(graph, crapi_identities, handler)
    crapi_identities.open_session("owner_a", "owner-a-token")

    summary = mapper.run(spec)

    assert graph.owns_edges() == []
    assert summary.owns_discovered == 0
    assert summary.owns_skipped_unresolved == 1


def test_caller_scoped_empty_reveal_writes_no_edge(crapi_identities: IdentityStore) -> None:
    # Regression (caught live against crAPI, Task 6): a caller-scoped reveal that
    # returns 200 with an *empty* body is no association — a caller with no
    # resource must not be attributed ownership. Only a non-empty reveal does.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])  # 2xx, but the caller owns nothing

    spec = SurfaceSpec.from_mapping(CRAPI_SURFACE)
    graph = ReachabilityGraph()
    mapper = _mapper(graph, crapi_identities, handler)
    crapi_identities.open_session("owner_a", "owner-a-token")

    summary = mapper.run(spec)

    assert graph.owns_edges() == []
    assert graph.owner_of(object_id("vehicle")) is None
    assert summary.owns_discovered == 0
    # A served-but-empty reveal is unresolved, not "no session" (the session exists).
    assert summary.owns_skipped_unresolved == 1


# -- Invariant 4: named-owner reveal resolves through the response --------


def test_named_owner_field_resolves_to_seeded_identity(
    crapi_identities: IdentityStore,
) -> None:
    # A reveal that *names* the owner in a JSON field (e.g. an admin-visible
    # listing). The value is matched to a seeded identity's username — read from
    # the response, never asserted.
    surface = {
        "endpoints": [
            {
                "method": "GET",
                "path": "/reports",
                "returns": [
                    {
                        "type": "service_report",
                        "ownership": {
                            "reveal_path": "/reports",
                            "owner_field": "owner_email",
                            "requires_session": True,
                        },
                    }
                ],
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"owner_email": "victim@crapi.test"})

    spec = SurfaceSpec.from_mapping(surface)
    graph = ReachabilityGraph()
    mapper = _mapper(graph, crapi_identities, handler)
    crapi_identities.open_session("mechanic", "mechanic-token")

    mapper.run(spec)

    # The response named victim@crapi.test → owner_a, regardless of which identity
    # fired the reveal — the owner is read from the body, not the caller.
    assert graph.owner_of(object_id("service_report")) == identity_id("owner_a")


def test_unmatched_named_owner_writes_no_edge(crapi_identities: IdentityStore) -> None:
    # The reveal names an owner that matches no seeded identity — never guess.
    surface = {
        "endpoints": [
            {
                "method": "GET",
                "path": "/reports",
                "returns": [
                    {
                        "type": "service_report",
                        "ownership": {
                            "reveal_path": "/reports",
                            "owner_field": "owner_email",
                            "requires_session": True,
                        },
                    }
                ],
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"owner_email": "stranger@example.com"})

    spec = SurfaceSpec.from_mapping(surface)
    graph = ReachabilityGraph()
    mapper = _mapper(graph, crapi_identities, handler)
    crapi_identities.open_session("owner_a", "t")

    summary = mapper.run(spec)

    assert graph.owns_edges() == []
    assert summary.owns_skipped_unresolved == 1


# -- Invariant 3: no recipe → no edge (empirical-or-absent) ---------------


def test_object_without_recipe_gets_no_owns_edge(crapi_identities: IdentityStore) -> None:
    surface = {
        "endpoints": [
            {
                "method": "GET",
                "path": "/public",
                "returns": [{"type": "brochure", "sensitivity_tier": 0}],
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"anything": True})

    spec = SurfaceSpec.from_mapping(surface)
    graph = ReachabilityGraph()
    mapper = _mapper(graph, crapi_identities, handler)
    crapi_identities.open_session("owner_a", "t")

    mapper.run(spec)

    assert graph.has_node(object_id("brochure"))
    assert graph.owner_of(object_id("brochure")) is None
    assert graph.owns_edges() == []


# -- Invariant 5: the mapper stays generic (no per-target branch) ---------


def test_mapper_has_no_target_specific_identifiers() -> None:
    # The generic-mapper invariant (Phase 1 Task 3, carried into Task 2): no
    # per-object or per-target branch. A grep for target names must be clean.
    source = Path("src/reachagent/recon/mapper.py").read_text(encoding="utf-8")
    lowered = source.lower()
    for needle in ("crapi", "vampi", "vehicle", "mechanic", "victim", "attacker"):
        assert needle not in lowered, f"mapper.py leaked a target-specific identifier: {needle!r}"


# -- Invariant 6: Phase 1 (VAmPI) is unregressed --------------------------


def test_vampi_surface_writes_zero_owns_edges() -> None:
    # A VAmPI-shaped surface declares no ownership recipes, so the ownership pass
    # is a no-op: zero owns edges, and the discovery counters stay zero. The
    # structural + can_call graph is exactly what Phase 1 produced.
    identities = IdentityStore.from_env(VAMPI_ENV)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    spec = SurfaceSpec.from_mapping(VAMPI_SURFACE)
    graph = ReachabilityGraph()
    mapper = _mapper(graph, identities, handler, base_url="https://vampi.test", host="vampi.test")

    summary = mapper.run(spec)

    assert graph.owns_edges() == []
    assert summary.owns_discovered == 0
    assert summary.owns_skipped_no_session == 0
    assert summary.owns_skipped_unresolved == 0
    # Structure is still there — ownership is purely additive.
    assert graph.has_node(object_id("user_credentials"))
    assert summary.objects == 2
