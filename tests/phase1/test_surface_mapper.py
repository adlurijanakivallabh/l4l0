"""Recon / surface mapper (plan §3, §6; docs/phase1-tasks.md Task 3).

Asserts the two DoD invariants:
  1. every endpoint, parameter, and object is represented as
     ``Endpoint``/``Parameter``/``Object`` nodes with ``accepts``/``returns``
     edges;
  2. ``can_call`` edges are written per identity, carrying a
     ``confirmed_allowed``/``confirmed_denied`` status set *empirically* from an
     actual response — never assumed.

The mapper fires through Task 1's :class:`RequestFirer`; here that firer is wired
to an ``httpx.MockTransport`` standing in for VAmPI, so the tests are hermetic
but exercise the real fire → classify → write-edge path. Pointing the same firer
at a live VAmPI is the only change for an integration run.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import FindingStatus
from reachagent.graph.store import (
    ReachabilityGraph,
    endpoint_id,
    identity_id,
    object_id,
    parameter_id,
)
from reachagent.identity import IdentityStore
from reachagent.recon import SurfaceMapper, SurfaceSpec, classify_can_call

BASE_URL = "https://vampi.test"

# A representative VAmPI-shaped slice: a public root, an admin-sensitive debug
# dump, a templated per-user lookup, and a state-changing DELETE (must never
# fire during recon).
SURFACE = {
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
        {
            "method": "GET",
            "path": "/users/v1/{username}",
            "content_type": "application/json",
            "parameters": [{"name": "username", "location": "path"}],
            "returns": [{"type": "user", "sensitivity_tier": 2}],
            "sample_path_values": {"username": "alice"},
        },
        {
            "method": "GET",
            "path": "/createdb",
            "state_changing": True,
        },
        {
            "method": "DELETE",
            "path": "/users/v1/{username}",
            "state_changing": True,
            "parameters": [{"name": "username", "location": "path"}],
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
def spec() -> SurfaceSpec:
    return SurfaceSpec.from_mapping(SURFACE)


@pytest.fixture
def identities() -> IdentityStore:
    return IdentityStore.from_env(VAMPI_ENV)


def _mapper(
    graph: ReachabilityGraph,
    identities: IdentityStore,
    handler: Callable[[httpx.Request], httpx.Response],
    calls: list[httpx.Request] | None = None,
) -> SurfaceMapper:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = RequestFirer(client, ScopeGuard.from_hosts(["vampi.test"]))
    return SurfaceMapper(graph, firer, identities, BASE_URL)


# -- Invariant 1: full structural materialization -------------------------


def test_every_endpoint_parameter_object_is_a_node_with_edges(
    spec: SurfaceSpec, identities: IdentityStore
) -> None:
    graph = ReachabilityGraph()
    mapper = _mapper(graph, identities, lambda r: httpx.Response(200, text="ok"))
    mapper.map_structure(spec)

    # Every endpoint node exists — including the state-changing ones, which are
    # materialized structurally even though recon never fires them.
    for method, path in [
        ("GET", "/"),
        ("GET", "/users/v1/_debug"),
        ("GET", "/users/v1/{username}"),
        ("GET", "/createdb"),
        ("DELETE", "/users/v1/{username}"),
    ]:
        assert graph.has_node(endpoint_id(method, path))

    # Parameters materialize as nodes reachable by an accepts edge.
    get_user = endpoint_id("GET", "/users/v1/{username}")
    param_names = {p.name for _, p in graph.parameters_of(get_user)}
    assert param_names == {"username"}
    assert graph.has_node(parameter_id(get_user, "path", "username"))

    # Objects materialize and are reachable by a returns edge.
    assert graph.has_node(object_id("user_credentials"))
    assert graph.has_node(object_id("user"))
    assert graph.has_node(object_id("status_message"))


# -- Invariant 2: can_call is empirical, never assumed --------------------


def test_can_call_status_comes_from_the_observed_response(
    spec: SurfaceSpec, identities: IdentityStore
) -> None:
    # VAmPI-like authorization: the admin debug dump is 200 for everyone in this
    # toggle-on scenario; the per-user lookup is allowed. Root path is public.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/users/v1/_debug":
            return httpx.Response(200, json={"users": []})
        return httpx.Response(200, text="ok")

    graph = ReachabilityGraph()
    mapper = _mapper(graph, identities, handler)
    mapper.run(spec)

    debug = endpoint_id("GET", "/users/v1/_debug")
    # A can_call edge exists per identity, and its status is confirmed_allowed
    # because the *response* said 200 — not because we defaulted it.
    for name in ("user_a", "admin"):
        status = graph.can_call_status(identity_id(name), debug)
        assert status is FindingStatus.CONFIRMED_ALLOWED


def test_denied_response_yields_confirmed_denied(
    spec: SurfaceSpec, identities: IdentityStore
) -> None:
    # The debug dump is 403 for the regular user, 200 for admin — the mapper must
    # record two *different* empirical verdicts on the same endpoint.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/users/v1/_debug":
            token = request.headers.get("Authorization", "")
            if "root-secret-token" in token:
                return httpx.Response(200, json={"users": []})
            return httpx.Response(403, text="forbidden")
        return httpx.Response(200, text="ok")

    identities.open_session("admin", "root-secret-token")
    graph = ReachabilityGraph()
    mapper = _mapper(graph, identities, handler)
    mapper.run(spec)

    debug = endpoint_id("GET", "/users/v1/_debug")
    assert graph.can_call_status(identity_id("admin"), debug) is FindingStatus.CONFIRMED_ALLOWED
    assert graph.can_call_status(identity_id("user_a"), debug) is FindingStatus.CONFIRMED_DENIED


def test_state_changing_endpoints_are_never_probed(
    spec: SurfaceSpec, identities: IdentityStore
) -> None:
    # Record every request the transport actually receives — a state-changing
    # endpoint reaching it would be a read-only-first violation.
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="ok")

    graph = ReachabilityGraph()
    mapper = _mapper(graph, identities, handler)
    summary = mapper.run(spec)

    # GET /createdb and DELETE /users/v1/{username} are state-changing: no packet.
    assert all(req.url.path != "/createdb" for req in seen)
    assert all(req.method != "DELETE" for req in seen)

    # And no can_call edge was invented for them, for any identity.
    createdb = endpoint_id("GET", "/createdb")
    delete_user = endpoint_id("DELETE", "/users/v1/{username}")
    for name in ("user_a", "admin"):
        assert graph.can_call_status(identity_id(name), createdb) is None
        assert graph.can_call_status(identity_id(name), delete_user) is None

    # The summary counts them as skipped, not probed.
    assert summary.can_call_skipped_state_changing == 2


def test_untemplated_path_without_sample_value_is_not_probed(
    identities: IdentityStore,
) -> None:
    # A templated read-only endpoint with no sample value can't be fired into a
    # real URL, so the mapper must skip it rather than invent a can_call status.
    surface = SurfaceSpec.from_mapping(
        {
            "endpoints": [
                {
                    "method": "GET",
                    "path": "/books/v1/{book_title}",
                    "parameters": [{"name": "book_title", "location": "path"}],
                }
            ]
        }
    )
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="ok")

    graph = ReachabilityGraph()
    mapper = _mapper(graph, identities, handler)
    summary = mapper.run(surface)

    assert seen == []  # nothing fired
    assert summary.can_call_skipped_untemplated == 1
    endpoint = endpoint_id("GET", "/books/v1/{book_title}")
    assert graph.can_call_status(identity_id("user_a"), endpoint) is None


def test_no_can_call_edge_when_request_is_out_of_scope(
    spec: SurfaceSpec, identities: IdentityStore
) -> None:
    # A mapper whose base_url is outside the scope allowlist must produce zero
    # can_call edges — the scope gate refuses every probe before any I/O, and an
    # unfired probe never becomes a confirmed verdict.
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("scope gate should have refused before any I/O")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = RequestFirer(client, ScopeGuard.from_hosts(["in-scope.test"]))
    mapper = SurfaceMapper(graph := ReachabilityGraph(), firer, identities, BASE_URL)
    mapper.run(spec)

    assert graph.can_call_edges() == []


# -- classify_can_call is a pure, deterministic status map ----------------


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (200, FindingStatus.CONFIRMED_ALLOWED),
        (204, FindingStatus.CONFIRMED_ALLOWED),
        (401, FindingStatus.CONFIRMED_DENIED),
        (403, FindingStatus.CONFIRMED_DENIED),
        (404, FindingStatus.INCONCLUSIVE),
        (500, FindingStatus.INCONCLUSIVE),
        (302, FindingStatus.INCONCLUSIVE),
    ],
)
def test_classify_can_call_is_deterministic(code: int, expected: FindingStatus) -> None:
    assert classify_can_call(code) is expected
