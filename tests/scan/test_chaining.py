"""Attack-path chaining (Build Order v2 W17): capture + spawn, hermetic.

capture_bypass_session reuses identity.login's own response parser; spawn_derived_identity
reuses IdentityStore.add/open_session and the new RequestFirer.register_identity seam. Both
fail open (return None) rather than raising — a chaining failure must never abort a scan.
"""

from __future__ import annotations

import httpx

from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import AuthState, Provenance
from reachagent.graph.store import ReachabilityGraph
from reachagent.identity.store import IdentityStore
from reachagent.scan.chaining import capture_bypass_session, spawn_derived_identity


def _fire_result(*, headers: dict[str, str] | None = None, body: bytes = b"") -> object:
    from reachagent.execution.firer import FireResult

    return FireResult(
        status_code=200,
        elapsed_seconds=0.01,
        body=body,
        headers=httpx.Headers(headers or {}),
    )


def _firer() -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(200)))
    return RequestFirer(client, ScopeGuard.from_hosts(["target.test"]))


# === capture_bypass_session ===================================================


def test_captures_real_cookie_session_material() -> None:
    result = _fire_result(headers={"set-cookie": "session=abc123; Path=/"})
    captured = capture_bypass_session(result, "")
    assert captured is not None
    assert dict(captured.cookies) == {"session": "abc123"}


def test_captures_real_bearer_token_from_json_body() -> None:
    result = _fire_result()
    captured = capture_bypass_session(result, '{"access_token": "tok-xyz"}')
    assert captured is not None
    assert captured.token == "tok-xyz"


def test_returns_none_when_nothing_reusable_was_captured() -> None:
    result = _fire_result()
    assert capture_bypass_session(result, '{"ok": true}') is None
    assert capture_bypass_session(result, "") is None


def test_returns_none_on_a_malformed_response_instead_of_raising() -> None:
    class _Weird:
        headers = object()  # no get_list/get — must not blow up the driver

    assert capture_bypass_session(_Weird(), "not json{{{") is None


# === spawn_derived_identity ====================================================


def test_spawns_a_synthetic_identity_and_registers_it_with_the_firer() -> None:
    identities = IdentityStore()
    firer = _firer()
    graph = ReachabilityGraph()
    result = _fire_result(headers={"set-cookie": "session=abc123"})
    captured = capture_bypass_session(result, "")
    assert captured is not None

    spawned = spawn_derived_identity(
        identities, firer, graph, role_hint="nosqli-bypass-principal", captured=captured
    )
    assert spawned is not None
    name, session_node = spawned

    # Real IdentityStore registration, real synthetic auth state, real provenance.
    assert name in identities.names()
    assert identities.identity(name).auth_state is AuthState.SYNTHETIC
    assert identities.identity(name).provenance is Provenance.DERIVED

    # Real graph facts.
    assert graph.has_node(f"identity:{name}")
    assert graph.has_node(session_node)

    # The firer can now actually authenticate as the derived identity.
    seen: list[httpx.Request] = []
    firer2 = RequestFirer(
        httpx.Client(
            transport=httpx.MockTransport(
                lambda r: (seen.append(r), httpx.Response(200))[1]  # noqa: B023
            )
        ),
        ScopeGuard.from_hosts(["target.test"]),
    )
    firer2.register_identity(name, identities.token_store(name))
    firer2.fire(name, "GET", "https://target.test/x", state_changing=False)
    assert "cookie" in seen[0].headers or seen[0].headers.get("Cookie") is not None


def test_spawn_fails_open_when_identities_is_not_a_real_identity_store() -> None:
    result = _fire_result(headers={"set-cookie": "session=abc123"})
    captured = capture_bypass_session(result, "")
    assert captured is not None
    spawned = spawn_derived_identity(
        None, _firer(), ReachabilityGraph(), role_hint="x", captured=captured
    )
    assert spawned is None


def test_spawn_fails_open_on_a_firer_registration_error() -> None:
    class _BrokenFirer:
        def register_identity(self, *_a: object, **_k: object) -> None:
            raise RuntimeError("boom")

    result = _fire_result(headers={"set-cookie": "session=abc123"})
    captured = capture_bypass_session(result, "")
    assert captured is not None
    spawned = spawn_derived_identity(
        IdentityStore(), _BrokenFirer(), ReachabilityGraph(), role_hint="x", captured=captured
    )
    assert spawned is None
