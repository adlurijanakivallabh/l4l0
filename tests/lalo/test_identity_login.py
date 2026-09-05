"""Tests for multi-scheme login and the session-mirrors-onto-the-graph invariant."""

from __future__ import annotations

import json

import httpx
import pytest

from lalo.core.errors import LoginFailedError, SessionNotMirroredError
from lalo.execution.firer import HttpFirer
from lalo.execution.scope import ScopeGuard
from lalo.execution.target import Engagement
from lalo.graph import NodeKind, ReachabilityGraph
from lalo.identity import (
    BodyEncoding,
    Credential,
    CredentialKind,
    Identity,
    LoginScheme,
    Session,
    SessionRegistry,
    SessionSource,
    login,
)

_ALICE = Identity(
    id="alice", username="alice", credential=Credential(CredentialKind.PASSWORD, "hunter2xxxxx")
)


def _firer(handler: httpx.MockTransport | None = None, *, client: httpx.Client) -> HttpFirer:
    eng = Engagement.from_specs(["app.example.com"])
    scope = ScopeGuard(engagement=eng, resolver=lambda h: frozenset({"93.184.216.34"}))
    return HttpFirer(scope, client=client)


def test_login_json_scheme_extracts_cookie_session() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body == {"username": "alice", "password": "hunter2xxxxx"}
        return httpx.Response(200, headers={"set-cookie": "session=abc123; Path=/; HttpOnly"})

    firer = _firer(client=httpx.Client(transport=httpx.MockTransport(handler)))
    scheme = LoginScheme(
        login_url="https://app.example.com/login",
        body_encoding=BodyEncoding.JSON,
        session_source=SessionSource.COOKIE,
        session_field="session",
    )
    session = login(firer, _ALICE, scheme)
    assert session.identity_id == "alice"
    assert session.kind is SessionSource.COOKIE
    assert session.value == "abc123"
    assert session.auth_header() == ("Cookie", "session=abc123")


def test_login_form_scheme_extracts_json_field_bearer_session() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["content-type"] == "application/x-www-form-urlencoded"
        return httpx.Response(200, json={"token": "tok-xyz"})

    firer = _firer(client=httpx.Client(transport=httpx.MockTransport(handler)))
    scheme = LoginScheme(
        login_url="https://app.example.com/login",
        body_encoding=BodyEncoding.FORM,
        session_source=SessionSource.JSON_FIELD,
        session_field="token",
    )
    session = login(firer, _ALICE, scheme)
    assert session.auth_header() == ("Authorization", "Bearer tok-xyz")


def test_login_header_scheme_fires_no_request() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("a static header credential must never fire a login request")

    firer = _firer(client=httpx.Client(transport=httpx.MockTransport(handler)))
    scheme = LoginScheme(session_source=SessionSource.HEADER, session_field="X-Api-Key")
    session = login(firer, _ALICE, scheme)
    assert session.auth_header() == ("X-Api-Key", "hunter2xxxxx")


def test_login_non_2xx_status_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, content=b"nope")

    firer = _firer(client=httpx.Client(transport=httpx.MockTransport(handler)))
    scheme = LoginScheme(login_url="https://app.example.com/login")
    with pytest.raises(LoginFailedError):
        login(firer, _ALICE, scheme)


def test_login_missing_session_material_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)  # no Set-Cookie at all

    firer = _firer(client=httpx.Client(transport=httpx.MockTransport(handler)))
    scheme = LoginScheme(
        login_url="https://app.example.com/login", session_source=SessionSource.COOKIE
    )
    with pytest.raises(LoginFailedError):
        login(firer, _ALICE, scheme)


def test_login_out_of_engagement_url_is_never_fired_and_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("out-of-engagement login must not fire")

    firer = _firer(client=httpx.Client(transport=httpx.MockTransport(handler)))
    scheme = LoginScheme(login_url="https://evil.example.org/login")
    with pytest.raises(LoginFailedError):
        login(firer, _ALICE, scheme)


def test_session_registry_round_trip() -> None:
    graph = ReachabilityGraph()
    registry = SessionRegistry(graph)
    session = Session(
        id="session-alice",
        identity_id="alice",
        kind=SessionSource.COOKIE,
        name="session",
        value="abc",
    )
    registry.register(session)
    assert registry.get("session-alice") == session
    assert graph.has_node("session-alice")
    assert graph.nodes_of_kind(NodeKind.SESSION) == ["session-alice"]


def test_session_registry_refuses_a_session_never_mirrored_onto_the_graph() -> None:
    graph = ReachabilityGraph()
    registry = SessionRegistry(graph)
    # Bypass register() entirely -- simulates a bug that stores a session
    # without ever writing its graph node.
    sneaky = Session(
        id="session-x", identity_id="x", kind=SessionSource.HEADER, name="X-Api-Key", value="k"
    )
    registry._sessions["session-x"] = sneaky  # noqa: SLF001 - deliberately bypassing the invariant
    with pytest.raises(SessionNotMirroredError):
        registry.get("session-x")


def test_session_registry_get_unknown_session_raises_not_mirrored() -> None:
    registry = SessionRegistry(ReachabilityGraph())
    with pytest.raises(SessionNotMirroredError):
        registry.get("never-existed")
