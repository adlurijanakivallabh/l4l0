"""Phase 3 identity/session safety and login coverage."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.chain_solver import ChainSolver
from reachagent.graph.nodes import Endpoint, Parameter, Protocol
from reachagent.graph.persistence import dump_graph
from reachagent.graph.store import ReachabilityGraph
from reachagent.identity.login import (
    DetectedLoginForm,
    LoginError,
    authenticate_identity,
    detect_login_forms,
    discover_oidc,
    submit_login,
)
from reachagent.identity.store import Credential, IdentityStore, SessionMaterial
from reachagent.payloads import PayloadLibrary


class _Result:
    def __init__(self, status: int, body: str = "", headers: dict[str, str] | None = None) -> None:
        self.status_code = status
        self.body = body.encode()
        self.headers = headers or {}


class _FakeFirer:
    def __init__(self, responses: dict[str, _Result]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, str, dict[str, object]]] = []

    def fire(self, identity: str, method: str, url: str, **kwargs: object) -> _Result:
        self.calls.append((identity, method, url, kwargs))
        matches = [
            (len(marker), result) for marker, result in self.responses.items() if marker in url
        ]
        if matches:
            return max(matches, key=lambda item: item[0])[1]
        return _Result(404, "not found")


def _store() -> IdentityStore:
    store = IdentityStore()
    store.add(Credential("owner", "alice", "password-one", "user"))
    store.add(Credential("other", "bob", "password-two", "user"))
    return store


def test_dynamic_html_login_binds_opaque_session_and_cookie() -> None:
    html = (
        '<form action="/not-the-login-path" method="post">'
        '<input name="email"><input type="password" name="passcode">'
        '<input type="hidden" name="csrf" value="csrf-secret"></form>'
    )
    firer = _FakeFirer(
        {
            "/not-the-login-path": _Result(
                200, "ok", {"set-cookie": "sid=session-secret; HttpOnly"}
            ),
            "http://target.test": _Result(200, html),
        }
    )
    store = _store()
    session_ref = authenticate_identity(firer, store, "owner", "http://target.test")
    assert session_ref == "token:owner"
    assert store.auth_headers("owner") == {"Cookie": "sid=session-secret"}
    assert store.auth_headers("other") == {}
    assert "session-secret" not in repr(store.token_store("owner"))
    assert "csrf-secret" not in repr(
        DetectedLoginForm(url="http://target.test/login?token=csrf-secret", kind="html_form")
    )
    assert "csrf-secret" not in repr(
        next(item for item in firer.calls if item[2].endswith("login-path"))[:3]
    )


def test_session_capture_accepts_case_insensitive_bearer_header() -> None:
    form = DetectedLoginForm(url="https://target.test/auth", kind="json_api")
    captured = submit_login(
        _FakeFirer({"/auth": _Result(200, "ok", {"Authorization": "Token bearer-secret"})}),
        "owner",
        form,
        "alice",
        "password-one",
    )
    assert captured.token == "bearer-secret"
    assert captured.token_type == "Token"


def test_graphql_login_shape_is_detected_and_serialized_as_json() -> None:
    graph = ReachabilityGraph()
    graph.add_endpoint(
        Endpoint(
            method="POST",
            path="/api/graphql",
            protocol=Protocol.GRAPHQL,
            request_body=(
                "mutation SignIn($email: String!, $password: String!) { "
                "signIn(email: $email, password: $password) { access_token } }"
            ),
        )
    )
    assert "$password" in graph.endpoint("endpoint:POST /api/graphql").request_body
    firer = _FakeFirer({"http://target.test": _Result(404), "/api/graphql": _Result(404)})
    forms = detect_login_forms(firer, "http://target.test", "owner", graph=graph)
    form = next(item for item in forms if item.kind == "graphql")
    assert form.graphql_operation == "signIn"
    assert form.url == "http://target.test/api/graphql"
    assert form.username_field == "email"

    submitter = _FakeFirer(
        {"/api/graphql": _Result(200, '{"data":{"signIn":{"access_token":"bearer-secret"}}}')}
    )
    captured = submit_login(submitter, "owner", form, "alice", "password-one")
    assert captured.token == "bearer-secret"
    payload = submitter.calls[-1][3]["json"]
    assert payload["query"].startswith("mutation")  # type: ignore[index]
    assert "password-one" in json.dumps(payload)  # secret exists only in the outbound request


def test_oidc_discovery_is_read_only_and_secret_free() -> None:
    firer = _FakeFirer(
        {
            "openid-configuration": _Result(
                200,
                json.dumps(
                    {
                        "issuer": "https://issuer.test",
                        "authorization_endpoint": "https://issuer.test/authorize",
                        "token_endpoint": "https://issuer.test/token",
                        "scopes_supported": ["openid", "profile"],
                    }
                ),
            )
        }
    )
    discovery = discover_oidc(firer, "https://target.test", "owner")
    assert discovery is not None
    assert discovery.token_endpoint == "https://issuer.test/token"
    assert all(method == "GET" for _, method, _, _ in firer.calls)


def test_expired_bearer_refreshes_in_memory_and_is_identity_scoped() -> None:
    store = _store()
    token_store = store.token_store("owner")
    token_store.set_material(
        SessionMaterial(
            token="old-secret",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
            refresh_token="refresh-secret",
        )
    )
    token_store.set_refresh_callback(
        lambda refresh: SessionMaterial(
            token="new-secret", expires_at=datetime.now(UTC) + timedelta(minutes=5)
        )
    )
    assert store.auth_headers("owner") == {"Authorization": "Bearer new-secret"}
    assert store.auth_headers("other") == {}
    assert "old-secret" not in repr(token_store)
    assert (
        token_store.safe_summary()["has_refresh"] is False
    )  # refreshed material no longer exposes refresh state


def test_request_firer_uses_live_cookie_or_bearer_store_without_audit_leak() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="ok")

    store = _store()
    store.open_session("owner", "cookie-secret", kind="cookie", cookies={"sid": "cookie-secret"})
    store.open_session("other", "bearer-secret", kind="bearer")
    audit = AuditLog()
    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(handler)),
        ScopeGuard.from_hosts(["target.test"]),
        audit,
        identity_stores=store,
    )
    firer.fire("owner", "GET", "https://target.test/account")
    firer.fire("other", "GET", "https://target.test/account")
    assert seen[0].headers["Cookie"] == "sid=cookie-secret"
    assert seen[1].headers["Authorization"] == "Bearer bearer-secret"
    audit_text = repr(audit.entries)
    assert "cookie-secret" not in audit_text and "bearer-secret" not in audit_text


def test_graph_and_model_facing_state_contains_only_session_ref(tmp_path) -> None:
    store = _store()
    session = store.open_session("owner", "graph-secret", kind="bearer")
    graph = ReachabilityGraph()
    graph.add_identity("owner", store.identity("owner"))
    graph.add_session(session)
    path = tmp_path / "state.json"
    dump_graph(graph, ChainSolver(graph), AuditLog(), path)
    text = path.read_text(encoding="utf-8")
    assert "token:owner" in text
    assert "graph-secret" not in text
    assert "password-one" not in text
    from reachagent.scan.entrypoint import _recon_state_snapshot

    model_state = _recon_state_snapshot(graph, AuditLog(), "https://target.test", "url", (), ())
    assert "graph-secret" not in json.dumps(model_state)
    assert "password-one" not in json.dumps(model_state)


def test_graph_examples_redact_auth_fields() -> None:
    graph = ReachabilityGraph()
    endpoint = graph.add_endpoint(
        Endpoint(
            method="POST",
            path="/auth",
            request_body='{"username":"alice","password":"password-one","token":"token-one"}',
            request_headers=(("Authorization", "Bearer token-one"), ("X-Trace", "ok")),
        )
    )
    param = graph.add_parameter(
        endpoint, Parameter(name="password", location="json", example="password-one")
    )
    assert "password-one" not in repr(graph.endpoint(endpoint))
    assert "token-one" not in repr(graph.endpoint(endpoint))
    assert "password-one" not in repr(graph.parameter(param))


def test_authentication_failure_redacts_credentials_and_blocks() -> None:
    form = DetectedLoginForm(
        url="https://target.test/login?next=secret",
        kind="json_api",
        username_field="email",
        password_field="password",
    )
    firer = _FakeFirer({"/login": _Result(401, "invalid password-one")})
    with pytest.raises(LoginError) as raised:
        submit_login(firer, "owner", form, "alice", "password-one")
    message = str(raised.value)
    assert raised.value.code == "rejected"
    assert "password-one" not in message
    assert "?next=" not in message


def test_browser_form_binds_cookie_server_side_without_returning_secret(monkeypatch) -> None:
    """The browser transport may capture a cookie, but its MCP result cannot."""
    from mcp.server.fastmcp import FastMCP

    from reachagent.mcp import server as mcp_server
    from reachagent.tools.explorer_context import ExplorerContext

    class Locator:
        first = None

        def __init__(self) -> None:
            self.first = self

        async def count(self) -> int:
            return 1

        async def evaluate(self, _script: str) -> str:
            return "input"

        async def get_attribute(self, _name: str) -> str:
            return "text"

        async def fill(self, _value: str) -> None:
            return None

        async def check(self) -> None:
            return None

        async def click(self) -> None:
            return None

    class Page:
        url = "http://target.test/after?token=should-not-return"

        async def goto(self, _url: str, **_kwargs: object) -> None:
            return None

        def locator(self, _selector: str) -> Locator:
            return Locator()

        def expect_navigation(self, **_kwargs: object):
            class Navigation:
                async def __aenter__(self):
                    return self

                async def __aexit__(self, *_args: object) -> None:
                    return None

            return Navigation()

        async def content(self) -> str:
            return "<html>ok</html>"

        async def title(self) -> str:
            return "ok"

    class Context:
        async def new_page(self) -> Page:
            return Page()

        async def cookies(self) -> list[dict[str, str]]:
            return [{"name": "sid", "value": "browser-cookie-secret"}]

        async def close(self) -> None:
            return None

    class Browser:
        async def new_context(self, **_kwargs: object) -> Context:
            return Context()

        async def close(self) -> None:
            return None

    class Playwright:
        class Chromium:
            async def launch(self, **_kwargs: object) -> Browser:
                return Browser()

        chromium = Chromium()

    class AsyncPlaywright:
        async def __aenter__(self) -> Playwright:
            return Playwright()

        async def __aexit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr("playwright.async_api.async_playwright", lambda: AsyncPlaywright())
    identities = _store()
    ctx = ExplorerContext(
        graph=ReachabilityGraph(),
        firer=RequestFirer(
            httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(200))),
            ScopeGuard.from_hosts(["target.test"]),
            AuditLog(),
            identity_stores=identities,
        ),
        library=PayloadLibrary.from_file(),
        base_url="http://target.test",
        identities=identities,
    )
    mcp = FastMCP("phase3-browser-test")
    mcp_server.register_tools(mcp, mcp_server._Session(ctx=ctx))
    fn = mcp._tool_manager._tools["fire_browser_form"].fn
    result = asyncio.run(fn("owner", "http://target.test/login?next=secret", {"q": "payload"}))
    assert "session_cookie" not in result
    assert result["session_ref"] == "token:owner"
    assert "browser-cookie-secret" not in repr(result)
    assert identities.auth_headers("owner") == {"Cookie": "sid=browser-cookie-secret"}
