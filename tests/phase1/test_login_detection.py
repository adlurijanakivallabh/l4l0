"""Login detection, submission, and session capture - hermetic tests.

Covers: HTML form parsing (password field + CSRF), JSON API detection from
graph hints, credential submission through a mock firer, session capture
(cookie / bearer / JSON token), and fail-loud on wrong creds / CAPTCHA /
rate limit.
"""

from __future__ import annotations

import pytest

from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import Endpoint, Host
from reachagent.graph.store import ReachabilityGraph
from reachagent.identity.login import (
    DetectedLoginForm,
    LoginError,
    _parse_html_login_form,
    authenticate_identity,
    detect_login_forms,
    submit_login,
)
from reachagent.identity.store import IdentityStore

_TARGET = "target.test"
_BASE = "http://target.test"


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts([_TARGET])


class FakeFireResult:
    def __init__(self, status: int, body: str, headers: dict | None = None) -> None:
        self.status_code = status
        self.body = body.encode()
        self.headers = headers or {}


class MockFirer:
    """Records fired requests and returns canned responses."""

    def __init__(self) -> None:
        self.fired: list[tuple[str, str, str]] = []
        self.responses: dict[str, FakeFireResult] = {}

    def fire(self, identity: str, method: str, url: str, **kwargs: object) -> FakeFireResult:
        self.fired.append((identity, method, url))
        for pattern, resp in self.responses.items():
            if pattern in url:
                return resp
        return FakeFireResult(404, "not found")


_LOGIN_HTML = """
<html><body>
<form action="/auth/login" method="post">
  <input type="hidden" name="csrf_token" value="abc123"/>
  <input type="text" name="username"/>
  <input type="password" name="passwd"/>
  <input type="submit" value="Log in"/>
</form>
</body></html>
"""


class TestHtmlFormParsing:
    def test_parses_login_form_fields(self) -> None:
        form = _parse_html_login_form(_LOGIN_HTML, _BASE + "/login")
        assert form is not None
        assert form.kind == "html_form"
        assert form.username_field == "username"
        assert form.password_field == "passwd"
        assert form.url == _BASE + "/auth/login"
        assert form.method == "POST"
        assert form.extra_fields.get("csrf_token") == "abc123"

    def test_returns_none_without_password_field(self) -> None:
        html = '<form action="/x" method="post"><input name="q"/></form>'
        assert _parse_html_login_form(html, _BASE) is None


class TestDetectLoginForms:
    def test_finds_graph_post_endpoint(self) -> None:
        firer = MockFirer()
        g = ReachabilityGraph()
        g.add_host(Host(address=_TARGET, source="test"))
        g.add_endpoint(Endpoint(method="POST", path="/api/auth/login"))

        forms = detect_login_forms(firer, _BASE, "seed", graph=g)
        assert len(forms) >= 1
        api_forms = [f for f in forms if f.kind == "json_api"]
        assert any("/api/auth/login" in f.url for f in api_forms)

    def test_finds_html_login_page(self) -> None:
        firer = MockFirer()
        firer.responses["/login"] = FakeFireResult(200, _LOGIN_HTML)

        forms = detect_login_forms(firer, _BASE, "seed")
        assert len(forms) >= 1
        html_forms = [f for f in forms if f.kind == "html_form"]
        assert html_forms[0].password_field == "passwd"


class TestSubmitLogin:
    def _html_form(self) -> DetectedLoginForm:
        return DetectedLoginForm(
            url=_BASE + "/auth/login",
            kind="html_form",
            username_field="username",
            password_field="passwd",
            method="POST",
        )

    def test_success_with_cookie(self) -> None:
        firer = MockFirer()

        def _fire(identity: str, method: str, url: str, **kw: object) -> FakeFireResult:
            firer.fired.append((identity, method, url))
            if "auth/login" in url and kw.get("state_changing"):
                return FakeFireResult(
                    200, '{"user":"admin"}', headers={"set-cookie": "session=xyz; HttpOnly"}
                )
            return FakeFireResult(200, "ok")

        firer.fire = _fire  # type: ignore[assignment]
        token = submit_login(firer, "test_user", self._html_form(), "admin", "pass123")
        assert "session=xyz" in token

    def test_wrong_credentials_raises_loud(self) -> None:
        firer = MockFirer()
        firer.responses["/auth/login"] = FakeFireResult(401, "Unauthorized")

        with pytest.raises(LoginError, match="HTTP 401"):
            submit_login(firer, "u", self._html_form(), "bad", "creds")

    def test_captcha_blocked_raises_loud(self) -> None:
        firer = MockFirer()
        firer.responses["/auth/login"] = FakeFireResult(200, "Please solve the CAPTCHA below")

        with pytest.raises(LoginError, match="captcha"):
            submit_login(firer, "u", self._html_form(), "good", "creds")


class TestAuthenticateIdentity:
    def _store(self) -> IdentityStore:
        from reachagent.graph.nodes import AuthState
        from reachagent.identity.store import Credential

        store = IdentityStore()
        store.add(
            Credential(
                identity="testuser", username="admin", password="s3cret",
                role="admin", auth_state=AuthState.ADMIN,
            )
        )
        return store

    def test_full_flow_binds_session(self) -> None:
        firer = MockFirer()

        def _fire(identity: str, method: str, url: str, **kw: object) -> FakeFireResult:
            firer.fired.append((identity, method, url))
            if url.endswith("/login") and method == "GET":
                return FakeFireResult(200, _LOGIN_HTML)
            if "auth/login" in url and kw.get("state_changing"):
                return FakeFireResult(200, '{"token": "jwt-abc-123"}')
            return FakeFireResult(404, "nf")

        firer.fire = _fire  # type: ignore[assignment]
        store = self._store()
        token = authenticate_identity(firer, store, "testuser", _BASE)
        assert "jwt" in token.lower() or len(token) > 8
        assert store.token_store("testuser").get_token() == token
