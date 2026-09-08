"""Tests for the login_as/jwt agent tools."""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_module
import json

import httpx

from lalo.core.redaction import shared_redactor
from lalo.execution.firer import HttpFirer
from lalo.execution.scope import ScopeGuard
from lalo.execution.target import Engagement
from lalo.graph import ReachabilityGraph
from lalo.identity import (
    BodyEncoding,
    Credential,
    CredentialKind,
    Identity,
    IdentityStore,
    LoginScheme,
    Session,
    SessionRegistry,
    SessionSource,
)
from lalo.identity.jwt_tools import jwt_alg_none, jwt_with_claim
from lalo.identity.tool import build_jwt_tool, build_login_tool, build_session_check_tool

_ALICE = Identity(
    id="alice", username="alice", credential=Credential(CredentialKind.PASSWORD, "hunter2xxxxx")
)

_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def _b64url(obj: object) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode("utf-8")).rstrip(b"=").decode("ascii")


def _signed_token(secret: str) -> str:
    header_b = _b64url({"alg": "HS256", "typ": "JWT"})
    payload_b = _b64url({"sub": "admin"})
    signing_input = f"{header_b}.{payload_b}".encode("ascii")
    sig = (
        base64.urlsafe_b64encode(
            hmac_module.new(secret.encode(), signing_input, hashlib.sha256).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    return f"{header_b}.{payload_b}.{sig}"


def _firer(handler: httpx.MockTransport) -> HttpFirer:
    eng = Engagement.from_specs(["app.example.com"])
    scope = ScopeGuard(engagement=eng, resolver=lambda h: frozenset({"93.184.216.34"}))
    return HttpFirer(scope, client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_login_as_succeeds_and_registers_the_session_on_the_graph() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"set-cookie": "session=abc123; Path=/"})

    graph = ReachabilityGraph()
    identities = IdentityStore()
    identities.add(_ALICE)
    sessions = SessionRegistry(graph)
    scheme = LoginScheme(
        login_url="https://app.example.com/login",
        body_encoding=BodyEncoding.JSON,
        session_source=SessionSource.COOKIE,
        session_field="session",
    )
    tool = build_login_tool(_firer(handler), identities, sessions, {"default": scheme})

    result = tool.run({"identity_id": "alice", "scheme": "default"})
    assert result.ok is True
    assert "Cookie: session=abc123" in result.observation
    assert sessions.get("session-alice").value == "abc123"


def test_login_as_rejects_an_unknown_scheme() -> None:
    identities = IdentityStore()
    identities.add(_ALICE)
    sessions = SessionRegistry(ReachabilityGraph())
    tool = build_login_tool(_firer(lambda r: httpx.Response(200)), identities, sessions, {})
    result = tool.run({"identity_id": "alice", "scheme": "nope"})
    assert result.ok is False
    assert "unknown scheme" in result.observation


def test_login_as_rejects_an_unknown_identity() -> None:
    scheme = LoginScheme(login_url="https://app.example.com/login")
    sessions = SessionRegistry(ReachabilityGraph())
    tool = build_login_tool(
        _firer(lambda r: httpx.Response(200)), IdentityStore(), sessions, {"s": scheme}
    )
    result = tool.run({"identity_id": "nope", "scheme": "s"})
    assert result.ok is False
    assert "unknown identity" in result.observation


def test_login_as_reports_a_failed_login_without_crashing() -> None:
    identities = IdentityStore()
    identities.add(_ALICE)
    sessions = SessionRegistry(ReachabilityGraph())
    scheme = LoginScheme(login_url="https://app.example.com/login")
    tool = build_login_tool(
        _firer(lambda r: httpx.Response(401)), identities, sessions, {"s": scheme}
    )
    result = tool.run({"identity_id": "alice", "scheme": "s"})
    assert result.ok is False


def test_login_as_requires_both_args() -> None:
    tool = build_login_tool(
        _firer(lambda r: httpx.Response(200)),
        IdentityStore(),
        SessionRegistry(ReachabilityGraph()),
        {},
    )
    assert tool.run({"identity_id": "alice"}).ok is False
    assert tool.run({"scheme": "s"}).ok is False


def test_login_as_registers_the_session_material_with_the_shared_redactor() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"set-cookie": "session=super-secret-value; Path=/"})

    identities = IdentityStore()
    identities.add(_ALICE)
    sessions = SessionRegistry(ReachabilityGraph())
    scheme = LoginScheme(login_url="https://app.example.com/login", session_field="session")
    tool = build_login_tool(_firer(handler), identities, sessions, {"s": scheme})
    tool.run({"identity_id": "alice", "scheme": "s"})
    assert "super-secret-value" not in shared_redactor().redact("super-secret-value")


def test_login_scheme_totp_secret_is_registered_with_the_shared_redactor() -> None:
    """Mirrors test_adding_an_identity_registers_its_credential_for_universal_redaction
    (test_identity.py) for the one LoginScheme field IdentityStore.add() never sees:
    a scheme's totp_secret. Registration happens at build time, not login time -- the
    tool is built here but never run, proving the secret is protected the moment a
    scheme carrying one is wired in, not only after a login happens to succeed.

    ``secret`` is deliberately short and low-entropy (not a plausible real base32
    TOTP seed) and the surrounding sentence avoids every word the redactor's
    pattern layer keys on ("token", "secret=", etc.) -- unlike this module's own
    ``super-secret-value``/``zzz-unique-marker`` style fixtures elsewhere, which
    the pattern layer alone would already catch, so this is the only way to prove
    register_secret() itself (not the unrelated pattern layer) is what redacts it.
    """
    secret = "totp-seed-mk9-77"
    scheme = LoginScheme(login_url="https://app.example.com/login", totp_secret=secret)
    build_login_tool(
        _firer(lambda r: httpx.Response(200)),
        IdentityStore(),
        SessionRegistry(ReachabilityGraph()),
        {"s": scheme},
    )
    leaked_line = f"login flow needs one-time code derived from {secret}"
    assert secret not in shared_redactor().redact(leaked_line)


def test_jwt_decode_returns_header_and_payload() -> None:
    tool = build_jwt_tool()
    result = tool.run({"op": "decode", "token": _TOKEN})
    assert result.ok is True
    assert "sub" in result.observation


def test_jwt_alg_none_matches_the_pure_helper() -> None:
    tool = build_jwt_tool()
    result = tool.run({"op": "alg_none", "token": _TOKEN})
    assert result.observation == jwt_alg_none(_TOKEN)


def test_jwt_with_claim_matches_the_pure_helper() -> None:
    tool = build_jwt_tool()
    result = tool.run({"op": "with_claim", "token": _TOKEN, "claim": "sub", "value": "admin"})
    assert result.observation == jwt_with_claim(_TOKEN, "sub", "admin")


def test_jwt_with_claim_requires_a_claim_name() -> None:
    tool = build_jwt_tool()
    result = tool.run({"op": "with_claim", "token": _TOKEN})
    assert result.ok is False


def test_jwt_rejects_a_malformed_token_without_crashing() -> None:
    tool = build_jwt_tool()
    result = tool.run({"op": "decode", "token": "not-a-jwt"})
    assert result.ok is False


def test_jwt_rejects_an_unknown_op() -> None:
    tool = build_jwt_tool()
    result = tool.run({"op": "not-a-real-op", "token": _TOKEN})
    assert result.ok is False


def test_jwt_crack_secret_finds_the_real_secret_among_candidates() -> None:
    tool = build_jwt_tool()
    result = tool.run(
        {
            "op": "crack_secret",
            "token": _signed_token("vampi-secret"),
            "candidates": ["wrong", "vampi-secret", "also-wrong"],
        }
    )
    assert result.ok is True
    assert "vampi-secret" in result.observation


def test_jwt_crack_secret_reports_no_match_without_failing_the_tool_call() -> None:
    tool = build_jwt_tool()
    result = tool.run({"op": "crack_secret", "token": _TOKEN, "candidates": ["a", "b"]})
    assert result.ok is True
    assert "no match" in result.observation.lower()


def test_jwt_crack_secret_requires_candidates() -> None:
    tool = build_jwt_tool()
    result = tool.run({"op": "crack_secret", "token": _TOKEN})
    assert result.ok is False


def test_jwt_crack_secret_surfaces_the_too_many_candidates_error_as_a_failed_result() -> None:
    tool = build_jwt_tool()
    result = tool.run(
        {"op": "crack_secret", "token": _TOKEN, "candidates": [str(i) for i in range(5001)]}
    )
    assert result.ok is False
    assert "too many candidates" in result.observation


# --- check_session_valid ------------------------------------------------


def _registered_session(graph: ReachabilityGraph, *, value: str = "abc123") -> SessionRegistry:
    sessions = SessionRegistry(graph)
    sessions.register(
        Session(
            id="session-alice",
            identity_id="alice",
            kind=SessionSource.COOKIE,
            name="session",
            value=value,
        )
    )
    return sessions


def test_check_session_valid_reports_a_healthy_session() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["cookie"] = request.headers.get("cookie")
        return httpx.Response(200)

    sessions = _registered_session(ReachabilityGraph())
    tool = build_session_check_tool(_firer(handler), sessions)
    result = tool.run({"session_id": "session-alice", "validate_url": "https://app.example.com/me"})
    assert result.ok is True
    assert "valid" in result.observation
    assert seen["cookie"] == "session=abc123"


def test_check_session_valid_reports_a_stale_session() -> None:
    tool = build_session_check_tool(
        _firer(lambda r: httpx.Response(401)), _registered_session(ReachabilityGraph())
    )
    result = tool.run({"session_id": "session-alice", "validate_url": "https://app.example.com/me"})
    assert result.ok is False
    assert "stale" in result.observation


def test_check_session_valid_rejects_an_unknown_session_id() -> None:
    tool = build_session_check_tool(
        _firer(lambda r: httpx.Response(200)), SessionRegistry(ReachabilityGraph())
    )
    result = tool.run({"session_id": "nope", "validate_url": "https://app.example.com/me"})
    assert result.ok is False
    assert "unknown session" in result.observation


def test_check_session_valid_requires_both_args() -> None:
    tool = build_session_check_tool(
        _firer(lambda r: httpx.Response(200)), _registered_session(ReachabilityGraph())
    )
    assert tool.run({"session_id": "session-alice"}).ok is False
    assert tool.run({"validate_url": "https://app.example.com/me"}).ok is False


def test_check_session_valid_out_of_scope_url_is_a_failed_result_not_a_crash() -> None:
    tool = build_session_check_tool(
        _firer(lambda r: httpx.Response(200)), _registered_session(ReachabilityGraph())
    )
    result = tool.run(
        {"session_id": "session-alice", "validate_url": "https://evil.example.org/me"}
    )
    assert result.ok is False
    assert "could not check" in result.observation
