"""LLM-selected login discovery and isolated session capture.

Discovery is evidence driven: graph routes, HTML forms, and GraphQL request
shapes are inspected before a credential is submitted. The returned login
handle is opaque; token/cookie values stay in the owning :class:`TokenStore`.
"""

from __future__ import annotations

import base64
import json
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from reachagent.graph.nodes import Protocol
from reachagent.identity.store import SessionMaterial

_log = logging.getLogger(__name__)
_AUTH_PATH_HINTS = ("login", "signin", "sign-in", "auth", "session", "token")
_USERNAME_NAMES = {"username", "user", "email", "login", "account", "mail"}
_PASSWORD_TYPE = re.compile(r"\btype\s*=\s*(['\"]?)password\1", re.IGNORECASE)
_ATTR = re.compile(
    r"(?P<name>[A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?P<quote>['\"]?)(?P<value>[^\s>]*?)(?P=quote)(?=\s|>|/|$)",
    re.IGNORECASE,
)
_FORM = re.compile(r"<form\b(?P<attrs>[^>]*)>(?P<body>[\s\S]*?)</form>", re.IGNORECASE)
_INPUT = re.compile(r"<(?:input|textarea|select)\b(?P<attrs>[^>]*)>", re.IGNORECASE)
_GRAPHQL_MUTATION = re.compile(r"\bmutation(?:\s+[A-Za-z_][\w]*)?\s*\{", re.IGNORECASE)
_TOKEN_KEYS = ("access_token", "token", "jwt", "id_token", "session_token")
_DEFAULT_TOKEN_SCHEME = "Bearer"  # noqa: S105 - HTTP auth scheme, not a credential


class LoginError(RuntimeError):
    """A fail-loud authentication failure with a stable, secret-free code."""

    def __init__(self, message: str, *, code: str = "authentication_failed") -> None:
        self.code = code
        super().__init__(message[:300])


@dataclass(frozen=True)
class DetectedLoginForm:
    """One login surface discovered from a graph or read-only response."""

    url: str
    kind: str
    username_field: str = ""
    password_field: str = ""
    method: str = "POST"
    extra_fields: dict[str, str] = field(default_factory=dict, repr=False, compare=False)
    page_url: str = ""
    enctype: str = "application/x-www-form-urlencoded"
    graphql_operation: str = "login"
    auth_hint: str = ""

    def __repr__(self) -> str:
        """Human-safe representation; action query strings may contain secrets."""
        return (
            "DetectedLoginForm("
            f"url={_safe_url(self.url)!r}, kind={self.kind!r}, "
            f"username_field={self.username_field!r}, password_field={self.password_field!r}, "
            f"method={self.method!r}, page_url={_safe_url(self.page_url)!r}, "
            f"enctype={self.enctype!r}, graphql_operation={self.graphql_operation!r}, "
            f"auth_hint={self.auth_hint!r})"
        )


@dataclass(frozen=True)
class CapturedSession:
    """Raw material held briefly while it is transferred into ``TokenStore``."""

    token: str = field(default="", repr=False)
    kind: str = "bearer"
    cookies: tuple[tuple[str, str], ...] = field(default=(), repr=False, compare=False)
    expires_at: datetime | None = None
    refresh_token: str | None = field(default=None, repr=False, compare=False)
    refresh_url: str | None = None
    token_type: str = _DEFAULT_TOKEN_SCHEME

    def material(self) -> SessionMaterial:
        return SessionMaterial(
            kind=self.kind,
            token=self.token or None if self.kind in {"bearer", "mixed"} else None,
            cookies=self.cookies,
            expires_at=self.expires_at,
            refresh_token=self.refresh_token,
            refresh_url=self.refresh_url,
            token_type=self.token_type,
        )


@dataclass(frozen=True)
class OAuthDiscovery:
    """Non-secret OAuth/OIDC metadata discovered from a well-known document."""

    issuer: str
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    userinfo_endpoint: str | None = None
    scopes_supported: tuple[str, ...] = ()


def _safe_url(value: str) -> str:
    """Drop query/fragment/userinfo before an URL is put in an error message."""
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        netloc = host + (f":{parsed.port}" if parsed.port is not None else "")
        return urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", ""))
    except Exception:  # noqa: BLE001
        return "<target>"


def _safe_message(value: object, secrets: tuple[str, ...] = ()) -> str:
    text = str(value)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    text = re.sub(r"https?://[^\s)]+", lambda m: _safe_url(m.group(0)), text)
    text = re.sub(
        r"(?i)(password|passwd|token|bearer|secret|authorization|cookie|api[_-]?key)"
        r"\s*[=:]\s*(?:Bearer\s+)?[^,;\s]+",
        r"\1=<redacted>",
        text,
    )
    text = re.sub(r"(?i)\bBearer\s+[^\s,;}]+", "Bearer <redacted>", text)
    return text[:300]


def redact_message(value: object, secrets: tuple[str, ...] = ()) -> str:
    """Return an operator-safe error string with auth-looking values removed."""
    return _safe_message(value, secrets)


def _attrs(raw: str) -> dict[str, str]:
    return {m.group("name").lower(): m.group("value").strip("'\"") for m in _ATTR.finditer(raw)}


def _parse_html_login_form(html_body: str, page_url: str) -> DetectedLoginForm | None:
    """Extract the first form containing a password input, including hidden fields."""
    for match in _FORM.finditer(html_body):
        attrs = _attrs(match.group("attrs"))
        body = match.group("body")
        inputs: list[tuple[dict[str, str], str]] = []
        for input_match in _INPUT.finditer(body):
            item = _attrs(input_match.group("attrs"))
            if item:
                inputs.append((item, input_match.group(0)))
        password = ""
        for item, tag in inputs:
            if item.get("type", "").lower() == "password" or _PASSWORD_TYPE.search(tag):
                password = item.get("name", "")
                if password:
                    break
        if not password:
            continue
        username = ""
        hidden: dict[str, str] = {}
        for item, _tag in inputs:
            name = item.get("name", "")
            lower = name.lower()
            if not username and lower in _USERNAME_NAMES:
                username = name
            if item.get("type", "").lower() == "hidden" and item.get("value") is not None:
                hidden[name] = item.get("value", "")
        action = attrs.get("action", "")
        method = attrs.get("method", "POST").upper() or "POST"
        enctype = attrs.get("enctype", "application/x-www-form-urlencoded").lower()
        return DetectedLoginForm(
            url=urljoin(page_url, action) if action else page_url,
            kind="html_form",
            username_field=username,
            password_field=password,
            method=method,
            extra_fields=hidden,
            page_url=page_url,
            enctype=enctype,
            auth_hint="password form",
        )
    return None


def _graph_form(graph: object, endpoint_id: str, endpoint: object) -> DetectedLoginForm | None:
    path = str(getattr(endpoint, "path", ""))
    body = str(getattr(endpoint, "request_body", "") or "")
    protocol = getattr(
        getattr(endpoint, "protocol", None), "value", getattr(endpoint, "protocol", "")
    )
    is_graphql = (
        protocol == Protocol.GRAPHQL.value
        or "graphql" in path.lower()
        or bool(_GRAPHQL_MUTATION.search(body))
    )
    if is_graphql:
        operation = "login"
        username_field = "username"
        pass_field = "password"  # noqa: S105 - field name inferred from GraphQL schema
        op_match = re.search(r"\b(?:mutation|query)\s+([A-Za-z_]\w*)", body, re.IGNORECASE)
        if op_match:
            operation = op_match.group(1)
        field_match = re.search(r"\{\s*([A-Za-z_]\w*)\s*\(", body)
        if field_match:
            operation = field_match.group(1)
        variables = re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*:", body)
        username_field = next(
            (
                name
                for name in variables
                if any(tag in name.lower() for tag in ("email", "user", "login"))
            ),
            username_field,
        )
        pass_field = next((name for name in variables if "pass" in name.lower()), pass_field)
        return DetectedLoginForm(
            url=path,
            kind="graphql",
            username_field=username_field,
            password_field=pass_field,
            method="POST",
            graphql_operation=operation,
            extra_fields={"graphql_body": body} if body else {},
            auth_hint="GraphQL mutation",
        )
    if getattr(endpoint, "method", "").upper() != "POST":
        return None
    if not any(hint in path.lower() for hint in _AUTH_PATH_HINTS):
        return None
    username = "username"
    pass_name = "password"  # noqa: S105 - conventional field fallback
    try:
        body_fields = json.loads(body) if body else {}
        if isinstance(body_fields, dict):
            username = next(
                (name for name in body_fields if str(name).lower() in _USERNAME_NAMES), username
            )
            pass_name = next(
                (name for name in body_fields if "pass" in str(name).lower()), pass_name
            )
    except (TypeError, ValueError):
        pass
    try:
        params = graph.parameters_of(endpoint_id)  # type: ignore[attr-defined]
        names = [str(getattr(param, "name", "")) for _, param in params]
        pass_name = next((name for name in names if "pass" in name.lower()), pass_name)
        username = next((name for name in names if name.lower() in _USERNAME_NAMES), username)
    except Exception:  # noqa: BLE001 - graph metadata is optional
        _log.debug("graph login metadata unavailable", exc_info=True)
    return DetectedLoginForm(
        url=path,
        kind="json_api",
        username_field=username,
        password_field=pass_name,
        auth_hint="auth-shaped POST endpoint",
    )


def detect_login_forms(
    firer: object,
    base_url: str,
    identity: str,
    graph: object | None = None,
) -> list[DetectedLoginForm]:
    """Discover forms from observed graph routes and bounded same-host pages."""
    forms: list[DetectedLoginForm] = []
    seen: set[tuple[str, str]] = set()
    candidates: list[str] = [base_url]

    if graph is not None:
        for endpoint_id, endpoint in graph.endpoints():  # type: ignore[attr-defined]
            path = str(getattr(endpoint, "path", ""))
            candidate = _graph_form(graph, endpoint_id, endpoint)
            if candidate is not None:
                url = urljoin(base_url, candidate.url)
                key = (url, candidate.kind)
                if key not in seen:
                    seen.add(key)
                    forms.append(DetectedLoginForm(**{**candidate.__dict__, "url": url}))
            if getattr(endpoint, "method", "").upper() == "GET" and (
                "html" in str(getattr(endpoint, "content_type", "") or "").lower()
                or not getattr(endpoint, "content_type", None)
            ):
                candidates.append(urljoin(base_url, path))

    # Common aliases are only bounded fallback probes; observed routes/root are
    # always attempted first, so a non-standard login path is discoverable.
    candidates.extend(urljoin(base_url, path) for path in ("/login", "/signin", "/auth"))
    for url in candidates[:24]:
        try:
            result = firer.fire(identity, "GET", url, state_changing=False)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            _log.debug("login probe skipped %s: %s", _safe_url(url), type(exc).__name__)
            continue
        if not 200 <= result.status_code < 400:
            continue
        body = result.body.decode("utf-8", errors="replace")
        form = _parse_html_login_form(body, url)
        if form is not None and (form.url, form.kind) not in seen:
            forms.append(form)
            seen.add((form.url, form.kind))
    return forms


def discover_oidc(firer: object, base_url: str, identity: str) -> OAuthDiscovery | None:
    """Read the standard OAuth/OIDC metadata document without submitting credentials."""
    for suffix in ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"):
        url = urljoin(base_url.rstrip("/") + "/", suffix.lstrip("/"))
        try:
            result = firer.fire(identity, "GET", url, state_changing=False)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            _log.debug("OIDC discovery probe failed", exc_info=True)
            continue
        if not 200 <= result.status_code < 300:
            continue
        try:
            payload = json.loads(result.body.decode("utf-8", errors="replace"))
        except (TypeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        scopes = payload.get("scopes_supported")
        return OAuthDiscovery(
            issuer=str(payload.get("issuer") or base_url),
            authorization_endpoint=_optional_str(payload.get("authorization_endpoint")),
            token_endpoint=_optional_str(payload.get("token_endpoint")),
            userinfo_endpoint=_optional_str(payload.get("userinfo_endpoint")),
            scopes_supported=tuple(str(item) for item in scopes if isinstance(item, str))
            if isinstance(scopes, list)
            else (),
        )
    return None


def submit_login(
    firer: object,
    identity_name: str,
    form: DetectedLoginForm,
    username: str,
    password: str,
) -> CapturedSession:
    """Submit credentials in the detected serialization and capture material."""
    try:
        if form.kind == "html_form":
            data = dict(form.extra_fields)
            if form.username_field:
                data[form.username_field] = username
            data[form.password_field] = password
            result = firer.fire(  # type: ignore[attr-defined]
                identity_name,
                form.method,
                form.url,
                state_changing=True,
                authentication=True,
                data=data,
                headers={"Content-Type": form.enctype},
            )
        elif form.kind == "graphql":
            operation = form.graphql_operation or "login"
            query = form.extra_fields.get("graphql_body", "")
            if not query or "<redacted>" in query:
                user_var = form.username_field or "username"
                pass_var = form.password_field or "password"
                query = (
                    f"mutation {operation.title()}(${user_var}: String!, ${pass_var}: String!) "
                    f"{{ {operation}({user_var}: ${user_var}, {pass_var}: ${pass_var}) "
                    "{ token access_token } }"
                )
            result = firer.fire(  # type: ignore[attr-defined]
                identity_name,
                "POST",
                form.url,
                state_changing=True,
                authentication=True,
                json={
                    "query": query,
                    "variables": {
                        form.username_field or "username": username,
                        form.password_field or "password": password,
                    },
                },
                headers={"Content-Type": "application/json"},
            )
        else:
            result = firer.fire(  # type: ignore[attr-defined]
                identity_name,
                form.method,
                form.url,
                state_changing=True,
                authentication=True,
                json={
                    form.username_field or "username": username,
                    form.password_field or "password": password,
                },
                headers={"Content-Type": "application/json"},
            )
    except Exception as exc:  # noqa: BLE001
        raise LoginError(
            "login submission failed "
            f"({type(exc).__name__}): {_safe_message(exc, (username, password))}",
            code="transport",
        ) from exc

    status = int(getattr(result, "status_code", 0))
    if status == 429:
        raise LoginError(f"rate-limited (HTTP 429) at {_safe_url(form.url)}", code="rate_limited")
    body_text = bytes(getattr(result, "body", b"")).decode("utf-8", errors="replace")
    lowered = body_text.lower()
    for marker, code in (
        ("captcha", "captcha"),
        ("challenge", "challenge"),
        ("two-factor", "2fa"),
        ("2fa code", "2fa"),
    ):
        if marker in lowered and status in (200, 401, 403):
            raise LoginError(f"authentication blocked by {code} challenge", code=code)
    if not 200 <= status < 400:
        raise LoginError(f"login rejected at {_safe_url(form.url)}: HTTP {status}", code="rejected")
    captured = _extract_session_material(result, body_text)
    if not captured.token and not captured.cookies:
        raise LoginError(
            f"login succeeded but no session material captured at {_safe_url(form.url)}",
            code="no_session_material",
        )
    return captured


def _extract_session_material(result: object, body_text: str) -> CapturedSession:
    headers = getattr(result, "headers", None)
    cookies: dict[str, str] = {}
    token = ""
    token_type = _DEFAULT_TOKEN_SCHEME
    if headers is not None:
        set_cookie_values: list[str] = []
        get_list = getattr(headers, "get_list", None)
        if callable(get_list):
            try:
                set_cookie_values = [str(item) for item in get_list("set-cookie")]
            except Exception:  # noqa: BLE001
                set_cookie_values = []
        if not set_cookie_values:
            raw_cookie = _header_get(headers, "set-cookie")
            set_cookie_values = [str(raw_cookie)] if raw_cookie else []
        for raw in set_cookie_values:
            jar = SimpleCookie()
            try:
                jar.load(raw)
            except Exception:  # noqa: BLE001
                jar = SimpleCookie()
            for name, morsel in jar.items():
                cookies[name] = morsel.value
            if not jar and raw:
                first = raw.split(";", 1)[0].strip()
                if "=" in first:
                    name, value = first.split("=", 1)
                    cookies[name.strip()] = value.strip()
        for name in ("authorization", "x-auth-token", "x-access-token"):
            value = _header_get(headers, name)
            if value:
                if name == "authorization" and " " in value:
                    token_type, value = value.split(None, 1)
                    token_type = token_type.strip() or _DEFAULT_TOKEN_SCHEME
                else:
                    token_type = _DEFAULT_TOKEN_SCHEME
                token = value
                break
    refresh_token = None
    expires_at: datetime | None = None
    refresh_url = None
    try:
        data = json.loads(body_text)
    except (TypeError, ValueError):
        data = None
    if isinstance(data, dict):
        nested = _find_token_mapping(data) or data
        for key in _TOKEN_KEYS:
            token_value = nested.get(key)
            if isinstance(token_value, str) and token_value:
                token = token or token_value
                break
        refresh_token = _optional_str(nested.get("refresh_token"))
        refresh_url = _optional_str(nested.get("token_endpoint"))
        expires_at = _expiry_from_payload(nested)
        token_type = str(nested.get("token_type") or token_type)
    if expires_at is None:
        expires_at = _jwt_expiry(token)
    has_bearer = bool(token)
    if not token and cookies:
        # Keep the historical ``CapturedSession.token`` convenience value for
        # callers that only inspect a cookie, while ``material()`` correctly
        # stores it as cookie-only data (never as an Authorization header).
        token = "; ".join(f"{name}={value}" for name, value in sorted(cookies.items()))
    kind = "mixed" if has_bearer and cookies else ("cookie" if cookies else "bearer")
    return CapturedSession(
        token=token,
        kind=kind,
        cookies=tuple(sorted(cookies.items())),
        expires_at=expires_at,
        refresh_token=refresh_token,
        refresh_url=refresh_url,
        token_type=token_type,
    )


def _extract_session_token(result: object, body_text: str) -> CapturedSession:
    """Compatibility alias for callers of the pre-Phase-3 helper."""
    return _extract_session_material(result, body_text)


def _header_get(headers: object, name: str) -> str:
    getter = getattr(headers, "get", None)
    if callable(getter):
        value = getter(name, "")
        if value:
            return str(value)
    items = getattr(headers, "items", None)
    if callable(items):
        for key, value in items():
            if str(key).lower() == name.lower():
                return str(value)
    return ""


def authenticate_identity(
    firer: object,
    identity_store: object,
    identity_name: str,
    base_url: str,
    *,
    graph: object | None = None,
) -> str:
    """Detect, submit, and bind one identity; return only ``token:<identity>``."""
    cred = identity_store.credential(identity_name)  # type: ignore[attr-defined]
    forms = detect_login_forms(firer, base_url, identity_name, graph=graph)
    if not forms:
        discovery = discover_oidc(firer, base_url, identity_name)
        if discovery is not None:
            raise LoginError(
                "OIDC provider discovered; interactive authorization is required",
                code="interactive_required",
            )
        raise LoginError(f"no login surface detected at {_safe_url(base_url)}", code="no_surface")

    failures: list[str] = []
    for form in forms:
        try:
            captured = submit_login(firer, identity_name, form, cred.username, cred.password)
            material = captured.material()
            refresh_callback = None
            if material.refresh_token and material.refresh_url:
                refresh_callback = _make_refresh_callback(
                    firer, identity_name, material.refresh_url, material.token_type
                )
            identity_store.open_session(  # type: ignore[attr-defined]
                identity_name,
                material.token or "",
                kind=material.kind,
                cookies=dict(material.cookies),
                expires_at=material.expires_at,
                refresh_token=material.refresh_token,
                refresh_url=material.refresh_url,
                token_type=material.token_type,
                refresh_callback=refresh_callback,
            )
            return f"token:{identity_name}"
        except LoginError as exc:
            failures.append(f"{exc.code}: {str(exc)}")
    detail = failures[-1] if failures else "no compatible login surface"
    raise LoginError(
        f"all {len(forms)} login surface(s) failed for {identity_name!r}: {detail}",
        code="authentication_failed",
    )


def _optional_str(value: object) -> str | None:
    return str(value) if isinstance(value, str) and value else None


def _find_token_mapping(value: object) -> dict[str, Any] | None:
    if isinstance(value, dict):
        if any(key in value for key in _TOKEN_KEYS):
            return value
        for child in value.values():
            found = _find_token_mapping(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_token_mapping(child)
            if found is not None:
                return found
    return None


def _make_refresh_callback(firer: object, identity: str, refresh_url: str, token_type: str) -> Any:
    """Create an in-memory refresh callback; refresh secrets never leave the store."""

    def refresh(refresh_token: str) -> SessionMaterial | None:
        try:
            result = firer.fire(  # type: ignore[attr-defined]
                identity,
                "POST",
                refresh_url,
                state_changing=True,
                authentication=True,
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except Exception:  # noqa: BLE001 - TokenStore fails closed on refresh errors
            return None
        if not 200 <= int(getattr(result, "status_code", 0)) < 300:
            return None
        body = bytes(getattr(result, "body", b"")).decode("utf-8", errors="replace")
        refreshed = _extract_session_material(result, body)
        if not refreshed.token and not refreshed.cookies:
            return None
        return SessionMaterial(
            kind=refreshed.kind,
            token=refreshed.material().token,
            cookies=refreshed.cookies,
            expires_at=refreshed.expires_at,
            refresh_token=refreshed.refresh_token or refresh_token,
            refresh_url=refresh_url,
            token_type=refreshed.token_type or token_type,
        )

    return refresh


def _expiry_from_payload(payload: Mapping[str, Any]) -> datetime | None:
    raw = payload.get("expires_at")
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        try:
            return datetime.fromtimestamp(float(raw), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(raw, str) and raw:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    seconds = payload.get("expires_in")
    if isinstance(seconds, (int, float)) and not isinstance(seconds, bool) and seconds > 0:
        return datetime.now(UTC) + timedelta(seconds=float(seconds))
    return None


def _jwt_expiry(token: str) -> datetime | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        exp = payload.get("exp")
        if isinstance(exp, (int, float)) and not isinstance(exp, bool):
            try:
                return datetime.fromtimestamp(float(exp), tz=UTC)
            except (OverflowError, OSError, ValueError):
                return None
    except (ValueError, TypeError, KeyError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return None


__all__ = [
    "CapturedSession",
    "DetectedLoginForm",
    "LoginError",
    "OAuthDiscovery",
    "authenticate_identity",
    "detect_login_forms",
    "discover_oidc",
    "redact_message",
    "submit_login",
]
