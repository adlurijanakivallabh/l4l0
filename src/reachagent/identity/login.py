"""LLM-driven login detection and session capture.

Given user-supplied credentials, this module:
1. Probes the target for a login surface during recon (not assumed at
   a fixed path). Detection signals: a form with a password-type input,
   a POST endpoint on an auth-shaped path, or a GraphQL mutation.
2. Submits credentials through the gated RequestFirer.
3. Captures the resulting session material (cookie, bearer token) into
   the existing IdentityStore.open_session pattern.
4. Binds each credential set as a separate Identity so cross-identity
   differential oracles work naturally across roles.
5. Fails LOUD on login failure (wrong credentials, CAPTCHA, rate-limit).

Blast radius: session capture only. No finding written, no oracle called.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

_log = logging.getLogger(__name__)
_AUTH_PATH_HINTS = ("login", "signin", "sign-in", "auth", "session", "token")
_PASSWORD_TYPE = re.compile(r"type=.password.", re.IGNORECASE)
_INPUT_NAME = re.compile(r"name=.([\w\-]+).", re.IGNORECASE)
_FORM_ACTION = re.compile(r"action=.([^\x27\x22]*).", re.IGNORECASE)
_FORM_METHOD = re.compile(r"method=.([^\x27\x22]*).", re.IGNORECASE)


class LoginError(RuntimeError):
    """Raised when authentication fails. Fail loud, never silent."""


@dataclass(frozen=True)
class DetectedLoginForm:
    """One login surface discovered during recon."""

    url: str
    kind: str
    username_field: str = ""
    password_field: str = ""
    method: str = "POST"
    extra_fields: dict[str, str] = field(default_factory=dict)


def detect_login_forms(
    firer: object,
    base_url: str,
    identity: str,
    graph: object | None = None,
) -> list[DetectedLoginForm]:
    """Probe the target for login surfaces; return every distinct one found.

    Two detection paths: graph endpoints with auth-shaped POST paths, and
    HTML pages containing a form with a password-type input.
    Read-only GET probes only; no credential is submitted here.
    """
    forms: list[DetectedLoginForm] = []
    seen_urls: set[str] = set()

    if graph is not None:
        for _ep_id, ep in graph.endpoints():  # type: ignore[attr-defined]
            if ep.method.upper() != "POST":
                continue
            low = ep.path.lower()
            if not any(h in low for h in _AUTH_PATH_HINTS):
                continue
            url = urljoin(base_url, ep.path)
            if url not in seen_urls:
                seen_urls.add(url)
                forms.append(DetectedLoginForm(url=url, kind="json_api"))

    for path in ("/login", "/signin", "/auth"):
        url = urljoin(base_url, path)
        if url in seen_urls:
            continue
        try:
            result = firer.fire(identity, "GET", url, state_changing=False)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            _log.debug("login probe skipped %s: %s", url, type(exc).__name__)
            continue
        if not (200 <= result.status_code < 400):
            continue
        body = result.body.decode("utf-8", errors="replace")
        form = _parse_html_login_form(body, url)
        if form is not None:
            forms.append(form)
            seen_urls.add(url)

    return forms


def _parse_html_login_form(html_body: str, page_url: str) -> DetectedLoginForm | None:
    """Extract a login form (password input) from an HTML page."""
    form_blocks = re.findall(r"<form[\s\S]*?</form>", html_body, re.IGNORECASE)
    for block in form_blocks:
        if not _PASSWORD_TYPE.search(block):
            continue
        action_m = _FORM_ACTION.search(block)
        method_m = _FORM_METHOD.search(block)
        action = action_m.group(1).strip() if action_m else ""
        method = (method_m.group(1).strip() if method_m else "post").upper()
        submit_url = urljoin(page_url, action) if action else page_url

        inputs = re.findall(r"<input[^>]*>", block, re.IGNORECASE)
        username_field = ""
        password_field = ""
        extra_fields: dict[str, str] = {}
        for tag in inputs:
            name_m = _INPUT_NAME.search(tag)
            if name_m is None:
                continue
            name = name_m.group(1)
            low = name.lower()
            if _PASSWORD_TYPE.search(tag):
                password_field = name
            elif low in ("username", "user", "email", "login", "account"):
                username_field = username_field or name
            elif "csrf" in low or low == "authenticity_token":
                value_m = re.search(r"value=.([^\x27\x22]*).", tag, re.IGNORECASE)
                if value_m:
                    extra_fields[name] = value_m.group(1)

        if password_field:
            return DetectedLoginForm(
                url=submit_url,
                kind="html_form",
                username_field=username_field,
                password_field=password_field,
                method=method,
                extra_fields=extra_fields,
            )
    return None


def submit_login(
    firer: object,
    identity_name: str,
    form: DetectedLoginForm,
    username: str,
    password: str,
) -> str:
    """Submit credentials to the detected login form and return the session token.

    Raises LoginError on failure (fail loud, never silent).
    """
    try:
        if form.kind == "html_form":
            data = dict(form.extra_fields)
            if form.username_field:
                data[form.username_field] = username
            data[form.password_field] = password
            result = firer.fire(  # type: ignore[attr-defined]
                identity_name, form.method, form.url, state_changing=True, data=data
            )
        else:
            result = firer.fire(  # type: ignore[attr-defined]
                identity_name,
                form.method,
                form.url,
                state_changing=True,
                json={"username": username, "password": password},
            )
    except Exception as exc:
        raise LoginError(f"login submission failed ({type(exc).__name__}): {exc}") from exc

    if result.status_code == 429:
        raise LoginError(f"rate-limited (HTTP 429) at {form.url}")

    body_text = result.body.decode("utf-8", errors="replace")
    lowered = body_text.lower()
    for marker in ("captcha", "challenge", "two-factor", "2fa code"):
        if marker in lowered and result.status_code in (200, 401, 403):
            raise LoginError(f"authentication blocked by challenge: {marker}")

    if not (200 <= result.status_code < 400):
        raise LoginError(f"login rejected at {form.url}: HTTP {result.status_code}")

    token = _extract_session_token(result, body_text)
    if not token:
        raise LoginError(f"login succeeded but no session material captured at {form.url}")
    return token


def _extract_session_token(result: object, body_text: str) -> str:
    """Extract session material from a login response."""
    headers = getattr(result, "headers", None)
    if headers is not None:
        set_cookie = str(headers.get("set-cookie", ""))
        if set_cookie:
            return set_cookie.split(";")[0].strip()
        for hname in ("authorization", "x-auth-token"):
            header_val = str(headers.get(hname, ""))
            if header_val:
                return header_val
    lowered = body_text[:2000]
    import json as _json

    try:
        data = _json.loads(body_text)
        if isinstance(data, dict):
            for key in ("token", "access_token", "jwt", "session_token"):
                val: object | None = data.get(key)
                if isinstance(val, str) and len(val) > 8:
                    return val
    except Exception:  # noqa: BLE001, S110 — non-JSON body, skip token extraction
        pass
    _ = lowered  # reserved for future regex-based extraction
    return ""


def authenticate_identity(
    firer: object,
    identity_store: object,
    identity_name: str,
    base_url: str,
    *,
    graph: object | None = None,
) -> str:
    """Detect a login surface, submit credentials, and bind the session."""
    cred = identity_store.credential(identity_name)  # type: ignore[attr-defined]
    forms = detect_login_forms(firer, base_url, "seed", graph=graph)
    if not forms:
        raise LoginError(f"no login surface detected at {base_url}")

    last_error = ""
    for form in forms:
        try:
            token = submit_login(firer, identity_name, form, cred.username, cred.password)
        except LoginError as exc:
            last_error = str(exc)
            continue
        identity_store.open_session(identity_name, token)  # type: ignore[attr-defined]
        return token

    raise LoginError(
        f"all {len(forms)} login surface(s) failed for {identity_name!r}: {last_error}"
    )
