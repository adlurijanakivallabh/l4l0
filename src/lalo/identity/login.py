"""Multi-scheme login flows that produce SessionMaterial via the scoped firer."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode

from ..execution.firer import HttpFirer
from .store import SessionMaterial


def _dig(data: Any, dotted: str) -> str | None:
    node: Any = data
    for key in dotted.split("."):
        if isinstance(node, dict) and key in node:
            node = node[key]
        else:
            return None
    return str(node) if isinstance(node, str | int) else None


def _parse_set_cookie(header_value: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for chunk in header_value.split(","):
        first = chunk.split(";", 1)[0].strip()
        if "=" in first:
            name, _, value = first.partition("=")
            if name and name.lower() not in {"path", "domain", "expires", "max-age", "samesite"}:
                cookies[name] = value
    return cookies


def json_login(
    firer: HttpFirer,
    url: str,
    body: dict[str, object],
    *,
    token_field: str = "token",  # noqa: S107 - JSON field NAME to read, not a secret
) -> SessionMaterial:
    """POST JSON credentials; extract a bearer token from the response body."""
    resp = firer.fire(
        "POST",
        url,
        headers={"content-type": "application/json"},
        content=json.dumps(body).encode("utf-8"),
    )
    if resp.status and 200 <= resp.status < 300 and resp.body:
        try:
            data = json.loads(resp.body)
        except (json.JSONDecodeError, ValueError):
            return SessionMaterial()
        token = _dig(data, token_field)
        if token:
            return SessionMaterial(headers={"Authorization": f"Bearer {token}"})
    return SessionMaterial()


def form_login(firer: HttpFirer, url: str, data: dict[str, str]) -> SessionMaterial:
    """POST form credentials; capture Set-Cookie session material."""
    resp = firer.fire(
        "POST",
        url,
        headers={"content-type": "application/x-www-form-urlencoded"},
        content=urlencode(data).encode("utf-8"),
    )
    cookies = _parse_set_cookie(resp.headers.get("set-cookie", ""))
    return SessionMaterial(cookies=cookies)
