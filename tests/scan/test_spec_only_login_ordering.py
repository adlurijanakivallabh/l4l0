"""A pure JSON API (VAmPI-shaped) whose login endpoint is ONLY discoverable via
its own OpenAPI spec -- never a common HTML alias (/login, /auth, ...), never
linked from a crawled page -- must still authenticate. Live-verification
finding: spec-first API discovery used to run AFTER identity binding, so
credentials correctly supplied by the operator still failed with
"no login surface detected" because the login endpoint hadn't been
materialized into the graph yet when detect_login_forms looked for it.
"""

from __future__ import annotations

import httpx

from reachagent.identity.store import IdentityStore
from reachagent.scan.entrypoint import scan_target

_OPENAPI = {
    "openapi": "3.0.0",
    "paths": {
        "/users/v1/login": {
            "post": {
                "parameters": [
                    {"name": "username", "in": "body"},
                    {"name": "password", "in": "body"},
                ]
            }
        },
        "/users/v1/{username}": {
            "get": {"parameters": [{"name": "username", "in": "path"}]},
        },
    },
}


def _handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/openapi.json":
        return httpx.Response(200, json=_OPENAPI)
    if path == "/users/v1/login" and request.method == "POST":
        return httpx.Response(
            200,
            json={"auth_token": "sometoken"},
            headers={"set-cookie": "session=abc123; Path=/"},
        )
    return httpx.Response(404, text="not found")


def test_spec_only_login_endpoint_still_authenticates() -> None:
    identities = IdentityStore.from_identities_list(
        [{"name": "name1", "username": "name1", "password": "pass1", "role": "user"}]
    )
    result = scan_target(
        base_url="https://example.com",
        in_scope="example.com",
        dry_run=False,
        transport=httpx.MockTransport(_handler),
        identities=identities,
    )
    assert result["graph"].sessions(), "the spec-only login endpoint must still be found and used"


def test_endpoint_discovery_event_precedes_authentication_event() -> None:
    events: list = []
    identities = IdentityStore.from_identities_list(
        [{"name": "name1", "username": "name1", "password": "pass1", "role": "user"}]
    )
    scan_target(
        base_url="https://example.com",
        in_scope="example.com",
        dry_run=False,
        transport=httpx.MockTransport(_handler),
        identities=identities,
        events=events,
    )
    tool_names = [getattr(e, "details", {}).get("tool") for e in events]
    tool_names = [name for name in tool_names if name in ("surface-mapper", "authentication")]
    assert tool_names[0] == "surface-mapper", (
        "spec discovery must run before authentication so a spec-only login "
        f"endpoint is already in the graph; saw order: {tool_names}"
    )
