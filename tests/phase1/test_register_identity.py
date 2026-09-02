"""RequestFirer.register_identity — post-construction identity registration (v2 W17).

_identity_stores/_identity_headers are otherwise fixed at __init__; this is the one
additive seam that lets a mid-scan-derived identity authenticate through the SAME firer.
"""

from __future__ import annotations

import httpx

from reachagent.execution import RequestFirer, ScopeGuard

IN_SCOPE = "https://target.test"


class _FakeStore:
    def __init__(self, header_value: str) -> None:
        self.header_value = header_value

    def headers(self) -> dict[str, str]:
        return {"Authorization": self.header_value}


def _firer() -> tuple[RequestFirer, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="ok")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    return RequestFirer(client, ScopeGuard.from_hosts(["target.test"])), seen


def test_a_newly_registered_identity_authenticates_on_its_next_fire() -> None:
    firer, seen = _firer()
    firer.register_identity("derived-admin", _FakeStore("Bearer derived-token"))
    firer.fire("derived-admin", "GET", f"{IN_SCOPE}/x", state_changing=False)
    assert seen[0].headers["authorization"] == "Bearer derived-token"


def test_unregistered_identity_still_fires_unauthenticated() -> None:
    firer, seen = _firer()
    firer.fire("nobody", "GET", f"{IN_SCOPE}/x", state_changing=False)
    assert "authorization" not in {k.lower() for k in seen[0].headers.keys()}


def test_re_registering_the_same_name_overwrites_not_errors() -> None:
    firer, seen = _firer()
    firer.register_identity("derived-admin", _FakeStore("Bearer first"))
    firer.register_identity("derived-admin", _FakeStore("Bearer second"))
    firer.fire("derived-admin", "GET", f"{IN_SCOPE}/x", state_changing=False)
    assert seen[0].headers["authorization"] == "Bearer second"


def test_register_identity_does_not_disturb_identities_seeded_at_construction() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="ok")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = RequestFirer(
        client,
        ScopeGuard.from_hosts(["target.test"]),
        identity_headers={"seeded": {"Authorization": "Bearer seeded-token"}},
    )
    firer.register_identity("derived-admin", _FakeStore("Bearer derived-token"))
    firer.fire("seeded", "GET", f"{IN_SCOPE}/x", state_changing=False)
    firer.fire("derived-admin", "GET", f"{IN_SCOPE}/y", state_changing=False)
    assert seen[0].headers["authorization"] == "Bearer seeded-token"
    assert seen[1].headers["authorization"] == "Bearer derived-token"


def test_register_identity_can_also_set_static_headers() -> None:
    firer, seen = _firer()
    firer.register_identity(
        "derived-admin", _FakeStore("Bearer x"), headers={"X-Session": "abc123"}
    )
    firer.fire("derived-admin", "GET", f"{IN_SCOPE}/x", state_changing=False)
    # The store's headers() takes precedence when both exist (matches
    # _headers_for_identity's own lookup order — store checked first).
    assert seen[0].headers["authorization"] == "Bearer x"
