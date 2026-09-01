"""One identity's login failure must not abort a scan where another
identity already has a working session (real case hit against a live
target: jsmith authenticated fine, admin's login "succeeded" with no
session material captured -- the whole scan used to hard-block on that
second failure even though jsmith's session was already good).
"""

from __future__ import annotations

from urllib.parse import parse_qs

import httpx

from reachagent.identity.store import IdentityStore
from reachagent.scan.entrypoint import scan_target

_LOGIN_PAGE = """
<html><body>
<form action="/doLogin" method="post">
  <input type="text" name="username"/>
  <input type="password" name="password"/>
</form>
</body></html>
"""


def _handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/" or path == "/login":
        return httpx.Response(200, text=_LOGIN_PAGE)
    if path == "/doLogin":
        fields = parse_qs(request.content.decode())
        username = fields.get("username", [""])[0]
        if username == "gooduser":
            return httpx.Response(200, headers={"set-cookie": "session=abc123; Path=/"})
        # "Succeeds" (200, no error) but captures no session material at all --
        # exactly the real failure mode this test reproduces.
        return httpx.Response(200, text="<html>welcome</html>")
    return httpx.Response(404, text="not found")


def _identities() -> IdentityStore:
    return IdentityStore.from_identities_list(
        [
            {"name": "gooduser", "username": "gooduser", "password": "pw1", "role": "user"},
            {"name": "baduser", "username": "baduser", "password": "pw2", "role": "admin"},
        ]
    )


def test_one_identitys_login_failure_does_not_abort_the_scan() -> None:
    result = scan_target(
        base_url="https://example.com",
        in_scope="example.com",
        dry_run=False,
        transport=httpx.MockTransport(_handler),
        identities=_identities(),
    )
    assert result["graph"].sessions(), "gooduser's session must still be bound"


def test_events_report_the_failed_identity_without_a_hard_block() -> None:
    events: list = []
    scan_target(
        base_url="https://example.com",
        in_scope="example.com",
        dry_run=False,
        transport=httpx.MockTransport(_handler),
        identities=_identities(),
        events=events,
    )
    auth_events = [e for e in events if getattr(e, "details", {}).get("tool") == "authentication"]
    outcomes = {e.details.get("identity"): e.details.get("outcome") for e in auth_events}
    assert outcomes.get("gooduser") == "authenticated"
    assert outcomes.get("baduser") == "failed"
    assert "blocked" not in outcomes.values()


def test_every_identity_failing_is_still_a_hard_stop() -> None:
    from reachagent.identity.login import LoginError

    def _all_fail(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    identities = IdentityStore.from_identities_list(
        [{"name": "nobody", "username": "nobody", "password": "pw", "role": "user"}]
    )
    try:
        scan_target(
            base_url="https://example.com",
            in_scope="example.com",
            dry_run=False,
            transport=httpx.MockTransport(_all_fail),
            identities=identities,
        )
    except LoginError:
        return
    raise AssertionError("a scan where every configured identity fails must still raise")
