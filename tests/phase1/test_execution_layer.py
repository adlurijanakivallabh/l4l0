"""Execution-layer safety controls (plan §10; docs/phase1-tasks.md Task 1).

Asserts the three DoD invariants:
  1. no request leaves the process for an out-of-scope target;
  2. no state-changing request fires before the read-only case is confirmed;
  3. every fired request is recorded in the audit log.

The "no packet left the process" claim is proven by a transport whose handler
records every call it receives — if the firer ever reached the network, the
handler list would be non-empty.
"""

from __future__ import annotations

import httpx
import pytest

from reachagent.execution import (
    OutOfScopeError,
    ReadOnlyFirstError,
    RequestFirer,
    ScopeGuard,
)

IN_SCOPE = "https://target.test"
OUT_OF_SCOPE = "https://evil.test"


@pytest.fixture
def calls() -> list[httpx.Request]:
    return []


@pytest.fixture
def firer(calls: list[httpx.Request]) -> RequestFirer:
    """A firer wired to a transport that records every request it is handed."""

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, text="ok")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    scope = ScopeGuard.from_hosts(["target.test"])
    return RequestFirer(client, scope)


def test_out_of_scope_target_never_hits_the_network(
    firer: RequestFirer, calls: list[httpx.Request]
) -> None:
    with pytest.raises(OutOfScopeError):
        firer.fire("user_a", "GET", f"{OUT_OF_SCOPE}/orders")
    assert calls == []  # no packet left the process
    # The refusal is still audited.
    assert firer.audit.entries[-1].outcome == "refused_out_of_scope"


def test_state_changing_request_refused_before_read_only_confirmed(
    firer: RequestFirer, calls: list[httpx.Request]
) -> None:
    with pytest.raises(ReadOnlyFirstError):
        firer.fire("user_a", "POST", f"{IN_SCOPE}/orders")
    assert calls == []  # nothing fired
    assert firer.audit.entries[-1].outcome == "refused_read_only_first"


def test_state_changing_request_allowed_after_read_only_confirmed(
    firer: RequestFirer, calls: list[httpx.Request]
) -> None:
    # Read-only case first — this confirms the endpoint is safe to touch.
    firer.fire("user_a", "GET", f"{IN_SCOPE}/orders")
    # Now the mutating request is permitted.
    result = firer.fire("user_a", "POST", f"{IN_SCOPE}/orders")
    assert result.status_code == 200
    assert [r.method for r in calls] == ["GET", "POST"]


def test_options_not_successful_does_not_clear_method_specific_route(
    calls: list[httpx.Request],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(405)

    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(handler)),
        ScopeGuard.from_hosts(["target.test"]),
    )
    result = firer.fire("user_a", "OPTIONS", f"{IN_SCOPE}/login")
    assert result.status_code == 405
    with pytest.raises(ReadOnlyFirstError):
        firer.fire("user_a", "POST", f"{IN_SCOPE}/login")
    assert [request.method for request in calls] == ["OPTIONS"]


def test_read_only_clearance_is_per_endpoint(
    firer: RequestFirer, calls: list[httpx.Request]
) -> None:
    # Clearing /orders does not clear a different endpoint.
    firer.fire("user_a", "GET", f"{IN_SCOPE}/orders")
    with pytest.raises(ReadOnlyFirstError):
        firer.fire("user_a", "DELETE", f"{IN_SCOPE}/users/1")
    assert [r.method for r in calls] == ["GET"]


def test_read_only_clearance_is_identity_scoped(
    firer: RequestFirer, calls: list[httpx.Request]
) -> None:
    firer.fire("user_a", "GET", f"{IN_SCOPE}/orders")
    with pytest.raises(ReadOnlyFirstError):
        firer.fire("user_b", "POST", f"{IN_SCOPE}/orders")
    assert [r.method for r in calls] == ["GET"]


def test_get_flagged_state_changing_is_gated(
    firer: RequestFirer, calls: list[httpx.Request]
) -> None:
    # A GET with a side effect must be flagged and is then gated like a mutation.
    with pytest.raises(ReadOnlyFirstError):
        firer.fire("user_a", "GET", f"{IN_SCOPE}/trigger", state_changing=True)
    assert calls == []


def test_every_fired_request_is_audited(firer: RequestFirer, calls: list[httpx.Request]) -> None:
    firer.fire("user_a", "GET", f"{IN_SCOPE}/orders")
    firer.fire("user_b", "GET", f"{IN_SCOPE}/profile")
    outcomes = [(e.identity, e.method, e.outcome) for e in firer.audit.entries]
    assert outcomes == [
        ("user_a", "GET", "fired:200"),
        ("user_b", "GET", "fired:200"),
    ]
    # Target is recorded host+path only — no query string / secrets leaked.
    assert all(e.target.startswith("https://target.test/") for e in firer.audit.entries)


def test_audit_target_excludes_query_string(
    firer: RequestFirer, calls: list[httpx.Request]
) -> None:
    firer.fire("user_a", "GET", f"{IN_SCOPE}/orders?token=secret123")
    assert firer.audit.entries[-1].target == "https://target.test/orders"
    assert "secret123" not in firer.audit.entries[-1].target


def test_transport_error_is_audited_and_reraised(monkeypatch) -> None:
    import reachagent.execution.firer as _firer_mod

    monkeypatch.setattr(_firer_mod, "_RETRY_BACKOFF", (0.0, 0.0))

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = RequestFirer(client, ScopeGuard.from_hosts(["target.test"]))
    with pytest.raises(httpx.ConnectError):
        firer.fire("user_a", "GET", f"{IN_SCOPE}/orders")
    # Read-only transport errors are retried, then marked unrecoverable honestly.
    assert firer.audit.entries[-1].outcome == "error:ConnectError:unrecoverable"


# ---------------------------------------------------------------------------
# ScopeGuard.from_raw — full-URL entries must normalize to a bare host
# ---------------------------------------------------------------------------
#
# The GUI defaults "in-scope hosts" to the confirmed target URL verbatim
# (app.py: `in_scope = ... or target`) when the operator leaves it blank —
# the overwhelmingly common case. A rule literally holding the string
# "http://localhost:3000" as its host never matches a real request's parsed
# host ("localhost"), so every single request was refused as out-of-scope
# and every default-flow GUI scan silently produced zero endpoints/findings.


def test_from_raw_normalizes_a_full_url_entry_to_its_bare_host() -> None:
    scope = ScopeGuard.from_raw("http://localhost:3000")
    assert scope.is_in_scope("http://localhost:3000/api/users")
    assert scope.is_in_scope("http://localhost:3000/")


def test_from_raw_still_accepts_a_bare_host() -> None:
    scope = ScopeGuard.from_raw("target.test")
    assert scope.is_in_scope("https://target.test/orders")


def test_from_raw_still_accepts_a_wildcard_host() -> None:
    scope = ScopeGuard.from_raw("*.target.test")
    assert scope.is_in_scope("https://api.target.test/orders")


def test_from_raw_normalizes_full_urls_in_both_in_scope_and_out_of_scope() -> None:
    scope = ScopeGuard.from_raw("http://target.test:8080", "http://admin.target.test:8080")
    assert scope.is_in_scope("http://target.test:8080/orders")
    assert not scope.is_in_scope("http://admin.target.test:8080/orders")


# ---------------------------------------------------------------------------
# ScopeGuard.from_raw — V1: path/port-narrowed entries ("don't touch /admin")
# ---------------------------------------------------------------------------


def test_from_raw_out_of_scope_entry_can_narrow_by_path() -> None:
    scope = ScopeGuard.from_raw("target.test", "target.test/admin")
    assert scope.is_in_scope("https://target.test/orders")
    assert not scope.is_in_scope("https://target.test/admin/users")
    assert not scope.is_in_scope("https://target.test/admin")


def test_from_raw_in_scope_entry_can_narrow_by_port() -> None:
    scope = ScopeGuard.from_raw("target.test:8080")
    assert scope.is_in_scope("https://target.test:8080/orders")
    assert not scope.is_in_scope("https://target.test:9090/orders")


def test_from_raw_bare_host_path_entry_keeps_default_schemes() -> None:
    scope = ScopeGuard.from_raw("target.test/api")
    assert scope.is_in_scope("https://target.test/api/users")
    assert scope.is_in_scope("http://target.test/api/users")


def test_from_raw_accepts_newline_separated_entries() -> None:
    """v3 V6: a scope textarea invites one-entry-per-line input as naturally
    as a comma-separated line."""
    scope = ScopeGuard.from_raw("target.test\nadmin.target.test\n\napi.target.test")
    assert scope.is_in_scope("https://target.test/")
    assert scope.is_in_scope("https://admin.target.test/")
    assert scope.is_in_scope("https://api.target.test/")
    assert not scope.is_in_scope("https://other.test/")


def test_from_raw_accepts_mixed_comma_and_newline_separators() -> None:
    scope = ScopeGuard.from_raw("target.test, admin.target.test\napi.target.test")
    assert scope.is_in_scope("https://target.test/")
    assert scope.is_in_scope("https://admin.target.test/")
    assert scope.is_in_scope("https://api.target.test/")
