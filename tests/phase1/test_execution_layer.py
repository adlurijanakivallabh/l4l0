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


def test_read_only_clearance_is_per_endpoint(
    firer: RequestFirer, calls: list[httpx.Request]
) -> None:
    # Clearing /orders does not clear a different endpoint.
    firer.fire("user_a", "GET", f"{IN_SCOPE}/orders")
    with pytest.raises(ReadOnlyFirstError):
        firer.fire("user_a", "DELETE", f"{IN_SCOPE}/users/1")
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


def test_transport_error_is_audited_and_reraised() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = RequestFirer(client, ScopeGuard.from_hosts(["target.test"]))
    with pytest.raises(httpx.ConnectError):
        firer.fire("user_a", "GET", f"{IN_SCOPE}/orders")
    assert firer.audit.entries[-1].outcome == "error:ConnectError"
