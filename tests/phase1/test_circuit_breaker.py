"""Per-host circuit breaker (v2 W12).

Composes with ScopeGuard rather than replacing it: a host can be perfectly
in-scope and still be down. Deliberately counts ONLY transport-level failures
(a raised exception), never an HTTP status code — a 401/403/404/500 is often the
exact signal an oracle needs, not an "unhealthy host" indicator.
"""

from __future__ import annotations

import httpx
import pytest

from reachagent.execution import CircuitOpenError, RequestFirer, ScopeGuard
from reachagent.execution import firer as _firer_mod

IN_SCOPE = "https://target.test"


def _always_fails(_request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("boom")


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["target.test"]))


def test_repeated_transport_failures_open_the_circuit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_firer_mod, "_RETRY_BACKOFF", (0.0, 0.0))
    firer = _firer(_always_fails)
    threshold = _firer_mod._CIRCUIT_FAILURE_THRESHOLD
    for _ in range(threshold):
        with pytest.raises(httpx.ConnectError):
            firer.fire("anon", "GET", f"{IN_SCOPE}/x", state_changing=False)
    # The breaker is now open — the NEXT call is refused before any I/O, as a
    # CircuitOpenError, not another ConnectError.
    with pytest.raises(CircuitOpenError):
        firer.fire("anon", "GET", f"{IN_SCOPE}/x", state_changing=False)
    assert firer.audit.entries[-1].outcome == "refused_circuit_open"


def test_an_open_circuit_refuses_before_any_network_io(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_firer_mod, "_RETRY_BACKOFF", (0.0, 0.0))
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        raise httpx.ConnectError("boom")

    firer = _firer(handler)
    threshold = _firer_mod._CIRCUIT_FAILURE_THRESHOLD
    for _ in range(threshold):
        with pytest.raises(httpx.ConnectError):
            firer.fire("anon", "GET", f"{IN_SCOPE}/x", state_changing=False)
    count_before = len(seen)
    with pytest.raises(CircuitOpenError):
        firer.fire("anon", "GET", f"{IN_SCOPE}/x", state_changing=False)
    assert len(seen) == count_before  # no new request reached the transport


def test_http_error_status_codes_never_count_as_circuit_failures() -> None:
    """A 500/403/404 is a meaningful oracle signal, not a "host is down" indicator —
    it must NEVER contribute to opening the breaker."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="server error")

    firer = _firer(handler)
    threshold = _firer_mod._CIRCUIT_FAILURE_THRESHOLD
    for _ in range(threshold * 3):
        result = firer.fire("anon", "GET", f"{IN_SCOPE}/x", state_changing=False)
        assert result.status_code == 500  # never refused by the breaker


def test_a_successful_request_resets_the_failure_count(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_firer_mod, "_RETRY_BACKOFF", (0.0, 0.0))
    healthy = {"now": False}

    def toggle(_request: httpx.Request) -> httpx.Response:
        if not healthy["now"]:
            raise httpx.ConnectError("boom")
        return httpx.Response(200, text="ok")

    firer = _firer(toggle)
    threshold = _firer_mod._CIRCUIT_FAILURE_THRESHOLD

    # threshold - 1 outer fire() calls each exhaust all internal retries and raise —
    # one short of tripping the breaker.
    for _ in range(threshold - 1):
        with pytest.raises(httpx.ConnectError):
            firer.fire("anon", "GET", f"{IN_SCOPE}/a", state_changing=False)

    # One clean success resets the counter to zero.
    healthy["now"] = True
    result = firer.fire("anon", "GET", f"{IN_SCOPE}/b", state_changing=False)
    assert result.status_code == 200

    # A fresh run of (threshold - 1) failures now must NOT trip the breaker — the
    # earlier near-miss did not carry over past the intervening success.
    healthy["now"] = False
    for _ in range(threshold - 1):
        with pytest.raises(httpx.ConnectError):
            firer.fire("anon", "GET", f"{IN_SCOPE}/c", state_changing=False)
    healthy["now"] = True
    result = firer.fire("anon", "GET", f"{IN_SCOPE}/d", state_changing=False)
    assert result.status_code == 200  # still closed, not refused by the breaker


def test_circuit_is_per_host_not_global() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "target.test":
            raise httpx.ConnectError("boom")
        return httpx.Response(200, text="ok")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = RequestFirer(client, ScopeGuard.from_hosts(["target.test", "other.test"]))
    threshold = _firer_mod._CIRCUIT_FAILURE_THRESHOLD
    for _ in range(threshold):
        with pytest.raises(httpx.ConnectError):
            firer.fire("anon", "GET", "https://target.test/x", state_changing=False)
    with pytest.raises(CircuitOpenError):
        firer.fire("anon", "GET", "https://target.test/x", state_changing=False)
    # A different, healthy host is completely unaffected.
    result = firer.fire("anon", "GET", "https://other.test/x", state_changing=False)
    assert result.status_code == 200


def test_circuit_check_runs_after_scope_never_before() -> None:
    """An out-of-scope host is refused by ScopeGuard, not the circuit breaker —
    scope stays the first, non-negotiable gate."""
    firer = _firer(lambda _r: httpx.Response(200))
    from reachagent.execution import OutOfScopeError

    with pytest.raises(OutOfScopeError):
        firer.fire("anon", "GET", "https://evil.test/x", state_changing=False)
    assert firer.audit.entries[-1].outcome == "refused_out_of_scope"
