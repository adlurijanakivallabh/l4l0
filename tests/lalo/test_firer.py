"""Tests for the HTTP firer (scope integration + capture + circuit breaker)."""

from __future__ import annotations

import httpx

from lalo.execution.firer import HttpFirer
from lalo.execution.scope import ScopeGuard
from lalo.execution.target import Engagement


def _scope() -> ScopeGuard:
    eng = Engagement.from_specs(["example.com", "*.example.com"])
    return ScopeGuard(engagement=eng, resolver=lambda h: frozenset({"93.184.216.34"}))


def test_allowed_request_is_captured() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"x-test": "1"}, content=b"hello")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = HttpFirer(_scope(), client=client)
    result = firer.fire("GET", "https://app.example.com/")
    assert result.fired is True
    assert result.status == 200
    assert result.body == b"hello"
    assert result.headers["x-test"] == "1"
    assert result.elapsed_ms is not None


def test_out_of_engagement_is_not_fired() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not run
        raise AssertionError("should not fire out of engagement")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = HttpFirer(_scope(), client=client)
    result = firer.fire("GET", "https://evil.com/")
    assert result.fired is False
    assert result.scope_reason == "out_of_engagement"
    assert result.status is None


def test_transport_errors_trip_the_circuit_breaker() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = HttpFirer(_scope(), client=client, breaker_threshold=3)
    for _ in range(3):
        r = firer.fire("GET", "https://app.example.com/")
        assert r.error == "ConnectError"
    # Breaker now open: next call is skipped, not fired.
    blocked = firer.fire("GET", "https://app.example.com/")
    assert blocked.fired is False
    assert blocked.scope_reason == "circuit_open"
