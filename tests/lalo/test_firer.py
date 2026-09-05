"""Tests for the HTTP firer: scope integration, capture, circuit breaker, and
the pinned-IP dial mechanism (the real DNS-rebinding defense, not just a check)."""

from __future__ import annotations

import httpx

from lalo.execution.firer import HttpFirer
from lalo.execution.scope import ScopeGuard
from lalo.execution.target import Engagement

_PINNED_IP = "93.184.216.34"


def _scope() -> ScopeGuard:
    eng = Engagement.from_specs(["example.com", "*.example.com"])
    return ScopeGuard(engagement=eng, resolver=lambda h: frozenset({_PINNED_IP}))


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


def test_firer_dials_the_pinned_ip_not_the_hostname() -> None:
    # The load-bearing correctness fix: the OUTBOUND request must target the
    # pinned IP literal, with the real hostname preserved only in the Host
    # header (and, for https, the SNI extension) — never re-resolved by httpx.
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url_host"] = request.url.host
        seen["host_header"] = request.headers.get("host")
        seen["sni"] = request.extensions.get("sni_hostname")
        return httpx.Response(200, content=b"ok")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = HttpFirer(_scope(), client=client)
    firer.fire("GET", "https://app.example.com/path")
    assert seen["url_host"] == _PINNED_IP
    assert seen["host_header"] == "app.example.com"
    assert seen["sni"] == "app.example.com"


def test_out_of_engagement_is_not_fired() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
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
    blocked = firer.fire("GET", "https://app.example.com/")
    assert blocked.fired is False
    assert blocked.scope_reason == "circuit_open"


def test_dns_resolution_failure_does_not_fire_blind() -> None:
    guard = ScopeGuard(
        engagement=Engagement.from_specs(["nowhere.invalid"]), resolver=lambda h: frozenset()
    )

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("must not fire without a pinned IP")

    firer = HttpFirer(guard, client=httpx.Client(transport=httpx.MockTransport(handler)))
    result = firer.fire("GET", "http://nowhere.invalid/")
    assert result.fired is False
    assert result.error == "dns_resolution_failed"
