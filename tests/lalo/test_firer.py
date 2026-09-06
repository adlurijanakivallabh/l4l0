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


def test_literal_ip_target_with_embedded_control_characters_does_not_crash() -> None:
    # httpx.InvalidURL is NOT a subclass of httpx.HTTPError, and the literal-IP
    # branch of the URL-pinning helper used to return the raw url string
    # verbatim (skipping the urlsplit/urlunsplit round-trip that strips
    # control characters on the FQDN path) -- a target-influenced newline in a
    # redirect Location header reaching a literal-IP target used to crash the
    # whole firer with an uncaught InvalidURL instead of sanitizing the same
    # way the FQDN path already does.
    eng = Engagement.from_specs(["93.184.216.34"])
    guard = ScopeGuard(engagement=eng, resolver=lambda h: frozenset({"93.184.216.34"}))
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        return httpx.Response(200, content=b"ok")

    firer = HttpFirer(guard, client=httpx.Client(transport=httpx.MockTransport(handler)))
    result = firer.fire("GET", "http://93.184.216.34/path\nwith\nnewline")
    assert result.fired is True  # sanitized, not refused -- matches the FQDN path's own behavior
    assert result.status == 200
    assert seen["path"] == "/pathwithnewline"  # control characters stripped, never crashed


def test_httpx_invalid_url_from_build_request_degrades_to_a_fire_result() -> None:
    # A non-printable character urlsplit/urlunsplit does NOT strip (unlike
    # \t\r\n) but that httpx's own stricter validation still rejects -- this
    # exercises the InvalidURL except clause itself, independent of the
    # urlsplit/urlunsplit sanitization fix above.
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("must never reach the network with an invalid URL")

    firer = HttpFirer(_scope(), client=httpx.Client(transport=httpx.MockTransport(handler)))
    result = firer.fire("GET", "https://app.example.com/\x7f")
    assert result.fired is False
    assert result.error == "InvalidURL"


def test_circuit_breaker_recovers_after_its_cooldown_elapses() -> None:
    # Before the fix, is_open was never reset once tripped -- a host stayed
    # refused for the rest of the process regardless of recovery.
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] <= 2:
            raise httpx.ConnectError("boom", request=request)
        return httpx.Response(200, content=b"recovered")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = HttpFirer(_scope(), client=client, breaker_threshold=2, breaker_reset_after_s=0.0)

    for _ in range(2):
        assert firer.fire("GET", "https://app.example.com/").error == "ConnectError"

    # Zero cooldown -> the very next call is allowed through as a probe.
    probe = firer.fire("GET", "https://app.example.com/")
    assert probe.fired is True
    assert probe.status == 200
    assert probe.body == b"recovered"


def test_circuit_breaker_stays_open_before_its_cooldown_elapses() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = HttpFirer(_scope(), client=client, breaker_threshold=2, breaker_reset_after_s=9999.0)
    for _ in range(2):
        firer.fire("GET", "https://app.example.com/")
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


def test_response_body_is_capped_at_max_response_bytes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"A" * 10_000)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = HttpFirer(_scope(), client=client, max_response_bytes=100)
    result = firer.fire("GET", "https://app.example.com/")
    assert result.fired is True
    assert result.truncated is True
    # A mocked transport delivers the whole body as one chunk, well past the
    # cap on its own -- proving the final slice, not just "stop reading
    # further chunks", is what actually enforces the ceiling.
    assert len(result.body) == 100


def test_a_small_response_is_not_marked_truncated() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"hello")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = HttpFirer(_scope(), client=client, max_response_bytes=10_485_760)
    result = firer.fire("GET", "https://app.example.com/")
    assert result.truncated is False
    assert result.body == b"hello"
