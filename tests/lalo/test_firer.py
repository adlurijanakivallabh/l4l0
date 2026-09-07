"""Tests for the HTTP firer: scope integration, capture, circuit breaker, and
the pinned-IP dial mechanism (the real DNS-rebinding defense, not just a check)."""

from __future__ import annotations

import threading
import time

import httpx
import pytest

import lalo.execution.firer as firer_module
from lalo.execution.firer import HttpFirer, probe_reachability
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


class _SlowBreaker:
    """Stands in for firer_module._Breaker with the same duck-typed surface
    (fire() only ever touches attributes/should_probe(), never the real
    dataclass type), except `failures` is a property with a real
    time.sleep() between reading and writing it.

    A bare `breaker.failures += 1` turns out to execute as an
    effectively-atomic 2-3 bytecode sequence under CPython's GIL in
    practice -- confirmed by hand, 640k unlocked increments across 32
    threads on this box never lost one, because the eval loop's GIL-yield
    checks land on backward branches/calls, not mid-expression. Production's
    actual race window is real (many concurrent fire() calls each doing a
    genuine, variable-latency network round trip before reaching this same
    increment), just too timing-dependent to force via thread scheduling
    alone in a fast, deterministic test. `time.sleep` genuinely releases the
    GIL, so this reproduces the same shape of interleaving on demand instead
    of hoping for it.
    """

    def __init__(self, threshold: int = 5, reset_after_s: float = 30.0) -> None:
        self.threshold = threshold
        self.reset_after_s = reset_after_s
        self._failures = 0
        self.is_open = False
        self.opened_at = 0.0

    @property
    def failures(self) -> int:
        current = self._failures
        time.sleep(0.005)
        return current

    @failures.setter
    def failures(self, value: int) -> None:
        time.sleep(0.005)
        self._failures = value

    def should_probe(self) -> bool:
        return (time.monotonic() - self.opened_at) >= self.reset_after_s


def test_breaker_failure_count_is_not_corrupted_under_concurrent_fire_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """fire_concurrent fires up to 50 requests to the same host through one
    shared HttpFirer at once (and spawn_agents does the same for the whole
    firer across concurrent agents). Without a lock around the breaker's
    read-modify-write, concurrent `breaker.failures += 1` calls can race and
    lose updates -- reproduced deterministically here via `_SlowBreaker`
    (see its own docstring for why a plain unlocked race is otherwise too
    timing-dependent to force). breaker_threshold is set above the thread
    count so the breaker never actually trips, isolating the counter race
    itself from the expected, harmless overshoot legitimate concurrency
    causes once tripping starts short-circuiting some callers early.
    """
    monkeypatch.setattr(firer_module, "_Breaker", _SlowBreaker)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = HttpFirer(
        _scope(), client=client, breaker_threshold=1_000_000, breaker_reset_after_s=9999.0
    )

    n_threads = 8
    barrier = threading.Barrier(n_threads)

    def _loop() -> None:
        barrier.wait()
        firer.fire("GET", "https://app.example.com/")

    threads = [threading.Thread(target=_loop) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    breaker = firer._breaker("app.example.com")
    assert breaker.failures == n_threads
    assert breaker.is_open is False


def test_breaker_lock_does_not_serialize_concurrent_network_io() -> None:
    """The fix must lock ONLY the breaker-state check/update, never the
    network I/O -- locking the whole fire() call would serialize every
    concurrent request and defeat fire_concurrent's entire purpose
    (simultaneity for race-condition testing). Each mocked request sleeps;
    if fire() were serialized, total wall-clock would be roughly
    n_threads * delay_s instead of close to a single delay_s.
    """
    delay_s = 0.2

    def handler(request: httpx.Request) -> httpx.Response:
        time.sleep(delay_s)
        return httpx.Response(200, content=b"ok")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    firer = HttpFirer(_scope(), client=client)

    n_threads = 8
    barrier = threading.Barrier(n_threads)

    def _loop() -> None:
        barrier.wait()
        firer.fire("GET", "https://app.example.com/")

    threads = [threading.Thread(target=_loop) for _ in range(n_threads)]
    start = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - start

    assert elapsed < delay_s * (n_threads / 2)


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


def test_probe_reachability_reports_a_responding_concrete_host() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "HEAD"
        return httpx.Response(200)

    eng = Engagement.from_specs(["app.example.com"])
    scope = ScopeGuard(engagement=eng, resolver=lambda h: frozenset({_PINNED_IP}))
    firer = HttpFirer(scope, client=httpx.Client(transport=httpx.MockTransport(handler)))
    results = probe_reachability(eng, firer)
    assert results["app.example.com"] == (True, "responded 200")


def test_probe_reachability_skips_glob_hosts() -> None:
    eng = Engagement.from_specs(["*.example.com"])
    scope = ScopeGuard(engagement=eng, resolver=lambda h: frozenset({_PINNED_IP}))

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("a glob rule has no single host to probe")

    firer = HttpFirer(scope, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert probe_reachability(eng, firer) == {}


def test_probe_reachability_falls_back_to_http_when_https_is_not_restricted() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "https":
            raise httpx.ConnectError("refused")
        return httpx.Response(200)

    eng = Engagement.from_specs(["app.example.com"])
    scope = ScopeGuard(engagement=eng, resolver=lambda h: frozenset({_PINNED_IP}))
    firer = HttpFirer(scope, client=httpx.Client(transport=httpx.MockTransport(handler)))
    results = probe_reachability(eng, firer)
    assert results["app.example.com"] == (True, "responded 200 (http)")


def test_probe_reachability_reports_unreachable_when_nothing_responds() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    eng = Engagement.from_specs(["app.example.com"])
    scope = ScopeGuard(engagement=eng, resolver=lambda h: frozenset({_PINNED_IP}))
    firer = HttpFirer(scope, client=httpx.Client(transport=httpx.MockTransport(handler)))
    reachable, _reason = probe_reachability(eng, firer)["app.example.com"]
    assert reachable is False
