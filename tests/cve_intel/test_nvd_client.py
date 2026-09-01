"""Hermetic tests for the NVD/EPSS client — rate limiting, backoff, caching,
fail-open behavior. No real network calls: HttpClient is always a fake."""

from __future__ import annotations

import httpx
import pytest

import reachagent.cve_intel.nvd_client as nvd_module
from reachagent.cve_intel.nvd_client import (
    CveMatch,
    _RateLimiter,
    enrich_with_epss,
    lookup_cves,
    lookup_epss,
)


@pytest.fixture(autouse=True)
def _reset_module_state(monkeypatch):  # noqa: ANN001
    """Every test gets fresh caches/limiters — this module's state is
    process-global by design (cross-call caching), so tests must isolate it."""
    monkeypatch.setattr(nvd_module, "_nvd_cache", {})
    monkeypatch.setattr(nvd_module, "_epss_cache", {})
    monkeypatch.setattr(
        nvd_module, "_nvd_limiter", _RateLimiter(max_requests=5, window_seconds=30.0)
    )
    monkeypatch.setattr(
        nvd_module, "_epss_limiter", _RateLimiter(max_requests=10, window_seconds=30.0)
    )


_NVD_BODY = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2019-0232",
                "descriptions": [{"lang": "en", "value": "A CGI Servlet vulnerability."}],
                "metrics": {
                    "cvssMetricV31": [{"baseSeverity": "CRITICAL", "cvssData": {"baseScore": 9.8}}]
                },
            }
        }
    ]
}


class _FakeResponse:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> object:
        return self._payload


class _FakeClient:
    def __init__(self, responses: list) -> None:  # noqa: ANN001
        self._responses = list(responses)
        self.calls = 0

    def get(self, url: str, *, params: dict[str, str]) -> httpx.Response:
        self.calls += 1
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def test_lookup_cves_parses_a_real_shaped_response() -> None:
    client = _FakeClient([_FakeResponse(200, _NVD_BODY)])
    matches = lookup_cves("Apache Tomcat", "7.0.92", client=client)
    assert len(matches) == 1
    assert matches[0].cve_id == "CVE-2019-0232"
    assert matches[0].cvss_score == 9.8
    assert matches[0].severity == "critical"
    assert "CGI Servlet" in matches[0].summary


def test_lookup_cves_blank_input_never_calls_the_client() -> None:
    client = _FakeClient([])
    assert lookup_cves("", "1.0", client=client) == []
    assert lookup_cves("product", "", client=client) == []
    assert client.calls == 0


def test_lookup_cves_caches_a_successful_result() -> None:
    client = _FakeClient([_FakeResponse(200, _NVD_BODY)])
    lookup_cves("Apache Tomcat", "7.0.92", client=client)
    lookup_cves("Apache Tomcat", "7.0.92", client=client)  # second call, same key
    assert client.calls == 1


def test_lookup_cves_network_error_fails_open_to_empty_list(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(nvd_module.time, "sleep", lambda _seconds: None)
    client = _FakeClient(
        [httpx.ConnectError("boom"), httpx.ConnectError("boom"), httpx.ConnectError("boom")]
    )
    assert lookup_cves("Apache Tomcat", "7.0.92", client=client) == []


def test_lookup_cves_non_200_status_fails_open() -> None:
    client = _FakeClient([_FakeResponse(500, {})])
    assert lookup_cves("Apache Tomcat", "7.0.92", client=client) == []


def test_lookup_cves_malformed_json_fails_open() -> None:
    class _BoomResponse:
        status_code = 200

        def json(self) -> object:
            raise ValueError("not json")

    client = _FakeClient([_BoomResponse()])
    assert lookup_cves("Apache Tomcat", "7.0.92", client=client) == []


def test_lookup_cves_retries_a_retryable_status_then_succeeds(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(nvd_module.time, "sleep", lambda _seconds: None)
    client = _FakeClient([_FakeResponse(503, {}), _FakeResponse(200, _NVD_BODY)])
    matches = lookup_cves("Apache Tomcat", "7.0.92", client=client)
    assert len(matches) == 1
    assert client.calls == 2


def test_lookup_cves_rate_limit_exhausted_fails_open_without_calling_client(monkeypatch) -> None:  # noqa: ANN001
    limiter = _RateLimiter(max_requests=1, window_seconds=30.0)
    limiter.allow()  # consume the only slot
    monkeypatch.setattr(nvd_module, "_nvd_limiter", limiter)
    client = _FakeClient([])
    assert lookup_cves("Apache Tomcat", "7.0.92", client=client) == []
    assert client.calls == 0


def test_lookup_epss_parses_a_real_shaped_response() -> None:
    payload = {"data": [{"cve": "CVE-2019-0232", "epss": "0.973"}]}
    client = _FakeClient([_FakeResponse(200, payload)])
    assert lookup_epss("CVE-2019-0232", client=client) == pytest.approx(0.973)


def test_lookup_epss_blank_cve_never_calls_the_client() -> None:
    client = _FakeClient([])
    assert lookup_epss("", client=client) is None
    assert client.calls == 0


def test_lookup_epss_no_data_returns_none() -> None:
    client = _FakeClient([_FakeResponse(200, {"data": []})])
    assert lookup_epss("CVE-2019-0232", client=client) is None


def test_lookup_epss_failure_fails_open_to_none(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(nvd_module.time, "sleep", lambda _seconds: None)
    client = _FakeClient(
        [httpx.ConnectError("boom"), httpx.ConnectError("boom"), httpx.ConnectError("boom")]
    )
    assert lookup_epss("CVE-2019-0232", client=client) is None


def test_enrich_with_epss_attaches_score_per_match() -> None:
    client = _FakeClient([_FakeResponse(200, {"data": [{"cve": "CVE-2019-0232", "epss": "0.5"}]})])
    match = CveMatch(cve_id="CVE-2019-0232", cvss_score=9.8, severity="critical", summary="x")
    enriched = enrich_with_epss([match], client=client)
    assert enriched[0].epss_score == pytest.approx(0.5)
    assert enriched[0].cve_id == "CVE-2019-0232"  # everything else carried through unchanged


def test_rate_limiter_allows_up_to_the_configured_max() -> None:
    limiter = _RateLimiter(max_requests=2, window_seconds=30.0)
    assert limiter.allow() is True
    assert limiter.allow() is True
    assert limiter.allow() is False
