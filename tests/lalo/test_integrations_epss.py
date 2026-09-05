"""Tests for CVE/EPSS enrichment - a prioritization fact only."""

from __future__ import annotations

import httpx

from lalo.integrations.epss import build_epss_tool, fetch_epss_score

_GOOD_PAYLOAD = {
    "status": "OK",
    "status-code": 200,
    "data": [{"cve": "CVE-2024-12345", "epss": "0.234000000", "percentile": "0.567000000"}],
}


def _client(handler: httpx.MockTransport) -> httpx.Client:
    return httpx.Client(transport=handler)


def test_fetch_epss_score_parses_a_successful_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["cve"] == "CVE-2024-12345"
        return httpx.Response(200, json=_GOOD_PAYLOAD)

    result = fetch_epss_score("CVE-2024-12345", client=_client(httpx.MockTransport(handler)))
    assert result is not None
    assert result.cve == "CVE-2024-12345"
    assert result.score == 0.234
    assert result.percentile == 0.567


def test_fetch_epss_score_returns_none_for_an_unknown_cve() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "OK", "data": []})

    result = fetch_epss_score("CVE-0000-00000", client=_client(httpx.MockTransport(handler)))
    assert result is None


def test_fetch_epss_score_returns_none_on_http_error_never_raises() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    result = fetch_epss_score("CVE-2024-12345", client=_client(httpx.MockTransport(handler)))
    assert result is None


def test_fetch_epss_score_returns_none_on_malformed_json_never_raises() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json")

    result = fetch_epss_score("CVE-2024-12345", client=_client(httpx.MockTransport(handler)))
    assert result is None


def test_fetch_epss_score_returns_none_on_valid_json_non_dict_top_level_never_raises() -> None:
    """Valid JSON whose top-level value isn't an object (a bare null/list/
    string/number - plausible from a proxy, WAF, or rate-limit page) must not
    crash with AttributeError from calling .get() on a non-dict."""
    for body in (b"null", b"[]", b'"error"', b"42"):

        def handler(_request: httpx.Request, body: bytes = body) -> httpx.Response:
            return httpx.Response(200, content=body)

        result = fetch_epss_score("CVE-2024-12345", client=_client(httpx.MockTransport(handler)))
        assert result is None, f"body={body!r} should degrade to None, not raise"


def test_fetch_epss_score_returns_none_on_a_missing_field_never_raises() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"cve": "CVE-2024-12345"}]})

    result = fetch_epss_score("CVE-2024-12345", client=_client(httpx.MockTransport(handler)))
    assert result is None


def test_fetch_epss_score_returns_none_on_a_connection_error_never_raises() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("dns failure")

    result = fetch_epss_score("CVE-2024-12345", client=_client(httpx.MockTransport(handler)))
    assert result is None


def test_build_epss_tool_reports_the_score_and_states_it_is_prioritization_only() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_GOOD_PAYLOAD)

    tool = build_epss_tool(client=_client(httpx.MockTransport(handler)))
    result = tool.run({"cve": "CVE-2024-12345"})
    assert result.ok is True
    assert "score=0.234" in result.observation
    assert "does not affect CVSS or confidence scoring" in result.observation


def test_build_epss_tool_requires_a_cve() -> None:
    tool = build_epss_tool()
    result = tool.run({})
    assert result.ok is False
    assert "'cve' is required" in result.observation


def test_build_epss_tool_requires_a_cve_even_as_explicit_json_null() -> None:
    tool = build_epss_tool()
    result = tool.run({"cve": None})
    assert result.ok is False
    assert "'cve' is required" in result.observation


def test_build_epss_tool_reports_no_data_without_crashing() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": []})

    tool = build_epss_tool(client=_client(httpx.MockTransport(handler)))
    result = tool.run({"cve": "CVE-0000-00000"})
    assert result.ok is False
    assert "no EPSS data available" in result.observation
