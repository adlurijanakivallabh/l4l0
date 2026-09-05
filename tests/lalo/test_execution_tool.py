"""Tests for the `http` agent tool wiring."""

from __future__ import annotations

import httpx

from lalo.agent.tools import ToolRegistry
from lalo.execution import HttpFirer, ScopeGuard, build_http_tool
from lalo.execution.target import Engagement


def _tool(handler: httpx.MockTransport) -> ToolRegistry:
    eng = Engagement.from_specs(["app.example.com"])
    scope = ScopeGuard(engagement=eng, resolver=lambda h: frozenset({"93.184.216.34"}))
    firer = HttpFirer(scope, client=httpx.Client(transport=handler))
    return ToolRegistry([build_http_tool(firer)])


def test_http_tool_fires_and_captures_a_successful_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        return httpx.Response(200, headers={"x-test": "1"}, content=b"hello")

    registry = _tool(httpx.MockTransport(handler))
    result = registry.dispatch("http", {"url": "https://app.example.com/x"})
    assert result.ok is True
    assert "status=200" in result.observation
    assert "hello" in result.observation


def test_http_tool_sends_method_headers_and_body() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["header"] = request.headers.get("x-custom")
        seen["body"] = request.content
        return httpx.Response(200, content=b"ok")

    registry = _tool(httpx.MockTransport(handler))
    registry.dispatch(
        "http",
        {
            "method": "post",
            "url": "https://app.example.com/x",
            "headers": {"X-Custom": "v"},
            "body": "payload",
        },
    )
    assert seen["method"] == "POST"
    assert seen["header"] == "v"
    assert seen["body"] == b"payload"


def test_http_tool_requires_url() -> None:
    registry = _tool(httpx.MockTransport(lambda r: httpx.Response(200)))
    result = registry.dispatch("http", {})
    assert result.ok is False


def test_http_tool_defaults_to_get_even_when_method_is_an_explicit_json_null() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        return httpx.Response(200)

    registry = _tool(httpx.MockTransport(handler))
    registry.dispatch("http", {"url": "https://app.example.com/x", "method": None})
    assert seen["method"] == "GET"


def test_http_tool_reports_out_of_scope_as_a_failed_result_not_a_crash() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("must not fire out of scope")

    registry = _tool(httpx.MockTransport(handler))
    result = registry.dispatch("http", {"url": "https://evil.com/"})
    assert result.ok is False
    assert "not fired" in result.observation


def test_http_tool_marks_5xx_as_not_ok() -> None:
    registry = _tool(httpx.MockTransport(lambda r: httpx.Response(500, content=b"boom")))
    result = registry.dispatch("http", {"url": "https://app.example.com/x"})
    assert result.ok is False
    assert "status=500" in result.observation
