"""Tests for the `http`, `fire_concurrent`, and `diff_responses` agent tool wiring."""

from __future__ import annotations

from collections.abc import Callable
from itertools import count
from types import SimpleNamespace

import httpx

from lalo.agent.tools import ToolRegistry
from lalo.execution import FireResult, HttpFirer, ScopeGuard, build_http_tool
from lalo.execution.target import Engagement
from lalo.execution.tool import build_diff_responses_tool, build_fire_concurrent_tool


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


def _fake_firer(fire_fn: Callable[..., FireResult]) -> SimpleNamespace:
    """A `firer` stand-in whose `.fire` is the given callable — no real HTTP
    layer involved, per fire_concurrent/diff_responses firing off of a plain
    `firer.fire(...)` call and nothing else.
    """
    return SimpleNamespace(fire=fire_fn)


def _ok(method: str, url: str, *, status: int = 200, body: bytes = b"") -> FireResult:
    return FireResult(
        method=method,
        url=url,
        fired=True,
        scope_reason="in_scope",
        status=status,
        body=body,
        elapsed_ms=1.0,
    )


# --- fire_concurrent ---------------------------------------------------


def test_fire_concurrent_reports_every_result_in_index_order_with_a_mix_of_outcomes() -> None:
    counter = count()

    def fire(method, url, *, headers=None, content=None):
        n = next(counter)
        if n % 2 == 0:
            raise RuntimeError("boom")
        return _ok(method, url, status=200 + n)

    registry = ToolRegistry([build_fire_concurrent_tool(_fake_firer(fire))])
    result = registry.dispatch("fire_concurrent", {"url": "https://app.example.com/x", "count": 6})

    lines = result.observation.splitlines()
    assert len(lines) == 6
    for i, line in enumerate(lines):
        assert line.startswith(f"[{i}] ")
    assert any("exception: RuntimeError: boom" in line for line in lines)
    assert any("status=" in line for line in lines)
    assert result.ok is True


def test_fire_concurrent_ok_is_false_when_every_request_raises() -> None:
    def fire(method, url, *, headers=None, content=None):
        raise RuntimeError("boom")

    registry = ToolRegistry([build_fire_concurrent_tool(_fake_firer(fire))])
    result = registry.dispatch("fire_concurrent", {"url": "https://app.example.com/x", "count": 4})

    lines = result.observation.splitlines()
    assert len(lines) == 4
    assert all("exception: RuntimeError: boom" in line for line in lines)
    assert result.ok is False


def test_fire_concurrent_clamps_count_to_50() -> None:
    calls: list[int] = []

    def fire(method, url, *, headers=None, content=None):
        calls.append(1)
        return _ok(method, url)

    registry = ToolRegistry([build_fire_concurrent_tool(_fake_firer(fire))])
    result = registry.dispatch(
        "fire_concurrent", {"url": "https://app.example.com/x", "count": 1000}
    )

    assert len(calls) == 50
    lines = result.observation.splitlines()
    assert len(lines) == 50
    assert lines[-1].startswith("[49] ")


def test_fire_concurrent_clamps_count_to_at_least_1() -> None:
    calls: list[int] = []

    def fire(method, url, *, headers=None, content=None):
        calls.append(1)
        return _ok(method, url)

    registry = ToolRegistry([build_fire_concurrent_tool(_fake_firer(fire))])
    result = registry.dispatch("fire_concurrent", {"url": "https://app.example.com/x", "count": 0})

    assert len(calls) == 1
    assert result.observation.splitlines() == ["[0] status=200 elapsed_ms=1 len=0"]


def test_fire_concurrent_defaults_count_to_10_when_count_is_an_explicit_json_null() -> None:
    calls: list[int] = []

    def fire(method, url, *, headers=None, content=None):
        calls.append(1)
        return _ok(method, url)

    registry = ToolRegistry([build_fire_concurrent_tool(_fake_firer(fire))])
    registry.dispatch("fire_concurrent", {"url": "https://app.example.com/x", "count": None})

    assert len(calls) == 10


def test_fire_concurrent_defaults_count_to_10_when_omitted() -> None:
    calls: list[int] = []

    def fire(method, url, *, headers=None, content=None):
        calls.append(1)
        return _ok(method, url)

    registry = ToolRegistry([build_fire_concurrent_tool(_fake_firer(fire))])
    registry.dispatch("fire_concurrent", {"url": "https://app.example.com/x"})

    assert len(calls) == 10


def test_fire_concurrent_rejects_a_non_numeric_count_without_crashing() -> None:
    def fire(method, url, *, headers=None, content=None):  # pragma: no cover
        raise AssertionError("must not fire with a malformed count")

    registry = ToolRegistry([build_fire_concurrent_tool(_fake_firer(fire))])
    result = registry.dispatch(
        "fire_concurrent", {"url": "https://app.example.com/x", "count": "lots"}
    )
    assert result.ok is False
    assert "count" in result.observation


def test_fire_concurrent_requires_url() -> None:
    def fire(method, url, *, headers=None, content=None):
        raise AssertionError("must not fire without a url")  # pragma: no cover

    registry = ToolRegistry([build_fire_concurrent_tool(_fake_firer(fire))])
    result = registry.dispatch("fire_concurrent", {})
    assert result.ok is False


# --- diff_responses ------------------------------------------------------


def test_diff_responses_shows_lines_that_differ_between_the_two_bodies() -> None:
    def fire(method, url, *, headers=None, content=None):
        body = b"same\nold-value\n" if url.endswith("/a") else b"same\nnew-value\n"
        return _ok(method, url, body=body)

    registry = ToolRegistry([build_diff_responses_tool(_fake_firer(fire))])
    result = registry.dispatch(
        "diff_responses",
        {"url_a": "https://app.example.com/a", "url_b": "https://app.example.com/b"},
    )

    assert "old-value" in result.observation
    assert "new-value" in result.observation
    assert "a: status=200" in result.observation
    assert "b: status=200" in result.observation


def test_diff_responses_identical_bodies_report_zero_changed_lines() -> None:
    def fire(method, url, *, headers=None, content=None):
        return _ok(method, url, body=b"same\nbody\n")

    registry = ToolRegistry([build_diff_responses_tool(_fake_firer(fire))])
    result = registry.dispatch(
        "diff_responses",
        {"url_a": "https://app.example.com/a", "url_b": "https://app.example.com/b"},
    )

    assert "(0 changed line(s))" in result.observation


def test_diff_responses_requires_both_urls() -> None:
    def fire(method, url, *, headers=None, content=None):
        raise AssertionError("must not fire without both urls")  # pragma: no cover

    registry = ToolRegistry([build_diff_responses_tool(_fake_firer(fire))])
    result = registry.dispatch("diff_responses", {"url_a": "https://app.example.com/a"})
    assert result.ok is False


def test_diff_responses_method_b_defaults_to_method_a() -> None:
    seen_methods: list[str] = []

    def fire(method, url, *, headers=None, content=None):
        seen_methods.append(method)
        return _ok(method, url)

    registry = ToolRegistry([build_diff_responses_tool(_fake_firer(fire))])
    registry.dispatch(
        "diff_responses",
        {
            "method_a": "post",
            "url_a": "https://app.example.com/a",
            "url_b": "https://app.example.com/b",
        },
    )

    assert seen_methods == ["POST", "POST"]


def test_diff_responses_reports_not_fired_reason_instead_of_a_bogus_status() -> None:
    def fire(method, url, *, headers=None, content=None):
        if url.endswith("/a"):
            return FireResult(method=method, url=url, fired=False, scope_reason="out_of_scope")
        return _ok(method, url)

    registry = ToolRegistry([build_diff_responses_tool(_fake_firer(fire))])
    result = registry.dispatch(
        "diff_responses",
        {"url_a": "https://evil.example.com/a", "url_b": "https://app.example.com/b"},
    )

    assert "a: not fired: out_of_scope" in result.observation
    assert "b: status=200" in result.observation
