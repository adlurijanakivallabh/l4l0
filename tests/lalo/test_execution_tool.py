"""Tests for the `http`, `fire_concurrent`, `diff_responses`, `access_control_matrix`,
and `raw_tcp` agent tool wiring."""

from __future__ import annotations

import sys
import threading
from collections.abc import Callable
from itertools import count
from types import SimpleNamespace

import dns.resolver
import httpx
import pytest

import lalo.execution.tool as execution_tool_module
from lalo.agent.tools import ToolRegistry
from lalo.execution import FireResult, HttpFirer, RawResult, ScopeGuard, build_http_tool
from lalo.execution.history import RequestHistory
from lalo.execution.target import Engagement
from lalo.execution.tool import (
    build_access_control_matrix_tool,
    build_diff_responses_tool,
    build_dns_query_tool,
    build_fire_concurrent_tool,
    build_http_history_tool,
    build_raw_tcp_tool,
    build_ws_fire_tool,
)


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


def test_http_tool_rejects_a_curl_style_string_headers_arg_instead_of_dropping_it() -> None:
    """A malformed (present-but-wrong-shape) headers arg must be reported as
    an error, not silently coerced to "no headers at all" - the same
    present-but-malformed-is-an-error contract _count_arg already applies to
    'count'. Firing with an empty headers dict here would be a materially
    different, silently-degraded request the agent has no way to detect.

    Uses a call-tracking handler, not a raising one: ToolRegistry.dispatch
    catches ANY exception and folds its message into the observation, so a
    raising handler whose own message happens to contain "headers" would
    make this test pass whether or not the real fix exists.
    """
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    registry = _tool(httpx.MockTransport(handler))
    result = registry.dispatch(
        "http",
        {
            "url": "https://app.example.com/x",
            "headers": "Authorization: Bearer eyJabc",
        },
    )
    assert result.ok is False
    assert "headers" in result.observation
    assert calls == []


def test_http_tool_rejects_a_non_string_body_arg_instead_of_dropping_it() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    registry = _tool(httpx.MockTransport(handler))
    result = registry.dispatch(
        "http", {"url": "https://app.example.com/x", "body": {"not": "a string"}}
    )
    assert result.ok is False
    assert "body" in result.observation
    assert calls == []


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


def test_fire_concurrent_rejects_a_malformed_headers_arg_instead_of_dropping_it() -> None:
    """Call-tracking, not raising: fire_concurrent's own _fire_one already
    catches any exception the firer raises and folds it into the
    observation, so a raising fire_fn whose message happens to contain
    "headers" would pass this test whether or not the real fix exists."""
    calls: list[tuple[object, ...]] = []

    def fire(method, url, *, headers=None, content=None):
        calls.append((method, url, headers, content))
        return _ok(method, url)

    registry = ToolRegistry([build_fire_concurrent_tool(_fake_firer(fire))])
    result = registry.dispatch(
        "fire_concurrent",
        {"url": "https://app.example.com/x", "headers": "Authorization: Bearer eyJabc"},
    )
    assert result.ok is False
    assert "headers" in result.observation
    assert calls == []


def test_fire_concurrent_rejects_a_non_string_content_arg_instead_of_dropping_it() -> None:
    calls: list[tuple[object, ...]] = []

    def fire(method, url, *, headers=None, content=None):
        calls.append((method, url, headers, content))
        return _ok(method, url)

    registry = ToolRegistry([build_fire_concurrent_tool(_fake_firer(fire))])
    result = registry.dispatch(
        "fire_concurrent",
        {"url": "https://app.example.com/x", "content": {"not": "a string"}},
    )
    assert result.ok is False
    assert "content" in result.observation
    assert calls == []


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


def test_diff_responses_rejects_a_malformed_headers_a_arg_instead_of_dropping_it() -> None:
    calls: list[tuple[object, ...]] = []

    def fire(method, url, *, headers=None, content=None):
        calls.append((method, url, headers, content))
        return _ok(method, url)

    registry = ToolRegistry([build_diff_responses_tool(_fake_firer(fire))])
    result = registry.dispatch(
        "diff_responses",
        {
            "url_a": "https://app.example.com/a",
            "url_b": "https://app.example.com/b",
            "headers_a": "Authorization: Bearer eyJabc",
        },
    )
    assert result.ok is False
    assert "headers_a" in result.observation
    assert calls == []


def test_diff_responses_rejects_a_malformed_headers_b_arg_instead_of_dropping_it() -> None:
    calls: list[tuple[object, ...]] = []

    def fire(method, url, *, headers=None, content=None):
        calls.append((method, url, headers, content))
        return _ok(method, url)

    registry = ToolRegistry([build_diff_responses_tool(_fake_firer(fire))])
    result = registry.dispatch(
        "diff_responses",
        {
            "url_a": "https://app.example.com/a",
            "url_b": "https://app.example.com/b",
            "headers_b": "Authorization: Bearer eyJabc",
        },
    )
    assert result.ok is False
    assert "headers_b" in result.observation
    assert calls == []


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


# --- access_control_matrix ------------------------------------------------


def test_access_control_matrix_build_creates_the_full_cartesian_product() -> None:
    registry = ToolRegistry([build_access_control_matrix_tool()])
    result = registry.dispatch(
        "access_control_matrix",
        {"action": "build", "identity_ids": ["admin", "user"], "endpoint_ids": ["/a", "/b"]},
    )
    assert result.ok is True
    assert "built 4 cells" in result.observation


def test_access_control_matrix_query_untested_lists_all_cells_before_any_are_marked() -> None:
    registry = ToolRegistry([build_access_control_matrix_tool()])
    registry.dispatch(
        "access_control_matrix",
        {"action": "build", "identity_ids": ["admin", "user"], "endpoint_ids": ["/a", "/b"]},
    )
    result = registry.dispatch("access_control_matrix", {"action": "query_untested"})
    assert result.ok is True
    assert len(result.observation.splitlines()) == 4
    assert "admin x /a" in result.observation
    assert "user x /b" in result.observation


def test_access_control_matrix_mark_tested_removes_the_cell_from_query_untested() -> None:
    registry = ToolRegistry([build_access_control_matrix_tool()])
    registry.dispatch(
        "access_control_matrix",
        {"action": "build", "identity_ids": ["admin", "user"], "endpoint_ids": ["/a", "/b"]},
    )
    mark_result = registry.dispatch(
        "access_control_matrix",
        {
            "action": "mark_tested",
            "identity_id": "admin",
            "endpoint_id": "/a",
            "observed_status": "200",
        },
    )
    assert mark_result.ok is True

    result = registry.dispatch("access_control_matrix", {"action": "query_untested"})
    assert len(result.observation.splitlines()) == 3
    assert "admin x /a" not in result.observation


def test_access_control_matrix_rebuild_preserves_already_tested_cells() -> None:
    """Regression: `build` unconditionally called state.clear() before
    repopulating, silently wiping every cell another agent already marked
    tested. The state dict is shared across every agent in the scan
    hierarchy (see build_access_control_matrix_tool's own docstring) - a
    later build (extending the identity/endpoint list after discovering a
    new endpoint) must never discard a sibling's already-gathered coverage."""
    registry = ToolRegistry([build_access_control_matrix_tool()])
    registry.dispatch(
        "access_control_matrix",
        {"action": "build", "identity_ids": ["admin", "user"], "endpoint_ids": ["/a", "/b"]},
    )
    registry.dispatch(
        "access_control_matrix",
        {
            "action": "mark_tested",
            "identity_id": "admin",
            "endpoint_id": "/a",
            "observed_status": "200",
        },
    )
    # A sibling agent discovers a new endpoint and rebuilds to add it.
    result = registry.dispatch(
        "access_control_matrix",
        {
            "action": "build",
            "identity_ids": ["admin", "user"],
            "endpoint_ids": ["/a", "/b", "/c"],
        },
    )
    assert result.ok is True
    assert "built 6 cells" in result.observation

    untested = registry.dispatch("access_control_matrix", {"action": "query_untested"})
    assert "admin x /a" not in untested.observation
    assert len(untested.observation.splitlines()) == 5


def test_access_control_matrix_mark_tested_without_build_errors_without_raising() -> None:
    registry = ToolRegistry([build_access_control_matrix_tool()])
    result = registry.dispatch(
        "access_control_matrix",
        {"action": "mark_tested", "identity_id": "admin", "endpoint_id": "/a"},
    )
    assert result.ok is False
    assert "error" in result.observation


def test_access_control_matrix_query_untested_without_build_reports_all_tested() -> None:
    registry = ToolRegistry([build_access_control_matrix_tool()])
    result = registry.dispatch("access_control_matrix", {"action": "query_untested"})
    assert result.ok is True
    assert result.observation == "all cells tested"


def test_access_control_matrix_rejects_an_unknown_action() -> None:
    registry = ToolRegistry([build_access_control_matrix_tool()])
    result = registry.dispatch("access_control_matrix", {"action": "bogus"})
    assert result.ok is False
    assert "bogus" in result.observation


def test_access_control_matrix_build_requires_lists() -> None:
    registry = ToolRegistry([build_access_control_matrix_tool()])
    result = registry.dispatch(
        "access_control_matrix", {"action": "build", "identity_ids": "admin", "endpoint_ids": []}
    )
    assert result.ok is False


def test_access_control_matrix_is_thread_safe_under_concurrent_build_and_query() -> None:
    """spawn_agents runs sibling agents on real OS threads, all sharing one
    access_control_matrix tool instance. Without a lock, a concurrent `build`
    (state.clear() + repopulate) racing another thread's `query_untested`
    (iterating state.values()) can raise "dictionary changed size during
    iteration" - caught by ToolRegistry.dispatch and surfaced as ok=False.

    A barrier starts every thread's tight loop at the same instant, and
    `sys.setswitchinterval` is dropped to force frequent GIL handoffs, to
    maximize interleaving; confirmed by hand (temporarily removing the lock)
    that these parameters reproduce the RuntimeError within a handful of
    runs. With the lock, this must never fail regardless of scheduling -
    it's a real regression test, not a flaky probabilistic one.
    """
    tool = build_access_control_matrix_tool()
    registry = ToolRegistry([tool])
    build_args = {
        "action": "build",
        "identity_ids": [f"id{i}" for i in range(500)],
        "endpoint_ids": ["/x"],
    }
    registry.dispatch("access_control_matrix", build_args)

    n_query_threads = 16
    barrier = threading.Barrier(n_query_threads + 1)
    bad_results: list[str] = []
    bad_results_lock = threading.Lock()

    def _query_loop() -> None:
        barrier.wait()
        for _ in range(400):
            result = registry.dispatch("access_control_matrix", {"action": "query_untested"})
            if not result.ok:
                with bad_results_lock:
                    bad_results.append(result.observation)

    def _build_loop() -> None:
        barrier.wait()
        for _ in range(400):
            registry.dispatch("access_control_matrix", build_args)

    threads = [threading.Thread(target=_query_loop) for _ in range(n_query_threads)]
    threads.append(threading.Thread(target=_build_loop))
    original_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(original_interval)

    assert bad_results == []


# --- raw_tcp ---------------------------------------------------------------


def test_raw_tcp_reports_byte_count_and_data_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_tcp_send_recv(scope, host, port, payload, *, timeout=5.0, recv_bytes=65535):
        return RawResult(
            host=host,
            port=port,
            fired=True,
            scope_reason="in_scope",
            data=b"hello back",
            elapsed_ms=12.0,
        )

    monkeypatch.setattr(execution_tool_module, "tcp_send_recv", fake_tcp_send_recv)
    registry = ToolRegistry([build_raw_tcp_tool(object())])
    result = registry.dispatch("raw_tcp", {"host": "10.0.0.1", "port": 9999, "payload": "ping"})

    assert result.ok is True
    assert "received 10 bytes" in result.observation
    assert "hello back" in result.observation


def test_raw_tcp_surfaces_scope_reason_on_a_scope_denied_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_tcp_send_recv(scope, host, port, payload, *, timeout=5.0, recv_bytes=65535):
        return RawResult(host=host, port=port, fired=False, scope_reason="out of scope")

    monkeypatch.setattr(execution_tool_module, "tcp_send_recv", fake_tcp_send_recv)
    registry = ToolRegistry([build_raw_tcp_tool(object())])
    result = registry.dispatch("raw_tcp", {"host": "evil.example.com", "port": 22})

    assert result.ok is False
    assert "out of scope" in result.observation


def test_raw_tcp_requires_host_and_port() -> None:
    registry = ToolRegistry([build_raw_tcp_tool(object())])
    result = registry.dispatch("raw_tcp", {"host": "10.0.0.1"})
    assert result.ok is False


def test_raw_tcp_rejects_a_non_integer_port() -> None:
    registry = ToolRegistry([build_raw_tcp_tool(object())])
    result = registry.dispatch("raw_tcp", {"host": "10.0.0.1", "port": "not-a-port"})
    assert result.ok is False
    assert "port" in result.observation


# --- ws_fire ----------------------------------------------------------------


def _ws_scope() -> ScopeGuard:
    eng = Engagement.from_specs(["app.example.com"])
    return ScopeGuard(engagement=eng, resolver=lambda h: frozenset({"93.184.216.34"}))


class _FakeWSConnection:
    def __init__(self, reply: str = "pong") -> None:
        self.reply = reply
        self.sent: str | None = None

    async def send(self, message: str) -> None:
        self.sent = message

    async def recv(self) -> str:
        return self.reply

    async def __aenter__(self) -> _FakeWSConnection:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


def test_ws_fire_sends_a_message_and_returns_the_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # websockets.connect() itself is a plain (non-async) call that returns an
    # object supporting `async with` - a fake that's `async def` instead
    # would hand `async with` a coroutine, which has no __aenter__.
    def fake_connect(url: str, **kwargs: object) -> _FakeWSConnection:
        return _FakeWSConnection()

    monkeypatch.setattr(execution_tool_module.websockets, "connect", fake_connect)
    registry = ToolRegistry([build_ws_fire_tool(_ws_scope())])
    result = registry.dispatch("ws_fire", {"url": "ws://app.example.com/socket", "message": "ping"})
    assert result.ok is True
    assert "pong" in result.observation


def test_ws_fire_sends_the_given_message(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeWSConnection()

    def fake_connect(url: str, **kwargs: object) -> _FakeWSConnection:
        return conn

    monkeypatch.setattr(execution_tool_module.websockets, "connect", fake_connect)
    registry = ToolRegistry([build_ws_fire_tool(_ws_scope())])
    registry.dispatch("ws_fire", {"url": "ws://app.example.com/socket", "message": "hello"})
    assert conn.sent == "hello"


def test_ws_fire_rejects_an_out_of_scope_url() -> None:
    registry = ToolRegistry([build_ws_fire_tool(_ws_scope())])
    result = registry.dispatch(
        "ws_fire", {"url": "ws://evil.example.org/socket", "message": "ping"}
    )
    assert not result.ok
    assert "scope" in result.observation.lower()


def test_ws_fire_requires_url() -> None:
    registry = ToolRegistry([build_ws_fire_tool(_ws_scope())])
    result = registry.dispatch("ws_fire", {})
    assert result.ok is False


def test_ws_fire_reports_a_connection_failure_instead_of_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_connect(url: str, **kwargs: object) -> _FakeWSConnection:
        raise OSError("connection refused")

    monkeypatch.setattr(execution_tool_module.websockets, "connect", fake_connect)
    registry = ToolRegistry([build_ws_fire_tool(_ws_scope())])
    result = registry.dispatch("ws_fire", {"url": "ws://app.example.com/socket"})
    assert result.ok is False
    assert "OSError" in result.observation


# --- dns_query ----------------------------------------------------------


def test_dns_query_returns_records_for_an_in_scope_host(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_resolve(host: str, record_type: str, lifetime: float) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr(execution_tool_module.dns.resolver, "resolve", fake_resolve)
    registry = ToolRegistry([build_dns_query_tool(_ws_scope())])
    result = registry.dispatch("dns_query", {"host": "app.example.com", "record_type": "A"})
    assert result.ok
    assert "93.184.216.34" in result.observation


def test_dns_query_rejects_an_out_of_scope_host() -> None:
    registry = ToolRegistry([build_dns_query_tool(_ws_scope())])
    result = registry.dispatch("dns_query", {"host": "evil.example.org", "record_type": "A"})
    assert not result.ok
    assert "scope" in result.observation.lower()


def test_dns_query_reports_nxdomain_as_a_clean_non_error_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_nxdomain(host: str, record_type: str, lifetime: float) -> list[str]:
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(execution_tool_module.dns.resolver, "resolve", raise_nxdomain)
    registry = ToolRegistry([build_dns_query_tool(_ws_scope())])
    result = registry.dispatch("dns_query", {"host": "app.example.com", "record_type": "A"})
    assert result.ok  # a real, informative "no such record" answer, not a tool failure
    assert "no" in result.observation.lower()


def test_dns_query_reports_no_answer_as_a_clean_non_error_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_no_answer(host: str, record_type: str, lifetime: float) -> list[str]:
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(execution_tool_module.dns.resolver, "resolve", raise_no_answer)
    registry = ToolRegistry([build_dns_query_tool(_ws_scope())])
    result = registry.dispatch("dns_query", {"host": "app.example.com", "record_type": "MX"})
    assert result.ok
    assert "no" in result.observation.lower()


def test_dns_query_requires_host() -> None:
    registry = ToolRegistry([build_dns_query_tool(_ws_scope())])
    result = registry.dispatch("dns_query", {})
    assert result.ok is False


def test_dns_query_rejects_an_unknown_record_type() -> None:
    registry = ToolRegistry([build_dns_query_tool(_ws_scope())])
    result = registry.dispatch("dns_query", {"host": "app.example.com", "record_type": "BOGUS"})
    assert result.ok is False
    assert "record_type" in result.observation


def test_dns_query_zone_transfer_reports_success_when_the_server_allows_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_zone = SimpleNamespace(to_text=lambda: "app.example.com. 3600 IN A 93.184.216.34")

    monkeypatch.setattr(execution_tool_module.dns.query, "xfr", lambda *a, **kw: iter([]))
    monkeypatch.setattr(execution_tool_module.dns.zone, "from_xfr", lambda xfr: fake_zone)
    registry = ToolRegistry([build_dns_query_tool(_ws_scope())])
    result = registry.dispatch("dns_query", {"host": "app.example.com", "record_type": "AXFR"})
    assert result.ok
    assert "SUCCEEDED" in result.observation
    assert "93.184.216.34" in result.observation


def test_dns_query_zone_transfer_refusal_is_a_clean_non_error_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_xfr(host: str, zone: str, lifetime: float) -> object:
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(execution_tool_module.dns.query, "xfr", fake_xfr)
    registry = ToolRegistry([build_dns_query_tool(_ws_scope())])
    result = registry.dispatch("dns_query", {"host": "app.example.com", "record_type": "AXFR"})
    assert result.ok  # refusal is the secure, expected outcome - not a tool failure
    assert "refused" in result.observation.lower()


# --- http_history ------------------------------------------------------


def _history_and_firer(handler: httpx.MockTransport) -> tuple[RequestHistory, HttpFirer]:
    eng = Engagement.from_specs(["app.example.com"])
    scope = ScopeGuard(engagement=eng, resolver=lambda h: frozenset({"93.184.216.34"}))
    firer = HttpFirer(scope, client=httpx.Client(transport=handler))
    history = RequestHistory()
    firer.attach_recorder(history)
    return history, firer


def test_replay_headers_drops_transfer_encoding_and_recomputes_content_length() -> None:
    from lalo.execution.tool import _replay_headers

    original = {"Content-Length": "3", "Transfer-Encoding": "chunked", "Accept": "*/*"}
    merged = _replay_headers(original, {}, b"a longer body now")
    assert "Transfer-Encoding" not in merged
    assert merged["Content-Length"] == str(len(b"a longer body now"))
    assert merged["Accept"] == "*/*"


def test_http_history_tool_list_is_empty_before_anything_is_fired() -> None:
    history, firer = _history_and_firer(httpx.MockTransport(lambda r: httpx.Response(200)))
    registry = ToolRegistry([build_http_history_tool(history, firer)])
    result = registry.dispatch("http_history", {"action": "list"})
    assert result.observation == "(no history yet)"


def test_http_history_tool_list_shows_a_fired_request() -> None:
    history, firer = _history_and_firer(httpx.MockTransport(lambda r: httpx.Response(200)))
    firer.fire("GET", "https://app.example.com/x")
    registry = ToolRegistry([build_http_history_tool(history, firer)])
    result = registry.dispatch("http_history", {"action": "list"})
    assert "[0] GET https://app.example.com/x -> 200" in result.observation


def test_http_history_tool_view_shows_request_and_response_detail() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"hello")

    history, firer = _history_and_firer(httpx.MockTransport(handler))
    firer.fire("GET", "https://app.example.com/x", headers={"X-Test": "1"})
    registry = ToolRegistry([build_http_history_tool(history, firer)])
    result = registry.dispatch("http_history", {"action": "view", "index": 0})
    assert result.ok is True
    assert "X-Test" in result.observation
    assert "hello" in result.observation


def test_http_history_tool_view_unknown_index_errors() -> None:
    history, firer = _history_and_firer(httpx.MockTransport(lambda r: httpx.Response(200)))
    registry = ToolRegistry([build_http_history_tool(history, firer)])
    result = registry.dispatch("http_history", {"action": "view", "index": 5})
    assert result.ok is False
    assert "5" in result.observation


def test_http_history_tool_view_requires_index() -> None:
    history, firer = _history_and_firer(httpx.MockTransport(lambda r: httpx.Response(200)))
    registry = ToolRegistry([build_http_history_tool(history, firer)])
    result = registry.dispatch("http_history", {"action": "view"})
    assert result.ok is False


def test_http_history_tool_replay_refires_with_the_original_request() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"replayed")

    history, firer = _history_and_firer(httpx.MockTransport(handler))
    firer.fire("POST", "https://app.example.com/x", headers={"X-Test": "1"}, content=b"orig")
    registry = ToolRegistry([build_http_history_tool(history, firer)])
    result = registry.dispatch("http_history", {"action": "replay", "index": 0})
    assert result.ok is True
    assert "replayed" in result.observation
    assert len(seen) == 2  # the original fire + the replay
    assert seen[1].headers.get("x-test") == "1"
    assert seen[1].content == b"orig"


def test_http_history_tool_replay_with_a_body_override_recomputes_content_length() -> None:
    """The load-bearing replay-safety behavior: a modified body must never go
    out with a stale Content-Length or an inherited chunked Transfer-Encoding
    that was never actually chunked for the new body."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200)

    history, firer = _history_and_firer(httpx.MockTransport(handler))
    firer.fire(
        "POST",
        "https://app.example.com/x",
        headers={"Content-Length": "4", "Transfer-Encoding": "chunked"},
        content=b"orig",
    )
    registry = ToolRegistry([build_http_history_tool(history, firer)])
    registry.dispatch(
        "http_history", {"action": "replay", "index": 0, "body": "a much longer body"}
    )
    assert seen[1].content == b"a much longer body"
    assert seen[1].headers["content-length"] == str(len(b"a much longer body"))
    assert "transfer-encoding" not in seen[1].headers


def test_http_history_tool_replay_unknown_index_errors() -> None:
    history, firer = _history_and_firer(httpx.MockTransport(lambda r: httpx.Response(200)))
    registry = ToolRegistry([build_http_history_tool(history, firer)])
    result = registry.dispatch("http_history", {"action": "replay", "index": 9})
    assert result.ok is False


def test_http_history_tool_rejects_an_unknown_action() -> None:
    history, firer = _history_and_firer(httpx.MockTransport(lambda r: httpx.Response(200)))
    registry = ToolRegistry([build_http_history_tool(history, firer)])
    result = registry.dispatch("http_history", {"action": "bogus"})
    assert result.ok is False
    assert "bogus" in result.observation
