"""Client-side prototype pollution detection (Build Order v2 W9).

``probe_prototype_pollution`` is the testable core (takes an already-constructed driver,
same hermetic seam as ``browser/shim.py``'s ``run_taint_shim_async``) — only the real
Playwright launch/close in ``run_prototype_pollution`` is untested plumbing, mirroring
``scan/xss_dom.py``'s established split.
"""

from __future__ import annotations

import asyncio

import httpx

from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import Endpoint
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles.structural import StructuralCheckType
from reachagent.scan.prototype_pollution import (
    pollution_check_js,
    pollution_query,
    probe_prototype_pollution,
    run_prototype_pollution,
)


class _FakeResponse:
    def __init__(self, status: int) -> None:
        self.status = status


class _FakeDriver:
    """An async BrowserDriver-shaped fake: navigate() returns a status, evaluate()
    returns a canned pollution verdict."""

    def __init__(self, *, status: int = 200, polluted: bool = False) -> None:
        self.status = status
        self.polluted = polluted
        self.urls: list[str] = []
        self.evaluated: list[str] = []

    async def navigate(self, url: str) -> _FakeResponse:
        self.urls.append(url)
        return _FakeResponse(self.status)

    async def evaluate(self, expression: str) -> object:
        self.evaluated.append(expression)
        return self.polluted


# === pure helpers ============================================================


def test_pollution_query_includes_all_three_encodings_with_the_same_marker() -> None:
    q = pollution_query("m123")
    assert "__proto__[m123]=polluted" in q
    assert "__proto__.m123=polluted" in q
    assert "constructor[prototype][m123]=polluted" in q


def test_pollution_check_js_references_the_marker_on_a_fresh_object_literal() -> None:
    js = pollution_check_js("m123")
    assert "({}).m123" in js
    assert "catch" in js  # must never throw out to the caller


# === probe_prototype_pollution (the testable core) ===========================


def test_probe_reports_polluted_true_when_the_marker_is_observed() -> None:
    driver = _FakeDriver(status=200, polluted=True)
    status, polluted = asyncio.run(probe_prototype_pollution(driver, "http://t/x?y=1", "js"))
    assert status == 200
    assert polluted is True
    assert driver.urls == ["http://t/x?y=1"]
    assert driver.evaluated == ["js"]


def test_probe_reports_polluted_false_when_the_marker_is_absent() -> None:
    driver = _FakeDriver(status=200, polluted=False)
    status, polluted = asyncio.run(probe_prototype_pollution(driver, "http://t/x", "js"))
    assert status == 200
    assert polluted is False


def test_probe_handles_a_response_with_no_status_attribute() -> None:
    class _NoStatusDriver(_FakeDriver):
        async def navigate(self, url: str) -> object:
            self.urls.append(url)
            return object()  # no .status at all

    status, polluted = asyncio.run(probe_prototype_pollution(_NoStatusDriver(), "http://t/x", "js"))
    assert status == 0
    assert polluted is False


# === run_prototype_pollution orchestration (browser launch mocked) ==========


class _FakeVerdict:
    def __init__(self, is_violation: bool) -> None:
        self.is_violation = is_violation


class _FakeSeam:
    def __init__(self, *, is_violation: bool) -> None:
        self._is_violation = is_violation
        self.last = _FakeVerdict(is_violation)
        self.evidence_seen: list[object] = []
        self.written: list[str] = []

    def run(self, mechanism: object, evidence: object) -> object:
        self.evidence_seen.append(evidence)
        return _FakeVerdict(self._is_violation)

    def write(self, vuln_class: str, verdict: object, *, severity: str = "high") -> str | None:
        self.written.append(vuln_class)
        return f"finding:{vuln_class}"


def _graph_with_html_endpoint() -> ReachabilityGraph:
    graph = ReachabilityGraph()
    graph.add_endpoint(Endpoint(method="GET", path="/", content_type="text/html"))
    return graph


def test_run_reports_not_applicable_with_no_html_endpoints() -> None:
    events: list = []
    found = run_prototype_pollution(
        graph=ReachabilityGraph(),
        firer=None,  # type: ignore[arg-type]
        base_url="http://t",
        identity="seed",
        seam=_FakeSeam(is_violation=False),
        events=events,
    )
    assert found == []
    assert any("no HTML endpoints" in e.message for e in events)


class _FakeBrowser:
    async def new_page(self) -> object:
        return object()

    async def close(self) -> None:
        return None


class _FakeChromium:
    async def launch(self, headless: bool = True) -> _FakeBrowser:  # noqa: ARG002
        return _FakeBrowser()


class _FakePw:
    chromium = _FakeChromium()


class _FakePwCtx:
    """A fake ``async_playwright()`` return value: a sync call producing an async CM."""

    async def __aenter__(self) -> _FakePw:
        return _FakePw()

    async def __aexit__(self, *exc: object) -> bool:
        return False


def test_run_writes_a_finding_when_the_oracle_confirms(monkeypatch) -> None:  # noqa: ANN001
    import sys
    import types

    import reachagent.scan.prototype_pollution as pp

    monkeypatch.setattr(
        pp, "probe_prototype_pollution", lambda *_a, **_k: asyncio.sleep(0, result=(200, True))
    )
    # async_playwright() is a plain (non-async) callable that returns an async context
    # manager — patch the deferred import site via sys.modules so `run_prototype_pollution`'s
    # own `from playwright.async_api import async_playwright as pw_ctx` picks it up.
    fake_module = types.ModuleType("playwright.async_api")
    fake_module.async_playwright = _FakePwCtx  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright.async_api", fake_module)

    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(200, text="ok"))),
        ScopeGuard.from_hosts(["t"]),
    )
    seam = _FakeSeam(is_violation=True)
    events: list = []
    found = run_prototype_pollution(
        graph=_graph_with_html_endpoint(),
        firer=firer,
        base_url="http://t",
        identity="seed",
        seam=seam,
        events=events,
    )
    assert found == ["finding:prototype_pollution"]
    assert seam.written == ["prototype_pollution"]
    evidence = seam.evidence_seen[0]
    assert evidence.check_type is StructuralCheckType.PROTOTYPE_POLLUTION
    assert evidence.polluted is True
