"""Hermetic tests for the DOM XSS driver (``scan/xss_dom.py``), including the
v3 V3 delayed-second-navigation corroboration.

``run_xss_dom`` predates ``xss/detector.py``'s injectable ``XssProber``
pattern — it drives Playwright directly, so a real browser launch is mocked
out the same way ``tests/scan/test_prototype_pollution.py`` mocks it for
``run_prototype_pollution``: fake the ``playwright.async_api.async_playwright``
context manager via ``sys.modules``, and monkeypatch
``reachagent.browser.shim.run_taint_shim_async`` (the one real navigation
call) to return canned, sequenced ``BrowserFireResult``s.
"""

from __future__ import annotations

import sys
import types

import httpx

import reachagent.browser.shim as browser_shim
from reachagent.browser.shim import BrowserFireResult, TaintFlow
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import Endpoint
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.xss_dom import run_xss_dom

_FLOW = TaintFlow(source="location.hash", sink="innerHTML", value_snippet="<img onerror=1>")


class _FakeVerdict:
    def __init__(self, is_violation: bool) -> None:
        self.is_violation = is_violation


class _SequencedFakeSeam:
    """A minimal duck-typed seam: verdicts pop in call order, matching
    tests/phase3/test_cache_poisoning.py's own _SequencedRunner idea."""

    def __init__(self, verdicts: list) -> None:
        self._verdicts = list(verdicts)
        self.last: _FakeVerdict | None = None
        self.written: list[tuple] = []

    def run(self, mechanism: object, evidence: object) -> object:  # noqa: ARG002
        verdict = _FakeVerdict(self._verdicts.pop(0))
        self.last = verdict
        return verdict

    def write(
        self,
        vuln_class: str,
        verdict: object,
        *,
        severity: str = "high",
        metadata: dict | None = None,
    ) -> str | None:
        self.written.append((vuln_class, metadata or {}))
        return f"finding:{vuln_class}"


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


def _patch_playwright(monkeypatch) -> None:  # noqa: ANN001
    fake_module = types.ModuleType("playwright.async_api")
    fake_module.async_playwright = _FakePwCtx  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright.async_api", fake_module)


def _graph_with_html_endpoint() -> ReachabilityGraph:
    graph = ReachabilityGraph()
    graph.add_endpoint(Endpoint(method="GET", path="/page", content_type="text/html"))
    return graph


def _firer() -> RequestFirer:
    return RequestFirer(
        httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(200, text="ok"))),
        ScopeGuard.from_hosts(["t"]),
    )


def test_no_html_endpoints_is_not_applicable_and_never_crashes() -> None:
    events: list = []
    found = run_xss_dom(
        graph=ReachabilityGraph(),
        firer=None,  # type: ignore[arg-type]
        base_url="http://t",
        identity="seed",
        seam=_SequencedFakeSeam([]),
        events=events,
    )
    assert found == []
    assert any("no HTML endpoints" in e.message for e in events)


def test_second_navigation_never_fires_when_the_primary_does_not_confirm(monkeypatch) -> None:  # noqa: ANN001
    _patch_playwright(monkeypatch)
    calls = {"n": 0}

    async def fake_shim(
        driver: object, identity: str, url: str, *, inject_shim: bool = True
    ) -> object:
        calls["n"] += 1
        return BrowserFireResult(url=url, identity=identity, flows=(), executed=False)

    monkeypatch.setattr(browser_shim, "run_taint_shim_async", fake_shim)

    found = run_xss_dom(
        graph=_graph_with_html_endpoint(),
        firer=_firer(),
        base_url="http://t",
        identity="seed",
        seam=_SequencedFakeSeam([]),
        events=[],
    )
    assert found == []
    assert calls["n"] == 1  # no flow/executed at all — the oracle is never even reached


def test_corroboration_confirms_when_second_navigation_also_shows_the_flow(monkeypatch) -> None:  # noqa: ANN001
    _patch_playwright(monkeypatch)

    async def fake_shim(
        driver: object, identity: str, url: str, *, inject_shim: bool = True
    ) -> object:
        return BrowserFireResult(url=url, identity=identity, flows=(_FLOW,), executed=True)

    monkeypatch.setattr(browser_shim, "run_taint_shim_async", fake_shim)

    seam = _SequencedFakeSeam([True, True])
    events: list = []
    found = run_xss_dom(
        graph=_graph_with_html_endpoint(),
        firer=_firer(),
        base_url="http://t",
        identity="seed",
        seam=seam,
        events=events,
    )
    assert found == ["finding:xss_dom"]
    assert seam.written == [("xss_dom", {"corroborated": "1"})]
    assert any("corroborated" in e.message for e in events if e.kind == "finding")


def test_corroboration_fails_closed_when_second_navigation_shows_no_flow(monkeypatch) -> None:  # noqa: ANN001
    """A flow that doesn't reproduce on a second, independent navigation must
    not be confirmed — rules out a one-off flake in async JS execution."""
    _patch_playwright(monkeypatch)
    calls = {"n": 0}

    async def fake_shim(
        driver: object, identity: str, url: str, *, inject_shim: bool = True
    ) -> object:
        calls["n"] += 1
        if calls["n"] == 1:
            return BrowserFireResult(url=url, identity=identity, flows=(_FLOW,), executed=True)
        return BrowserFireResult(url=url, identity=identity, flows=(), executed=False)

    monkeypatch.setattr(browser_shim, "run_taint_shim_async", fake_shim)

    seam = _SequencedFakeSeam([True])  # only the primary verdict is ever asked for
    found = run_xss_dom(
        graph=_graph_with_html_endpoint(),
        firer=_firer(),
        base_url="http://t",
        identity="seed",
        seam=seam,
        events=[],
    )
    assert found == []
    assert seam.written == []
    assert calls["n"] == 2


def test_second_navigation_transport_failure_fails_closed(monkeypatch) -> None:  # noqa: ANN001
    """A crashing/hanging corroborating navigation must fail closed, not
    propagate an exception out of the whole driver."""
    _patch_playwright(monkeypatch)
    calls = {"n": 0}

    async def fake_shim(
        driver: object, identity: str, url: str, *, inject_shim: bool = True
    ) -> object:
        calls["n"] += 1
        if calls["n"] == 1:
            return BrowserFireResult(url=url, identity=identity, flows=(_FLOW,), executed=True)
        raise RuntimeError("boom")

    monkeypatch.setattr(browser_shim, "run_taint_shim_async", fake_shim)

    seam = _SequencedFakeSeam([True])
    found = run_xss_dom(
        graph=_graph_with_html_endpoint(),
        firer=_firer(),
        base_url="http://t",
        identity="seed",
        seam=seam,
        events=[],
    )
    assert found == []
    assert seam.written == []
