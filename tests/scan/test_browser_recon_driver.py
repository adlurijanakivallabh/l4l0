"""General Explorer browser recon driver (v2 W11) — orchestrator-level wiring.

run_browser_recon materializes SPA-rendered forms as new Endpoint/Parameter facts,
reusing recon/surface.py's own _form_endpoint builder — never a finding, never
touches run_oracle/write_finding. Browser launch is mocked; the shim/collection
logic itself is tested separately in tests/phase3/test_browser_recon.py.
"""

from __future__ import annotations

import sys
import types

import httpx
import pytest

from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import Endpoint
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.browser_recon import run_browser_recon

_BASE = "http://t.test"


def _firer() -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(200, text="ok")))
    return RequestFirer(client, ScopeGuard.from_hosts(["t.test"]))


def _html_graph() -> ReachabilityGraph:
    graph = ReachabilityGraph()
    graph.add_endpoint(Endpoint(method="GET", path="/", content_type="text/html"))
    return graph


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
    async def __aenter__(self) -> _FakePw:
        return _FakePw()

    async def __aexit__(self, *exc: object) -> bool:
        return False


def _patch_playwright(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_module = types.ModuleType("playwright.async_api")
    fake_module.async_playwright = _FakePwCtx  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright.async_api", fake_module)


def test_no_html_endpoints_is_not_applicable() -> None:
    events: list = []
    materialized = run_browser_recon(
        graph=ReachabilityGraph(), firer=_firer(), base_url=_BASE, identity="seed", events=events
    )
    assert materialized == 0
    assert any("no HTML endpoints" in e.message for e in events)


def test_discovered_form_materializes_a_new_endpoint_and_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_playwright(monkeypatch)

    class _FakeReconResult:
        local_storage_keys: tuple = ()
        session_storage_keys: tuple = ()
        console_messages: tuple = ()
        links: tuple = ()
        status_code = 200

        class _Form:
            action = "/api/search"
            method = "POST"
            inputs = ("q", "page")

        forms = (_Form(),)

    monkeypatch.setattr(
        "reachagent.browser.shim.run_browser_recon_async",
        lambda *_a, **_k: _async_return(_FakeReconResult()),
    )

    graph = _html_graph()
    events: list = []
    materialized = run_browser_recon(
        graph=graph, firer=_firer(), base_url=_BASE, identity="seed", events=events
    )

    assert materialized == 1
    paths = {ep.path for _n, ep in graph.endpoints()}
    assert "/api/search" in paths
    new_ep_node, new_ep = next((n, ep) for n, ep in graph.endpoints() if ep.path == "/api/search")
    assert new_ep.method == "POST"
    param_names = {p.name for _n, p in graph.parameters_of(new_ep_node)}
    assert param_names == {"q", "page"}
    assert any("SPA-rendered endpoint discovered" in e.message for e in events)
    # Never a "finding" kind — this is a recon fact, not a confirmed vulnerability.
    assert all(e.kind != "finding" for e in events)


def test_discovered_link_materializes_a_new_get_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v2 Phase 6 Stage C: a rendered <a href> the shim collects (not just a form)
    becomes a real GET Endpoint too — reused by _run_attack_path_chain so an
    admin-only nav link a derived identity's session reveals is testable."""
    _patch_playwright(monkeypatch)

    class _FakeReconResult:
        local_storage_keys: tuple = ()
        session_storage_keys: tuple = ()
        console_messages: tuple = ()
        status_code = 200
        forms: tuple = ()
        links = ("/admin/panel?tab=users",)

    monkeypatch.setattr(
        "reachagent.browser.shim.run_browser_recon_async",
        lambda *_a, **_k: _async_return(_FakeReconResult()),
    )

    graph = _html_graph()
    events: list = []
    materialized = run_browser_recon(
        graph=graph, firer=_firer(), base_url=_BASE, identity="seed", events=events
    )

    assert materialized == 1
    new_ep_node, new_ep = next((n, ep) for n, ep in graph.endpoints() if ep.path == "/admin/panel")
    assert new_ep.method == "GET"
    param_names = {p.name for _n, p in graph.parameters_of(new_ep_node)}
    assert param_names == {"tab"}  # query string on the link is captured too
    assert any("rendered link discovered" in e.message for e in events)
    assert all(e.kind != "finding" for e in events)


def test_a_link_to_an_already_known_path_is_not_re_materialized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_playwright(monkeypatch)

    class _FakeReconResult:
        local_storage_keys: tuple = ()
        session_storage_keys: tuple = ()
        console_messages: tuple = ()
        status_code = 200
        forms: tuple = ()
        links = ("/",)  # already exists in the graph

    monkeypatch.setattr(
        "reachagent.browser.shim.run_browser_recon_async",
        lambda *_a, **_k: _async_return(_FakeReconResult()),
    )
    graph = _html_graph()
    materialized = run_browser_recon(
        graph=graph, firer=_firer(), base_url=_BASE, identity="seed", events=[]
    )
    assert materialized == 0


def test_does_not_re_materialize_an_already_known_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_playwright(monkeypatch)

    class _FakeReconResult:
        local_storage_keys: tuple = ()
        session_storage_keys: tuple = ()
        console_messages: tuple = ()
        links: tuple = ()
        status_code = 200

        class _Form:
            action = "/"  # already exists in the graph
            method = "GET"
            inputs = ("q",)

        forms = (_Form(),)

    monkeypatch.setattr(
        "reachagent.browser.shim.run_browser_recon_async",
        lambda *_a, **_k: _async_return(_FakeReconResult()),
    )
    graph = _html_graph()
    events: list = []
    materialized = run_browser_recon(
        graph=graph, firer=_firer(), base_url=_BASE, identity="seed", events=events
    )
    assert materialized == 0


def test_storage_keys_are_surfaced_but_never_the_values(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_playwright(monkeypatch)

    class _FakeReconResult:
        local_storage_keys = ("jwt", "theme")
        session_storage_keys = ()
        console_messages = ()
        links: tuple = ()
        forms = ()
        status_code = 200

    monkeypatch.setattr(
        "reachagent.browser.shim.run_browser_recon_async",
        lambda *_a, **_k: _async_return(_FakeReconResult()),
    )
    graph = _html_graph()
    events: list = []
    run_browser_recon(graph=graph, firer=_firer(), base_url=_BASE, identity="seed", events=events)
    storage_events = [e for e in events if "storage key" in e.message]
    assert len(storage_events) == 1
    assert "jwt" in storage_events[0].details["keys"]
    # The message explicitly promises "names only" — no value ever appears anywhere.
    assert "values never captured" in storage_events[0].message


def test_a_browser_crash_on_one_endpoint_does_not_abort_the_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_playwright(monkeypatch)

    def _boom(*_a: object, **_k: object) -> object:
        raise RuntimeError("browser crashed")

    monkeypatch.setattr("reachagent.browser.shim.run_browser_recon_async", _boom)
    graph = _html_graph()
    events: list = []
    materialized = run_browser_recon(
        graph=graph, firer=_firer(), base_url=_BASE, identity="seed", events=events
    )
    assert materialized == 0
    assert any(e.kind == "error" for e in events)


async def _async_return(value: object) -> object:
    return value
