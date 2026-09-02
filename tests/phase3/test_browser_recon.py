"""General Explorer browser recon for SPA targets (v2 W11).

run_browser_recon_async is independent scope from the XSS taint shim: it installs its
own RECON_SHIM_JS (console/network hooks) and evaluates RECON_COLLECT_JS once the SPA
has had a chance to render, returning facts only — never a finding, never touches the
graph itself (the orchestrator-level caller decides what to do with the facts).
"""

from __future__ import annotations

import asyncio

from reachagent.browser.shim import (
    RECON_COLLECT_JS,
    RECON_SHIM_JS,
    AsyncBrowserDriver,
    BrowserReconResult,
    DiscoveredForm,
    run_browser_recon_async,
)


class _FakeResponse:
    def __init__(self, *, status: int, url: str) -> None:
        self.status = status
        self.url = url


class AsyncFakeReconBrowser:
    """In-memory AsyncBrowserDriver fake for the recon path."""

    def __init__(self, *, collected: dict | None = None, status: int = 200) -> None:
        self.init_scripts: list[str] = []
        self.urls: list[str] = []
        self._collected = collected if collected is not None else {}
        self._status = status

    async def add_init_script(self, script: str) -> None:
        self.init_scripts.append(script)

    async def navigate(self, url: str) -> object:
        self.urls.append(url)
        return _FakeResponse(status=self._status, url=url)

    async def evaluate(self, expression: str) -> object:
        if expression == RECON_COLLECT_JS:
            return self._collected
        return None


def test_async_fake_recon_browser_satisfies_protocol() -> None:
    assert isinstance(AsyncFakeReconBrowser(), AsyncBrowserDriver)


def test_installs_the_recon_shim_before_navigating() -> None:
    driver = AsyncFakeReconBrowser()
    asyncio.run(run_browser_recon_async(driver, "https://spa.test/", settle_seconds=0))
    assert driver.init_scripts == [RECON_SHIM_JS]
    assert driver.urls == ["https://spa.test/"]


def test_collects_storage_keys_forms_links_console_and_network() -> None:
    collected = {
        "local_storage_keys": ["jwt", "theme"],
        "session_storage_keys": ["csrf_token"],
        "forms": [
            {"action": "/api/search", "method": "post", "inputs": ["q", "page"]},
        ],
        "links": ["/dashboard", "/settings"],
        "console": ["error: something failed"],
        "network": ["GET /api/users", "POST /api/login"],
    }
    driver = AsyncFakeReconBrowser(collected=collected)
    result = asyncio.run(run_browser_recon_async(driver, "https://spa.test/", settle_seconds=0))

    assert isinstance(result, BrowserReconResult)
    assert result.local_storage_keys == ("jwt", "theme")
    assert result.session_storage_keys == ("csrf_token",)
    expected_form = DiscoveredForm(action="/api/search", method="POST", inputs=("q", "page"))
    assert result.forms == (expected_form,)
    assert result.links == ("/dashboard", "/settings")
    assert result.console_messages == ("error: something failed",)
    assert result.network_calls == ("GET /api/users", "POST /api/login")
    assert result.status_code == 200


def test_never_returns_storage_values_only_key_names() -> None:
    """The collector JS itself only ever asks for key names (RECON_COLLECT_JS uses
    storage.key(i), never storage.getItem) — this locks that contract at the JS
    source level so a future edit can't silently start leaking values."""
    assert "getItem" not in RECON_COLLECT_JS
    assert ".key(" in RECON_COLLECT_JS


def test_gracefully_handles_a_non_dict_or_missing_collection_result() -> None:
    driver = AsyncFakeReconBrowser(collected=None)
    result = asyncio.run(run_browser_recon_async(driver, "https://spa.test/", settle_seconds=0))
    assert result.local_storage_keys == ()
    assert result.forms == ()
    assert result.console_messages == ()


def test_malformed_form_entries_are_skipped_not_fatal() -> None:
    collected = {"forms": ["not-a-dict", {"action": "/ok", "method": "get", "inputs": []}]}
    driver = AsyncFakeReconBrowser(collected=collected)
    result = asyncio.run(run_browser_recon_async(driver, "https://spa.test/", settle_seconds=0))
    assert result.forms == (DiscoveredForm(action="/ok", method="GET", inputs=()),)


def test_bounded_result_sizes_even_if_the_page_returns_more() -> None:
    collected = {
        "local_storage_keys": [f"k{i}" for i in range(500)],
        "links": [f"/l{i}" for i in range(500)],
        "console": [f"m{i}" for i in range(500)],
    }
    driver = AsyncFakeReconBrowser(collected=collected)
    result = asyncio.run(run_browser_recon_async(driver, "https://spa.test/", settle_seconds=0))
    assert len(result.local_storage_keys) <= 100
    assert len(result.links) <= 200
    assert len(result.console_messages) <= 200


def test_never_touches_the_graph_or_returns_anything_finding_shaped() -> None:
    """BrowserReconResult carries no vuln_class/severity/status field — it structurally
    cannot be mistaken for (or accidentally routed to) write_finding."""
    fields = BrowserReconResult.__dataclass_fields__
    assert "vuln_class" not in fields
    assert "severity" not in fields
    assert "confirmed" not in fields
