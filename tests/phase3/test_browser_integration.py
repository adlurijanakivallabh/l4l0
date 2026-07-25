"""Integration tests — real Playwright browser confirms DOM XSS shim (Phase 3 Task 6).

These tests use a real Chromium browser (via Playwright) against a local HTTP
server serving static HTML. They prove the full live path:

  PlaywrightDriver → run_taint_shim → TAINT_SHIM_JS in real browser → flows

Two cases required by the Task 6 DoD:
  1. Positive: page with innerHTML sink fed from location.hash → ≥1 flow.
  2. Negative (clean): page with no injectable sink → 0 flows.

Marked ``integration`` so the standing gate can run them explicitly; they are
excluded from the fast unit-test pass by the ``-m "not integration"`` marker
(add to pytest.ini if needed — currently they run in the full suite).
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from reachagent.browser.playwright_driver import PlaywrightDriver
from reachagent.browser.shim import run_taint_shim

# ---------------------------------------------------------------------------
# Minimal local HTTP server fixture
# ---------------------------------------------------------------------------

_XSS_PAGE = b"""<!DOCTYPE html>
<html><body>
<div id="out"></div>
<script>
  // Classic DOM XSS: location.hash flows into innerHTML.
  document.getElementById('out').innerHTML = decodeURIComponent(location.hash.slice(1));
</script>
</body></html>
"""

_CLEAN_PAGE = b"""<!DOCTYPE html>
<html><body>
<div id="out">static content, no sink</div>
</body></html>
"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # silence access log
        pass

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0].split("#")[0]
        if path == "/xss":
            body = _XSS_PAGE
        elif path == "/clean":
            body = _CLEAN_PAGE
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def local_server() -> str:
    """Start a local HTTP server; return its base URL."""
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_real_browser_detects_dom_xss_flow(local_server: str) -> None:
    """Positive case: innerHTML sink fed from location.hash → ≥1 taint flow."""
    from playwright.sync_api import sync_playwright

    url = f"{local_server}/xss#<img src=x onerror=alert(1)>"
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            driver = PlaywrightDriver(page)
            result = run_taint_shim(driver, "user", url)
        finally:
            browser.close()

    assert result.shim_installed is True
    assert result.url == url
    assert len(result.flows) >= 1
    sinks = {f.sink for f in result.flows}
    assert "innerHTML" in sinks
    sources = {f.source for f in result.flows}
    assert "location.hash" in sources


@pytest.mark.integration
def test_real_browser_clean_page_finds_no_flows(local_server: str) -> None:
    """Negative case: page with no injectable sink → 0 flows."""
    from playwright.sync_api import sync_playwright

    url = f"{local_server}/clean"
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            driver = PlaywrightDriver(page)
            result = run_taint_shim(driver, "user", url)
        finally:
            browser.close()

    assert result.shim_installed is True
    assert result.flows == ()
