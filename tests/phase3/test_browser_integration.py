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

_OUTER_HTML_PAGE = b"""<!DOCTYPE html>
<html><body>
<div id="out"><span>x</span></div>
<script>
  document.getElementById('out').outerHTML = decodeURIComponent(location.hash.slice(1));
</script>
</body></html>
"""

_INSERT_ADJACENT_HTML_PAGE = b"""<!DOCTYPE html>
<html><body>
<div id="out"></div>
<script>
  var v = decodeURIComponent(location.hash.slice(1));
  document.getElementById('out').insertAdjacentHTML('beforeend', v);
</script>
</body></html>
"""

_SET_TIMEOUT_STRING_PAGE = b"""<!DOCTYPE html>
<html><body>
<script>
  setTimeout(decodeURIComponent(location.hash.slice(1)), 0);
</script>
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
        elif path == "/outer-html":
            body = _OUTER_HTML_PAGE
        elif path == "/insert-adjacent-html":
            body = _INSERT_ADJACENT_HTML_PAGE
        elif path == "/set-timeout-string":
            body = _SET_TIMEOUT_STRING_PAGE
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


def _run_shim_in_real_browser(url: str):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(headless=True)
        except Exception as exc:  # noqa: BLE001 — browser not installed → skip, not fail
            pytest.skip(f"Chromium not available: {exc}")
        try:
            page = browser.new_page()
            driver = PlaywrightDriver(page)
            return run_taint_shim(driver, "user", url)
        finally:
            browser.close()


@pytest.mark.integration
def test_real_browser_detects_dom_xss_flow(local_server: str) -> None:
    """Positive case: innerHTML sink fed from location.hash → ≥1 taint flow."""
    url = f"{local_server}/xss#<img src=x onerror=alert(1)>"
    result = _run_shim_in_real_browser(url)

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
    result = _run_shim_in_real_browser(f"{local_server}/clean")

    assert result.shim_installed is True
    assert result.flows == ()


@pytest.mark.integration
def test_real_browser_detects_outer_html_sink(local_server: str) -> None:
    url = f"{local_server}/outer-html#<img src=x onerror=alert(1)>"
    result = _run_shim_in_real_browser(url)

    sinks = {f.sink for f in result.flows}
    assert "outerHTML" in sinks


@pytest.mark.integration
def test_real_browser_detects_insert_adjacent_html_sink(local_server: str) -> None:
    url = f"{local_server}/insert-adjacent-html#<img src=x onerror=alert(1)>"
    result = _run_shim_in_real_browser(url)

    sinks = {f.sink for f in result.flows}
    assert "insertAdjacentHTML" in sinks


@pytest.mark.integration
def test_real_browser_detects_settimeout_string_sink(local_server: str) -> None:
    url = f"{local_server}/set-timeout-string#window.__reachagent_exec=1"
    result = _run_shim_in_real_browser(url)

    sinks = {f.sink for f in result.flows}
    assert "setTimeout" in sinks
