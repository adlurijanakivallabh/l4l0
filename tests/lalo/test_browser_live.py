"""One real, non-hermetic test with a genuine headless Chromium session -
test_browser_session.py's fake-page tests prove the dispatch/scope logic, this
proves Playwright itself is actually wired correctly end to end."""

from __future__ import annotations

import http.server
import threading
from collections.abc import Iterator

import pytest

from lalo.browser.session import BrowserSession
from lalo.execution.scope import ScopeGuard
from lalo.execution.target import Engagement

_OFFSITE_PORT_PLACEHOLDER = "__OFFSITE_PORT__"

_PAGE_TEMPLATE = f"""<!doctype html>
<html><body>
<p id="greeting">hello from the test server</p>
<a id="offsite" href="http://127.0.0.1:{_OFFSITE_PORT_PLACEHOLDER}/">leave the engagement</a>
<form><input id="username" type="text"></form>
</body></html>
""".encode()

_OFFSITE_PAGE = (
    b"<!doctype html><html><body><p>a second, out-of-engagement server</p></body></html>"
)


def _make_handler(page_body: bytes) -> type[http.server.BaseHTTPRequestHandler]:
    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's own naming convention
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(page_body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
            pass  # keep test output quiet

    return _Handler


def _start_server(page_body: bytes) -> http.server.HTTPServer:
    server = http.server.HTTPServer(("127.0.0.1", 0), _make_handler(page_body))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def local_server() -> Iterator[str]:
    server = _start_server(_PAGE_TEMPLATE.replace(_OFFSITE_PORT_PLACEHOLDER.encode(), b"1"))
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()


@pytest.fixture
def local_server_pair() -> Iterator[tuple[str, str]]:
    """(in_engagement_url, offsite_url) - two real local servers, the page
    served by the first links to the second, so a real click triggers a real,
    fast, deterministic cross-origin navigation (no external DNS/network)."""
    offsite = _start_server(_OFFSITE_PAGE)
    main = _start_server(
        _PAGE_TEMPLATE.replace(
            _OFFSITE_PORT_PLACEHOLDER.encode(), str(offsite.server_port).encode()
        )
    )
    try:
        yield f"http://127.0.0.1:{main.server_port}/", f"http://127.0.0.1:{offsite.server_port}/"
    finally:
        main.shutdown()
        offsite.shutdown()


@pytest.mark.integration
def test_a_real_chromium_session_navigates_and_reads_a_real_page(local_server: str) -> None:
    engagement = Engagement.from_specs(["127.0.0.1"])
    scope = ScopeGuard(engagement)
    session = BrowserSession(scope)
    try:
        result = session.navigate(local_server)
        assert result.ok is True
        assert "hello from the test server" in result.observation
        assert session.current_url() == local_server

        fill_result = session.fill("#username", "tester")
        assert fill_result.ok is True

        text_after = session.visible_text()
        assert "hello from the test server" in text_after
    finally:
        session.close()


@pytest.mark.integration
def test_a_real_chromium_session_hides_the_webdriver_automation_flag(local_server: str) -> None:
    """The stealth launch profile's actual point: navigator.webdriver must
    read as undefined, matching an ordinary browser, not True."""
    engagement = Engagement.from_specs(["127.0.0.1"])
    scope = ScopeGuard(engagement)
    session = BrowserSession(scope)
    try:
        session.navigate(local_server)
        webdriver_flag = session._page.evaluate("navigator.webdriver")  # type: ignore[attr-defined]
        assert webdriver_flag is None
    finally:
        session.close()


@pytest.mark.integration
def test_a_real_click_that_navigates_off_engagement_is_reverted(
    local_server_pair: tuple[str, str],
) -> None:
    """The core prompt-injection defense, proven against a genuine second
    server: the engagement is scoped to ONLY the main server's port, the
    served page links to a second, real, reachable server on a different
    port, and a real click through Chromium must still be caught and
    reverted - not just in the hermetic fake-page unit test."""
    main_url, offsite_url = local_server_pair
    main_port = main_url.rsplit(":", 1)[1].rstrip("/")
    engagement = Engagement.from_specs([f"127.0.0.1:{main_port}"])
    scope = ScopeGuard(engagement)
    session = BrowserSession(scope)
    try:
        session.navigate(main_url)
        result = session.click("#offsite")
        assert result.ok is False
        assert "out of scope" in result.observation
        assert offsite_url.rstrip("/") in result.observation
        assert session.current_url() == main_url
    finally:
        session.close()
