"""Hermetic tests for BrowserSession: scope-gated navigation, real Chromium
never started (a fake page object stands in). One real end-to-end test with a
genuine headless Chromium session lives in test_browser_live.py
(@pytest.mark.integration - this repo's existing marker for tests needing a
real browser/external process)."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from lalo.browser.session import BrowserSession
from lalo.execution.scope import ScopeGuard
from lalo.execution.target import Engagement


def _scope() -> ScopeGuard:
    return ScopeGuard(Engagement.from_specs(["app.example.com"]))


@dataclass
class _FakeResponse:
    server_ip: str | None = None
    raise_on_server_addr: Exception | None = None

    def server_addr(self) -> dict[str, object] | None:
        if self.raise_on_server_addr is not None:
            raise self.raise_on_server_addr
        return {"ipAddress": self.server_ip, "port": 443} if self.server_ip else None


@dataclass
class _FakePage:
    url: str = "about:blank"
    body_text: str = "hello"
    goto_calls: list[str] = field(default_factory=list)
    click_calls: list[str] = field(default_factory=list)
    fill_calls: list[tuple[str, str]] = field(default_factory=list)
    hover_calls: list[str] = field(default_factory=list)
    select_option_calls: list[tuple[str, str]] = field(default_factory=list)
    press_calls: list[tuple[str, str]] = field(default_factory=list)
    type_calls: list[tuple[str, str]] = field(default_factory=list)
    click_navigates_to: str | None = None
    fill_navigates_to: str | None = None
    raise_on_click: Exception | None = None
    raise_on_goto: Exception | None = None
    raise_on_hover: Exception | None = None
    redirect_to: str | None = None
    goto_response: _FakeResponse | None = None

    def goto(self, url: str, timeout: float = 0) -> _FakeResponse | None:
        if self.raise_on_goto is not None:
            raise self.raise_on_goto
        self.goto_calls.append(url)
        self.url = self.redirect_to if self.redirect_to is not None else url
        return self.goto_response

    def click(self, selector: str, timeout: float = 0) -> None:
        if self.raise_on_click is not None:
            raise self.raise_on_click
        self.click_calls.append(selector)
        if self.click_navigates_to is not None:
            self.url = self.click_navigates_to

    def fill(self, selector: str, value: str, timeout: float = 0) -> None:
        self.fill_calls.append((selector, value))
        if self.fill_navigates_to is not None:
            self.url = self.fill_navigates_to

    def hover(self, selector: str, timeout: float = 0) -> None:
        if self.raise_on_hover is not None:
            raise self.raise_on_hover
        self.hover_calls.append(selector)

    def select_option(self, selector: str, value: str, timeout: float = 0) -> None:
        self.select_option_calls.append((selector, value))

    def press(self, selector: str, key: str, timeout: float = 0) -> None:
        self.press_calls.append((selector, key))

    def type(self, selector: str, text: str, timeout: float = 0) -> None:
        self.type_calls.append((selector, text))

    def inner_text(self, selector: str) -> str:
        return self.body_text

    def go_back(self) -> None:
        self.url = "about:blank"


def _session_with_fake_page(page: _FakePage, *, scope: ScopeGuard | None = None) -> BrowserSession:
    session = BrowserSession(scope or _scope())
    session._page = page  # bypasses real Chromium startup - the established test seam
    return session


def test_navigate_refuses_an_out_of_scope_url_without_touching_the_page() -> None:
    page = _FakePage()
    session = _session_with_fake_page(page)
    result = session.navigate("https://evil.example.org/")
    assert result.ok is False
    assert "scope" in result.observation
    assert page.goto_calls == []


def test_navigate_fires_and_returns_visible_text_for_an_in_scope_url() -> None:
    page = _FakePage(body_text="Welcome to the app")
    session = _session_with_fake_page(page)
    result = session.navigate("https://app.example.com/")
    assert result.ok is True
    assert result.observation == "Welcome to the app"
    assert page.goto_calls == ["https://app.example.com/"]


def test_navigate_degrades_gracefully_on_a_real_navigation_error() -> None:
    page = _FakePage(raise_on_goto=TimeoutError("nav timeout"))
    session = _session_with_fake_page(page)
    result = session.navigate("https://app.example.com/")
    assert result.ok is False
    assert "navigation failed" in result.observation


def test_navigate_that_redirects_out_of_scope_is_reverted_and_refused() -> None:
    """A pre-check on the requested URL alone is not enough - the target's own
    server-side redirect can still land the agent off-scope, exactly the risk
    click() already guards against post-action."""
    page = _FakePage(url="https://app.example.com/", redirect_to="https://evil.example.org/")
    session = _session_with_fake_page(page)
    result = session.navigate("https://app.example.com/start")
    assert result.ok is False
    assert "out of scope" in result.observation
    assert page.url == "about:blank"  # go_back() was called


def test_navigate_reverts_when_the_real_connection_lands_on_a_metadata_address() -> None:
    """DNS rebinding: the pre-check's own resolution said this host was safe,
    but the literal IP Chromium actually connected to is cloud metadata."""
    page = _FakePage(
        url="https://app.example.com/",
        goto_response=_FakeResponse(server_ip="169.254.169.254"),
    )
    session = _session_with_fake_page(page)
    result = session.navigate("https://app.example.com/")
    assert result.ok is False
    assert "cloud-metadata" in result.observation
    assert page.url == "about:blank"


def test_navigate_succeeds_when_the_real_connection_is_an_ordinary_address() -> None:
    page = _FakePage(
        url="https://app.example.com/",
        body_text="fine",
        goto_response=_FakeResponse(server_ip="93.184.216.34"),
    )
    session = _session_with_fake_page(page)
    result = session.navigate("https://app.example.com/")
    assert result.ok is True
    assert result.observation == "fine"


def test_navigate_degrades_gracefully_if_server_addr_itself_raises() -> None:
    page = _FakePage(
        url="https://app.example.com/",
        body_text="fine",
        goto_response=_FakeResponse(raise_on_server_addr=RuntimeError("browser process hiccup")),
    )
    session = _session_with_fake_page(page)
    result = session.navigate("https://app.example.com/")
    assert result.ok is True
    assert result.observation == "fine"


def test_click_before_any_navigation_is_a_failed_result() -> None:
    session = BrowserSession(_scope())
    result = session.click("#submit")
    assert result.ok is False
    assert "navigate somewhere first" in result.observation


def test_click_that_stays_in_scope_succeeds() -> None:
    page = _FakePage(url="https://app.example.com/", body_text="clicked")
    session = _session_with_fake_page(page)
    result = session.click("#submit")
    assert result.ok is True
    assert result.observation == "clicked"
    assert page.click_calls == ["#submit"]


def test_click_that_navigates_out_of_scope_is_reverted_and_refused() -> None:
    """The core prompt-injection defense: a page's own link/JS redirect must
    never be allowed to carry the agent off-target just because a click
    itself was requested against an in-scope page."""
    page = _FakePage(url="https://app.example.com/", click_navigates_to="https://evil.example.org/")
    session = _session_with_fake_page(page)
    result = session.click("a.malicious-link")
    assert result.ok is False
    assert "out of scope" in result.observation
    assert page.url == "about:blank"  # go_back() was called


def test_click_degrades_gracefully_when_the_selector_is_missing() -> None:
    page = _FakePage(raise_on_click=Exception("no such element"))
    session = _session_with_fake_page(page)
    result = session.click("#nonexistent")
    assert result.ok is False
    assert "click failed" in result.observation


def test_fill_before_any_navigation_is_a_failed_result() -> None:
    session = BrowserSession(_scope())
    result = session.fill("#username", "admin")
    assert result.ok is False


def test_fill_records_the_value_on_an_in_scope_page() -> None:
    page = _FakePage(url="https://app.example.com/")
    session = _session_with_fake_page(page)
    result = session.fill("#username", "admin")
    assert result.ok is True
    assert result.observation == "filled '#username'"
    assert page.fill_calls == [("#username", "admin")]


def test_fill_that_navigates_out_of_scope_is_reverted_and_refused() -> None:
    """Closes a real asymmetry: an onchange/onkeyup handler can navigate off
    -target exactly like an onclick one, but fill() previously had no
    post-action re-check at all."""
    page = _FakePage(url="https://app.example.com/", fill_navigates_to="https://evil.example.org/")
    session = _session_with_fake_page(page)
    result = session.fill("#promo-code", "REDIRECT")
    assert result.ok is False
    assert "out of scope" in result.observation
    assert page.url == "about:blank"


def test_hover_before_any_navigation_is_a_failed_result() -> None:
    session = BrowserSession(_scope())
    result = session.hover("#menu")
    assert result.ok is False
    assert "navigate somewhere first" in result.observation


def test_hover_that_stays_in_scope_succeeds() -> None:
    page = _FakePage(url="https://app.example.com/", body_text="menu revealed")
    session = _session_with_fake_page(page)
    result = session.hover("#menu")
    assert result.ok is True
    assert result.observation == "menu revealed"
    assert page.hover_calls == ["#menu"]


def test_hover_degrades_gracefully_when_the_selector_is_missing() -> None:
    page = _FakePage(raise_on_hover=Exception("no such element"))
    session = _session_with_fake_page(page)
    result = session.hover("#nonexistent")
    assert result.ok is False
    assert "hover failed" in result.observation


def test_select_option_on_an_in_scope_page_succeeds() -> None:
    page = _FakePage(url="https://app.example.com/")
    session = _session_with_fake_page(page)
    result = session.select_option("#country", "US")
    assert result.ok is True
    assert result.observation == "selected 'US' in '#country'"
    assert page.select_option_calls == [("#country", "US")]


def test_press_on_an_in_scope_page_succeeds() -> None:
    page = _FakePage(url="https://app.example.com/", body_text="submitted")
    session = _session_with_fake_page(page)
    result = session.press("#search", "Enter")
    assert result.ok is True
    assert result.observation == "submitted"
    assert page.press_calls == [("#search", "Enter")]


def test_type_text_on_an_in_scope_page_succeeds() -> None:
    page = _FakePage(url="https://app.example.com/", body_text="autocomplete shown")
    session = _session_with_fake_page(page)
    result = session.type_text("#query", "sql")
    assert result.ok is True
    assert result.observation == "autocomplete shown"
    assert page.type_calls == [("#query", "sql")]


def test_visible_text_before_any_navigation_is_empty() -> None:
    session = BrowserSession(_scope())
    assert session.visible_text() == ""


def test_visible_text_truncates_a_very_long_page() -> None:
    page = _FakePage(body_text="x" * 20_000)
    session = _session_with_fake_page(page)
    assert len(session.visible_text()) == 8_000


def test_current_url_before_any_navigation_is_empty() -> None:
    session = BrowserSession(_scope())
    assert session.current_url() == ""


def test_current_url_reflects_the_page() -> None:
    page = _FakePage(url="https://app.example.com/dashboard")
    session = _session_with_fake_page(page)
    assert session.current_url() == "https://app.example.com/dashboard"


def test_close_before_any_navigation_never_raises() -> None:
    session = BrowserSession(_scope())
    session.close()  # must be a no-op, not an AttributeError on a None playwright


def test_close_still_stops_playwright_when_browser_close_itself_raises() -> None:
    """Regression: close() used to run browser.close() then
    playwright.stop() as two unguarded statements - a crashed/killed
    Chromium process raising out of the first one skipped the second
    entirely (a leaked Playwright driver process) AND propagated out of
    close() itself, replacing whatever real exception a caller's own
    `finally: browser.close()` (scan.py's ScanRunner.run()) was
    protecting."""

    class _RaisingBrowser:
        def close(self) -> None:
            raise RuntimeError("simulated crashed Chromium process")

    class _FakePlaywright:
        def __init__(self) -> None:
            self.stopped = False

        def stop(self) -> None:
            self.stopped = True

    session = BrowserSession(_scope())
    playwright = _FakePlaywright()
    session._browser = _RaisingBrowser()
    session._playwright = playwright
    session.close()  # must not raise

    assert playwright.stopped is True
    assert session._browser is None
    assert session._playwright is None


@dataclass
class _FakeContext:
    state: dict[str, object] = field(default_factory=dict)

    def storage_state(self) -> dict[str, object]:
        return self.state


def test_export_storage_state_reads_from_the_context() -> None:
    page = _FakePage(url="https://app.example.com/")
    session = _session_with_fake_page(page)
    session._context = _FakeContext(state={"cookies": [{"name": "session", "value": "abc"}]})
    state = session.export_storage_state()
    assert state == {"cookies": [{"name": "session", "value": "abc"}]}


def test_import_storage_state_before_the_session_starts_is_accepted() -> None:
    session = BrowserSession(_scope())
    session.import_storage_state({"cookies": []})
    assert session._pending_storage_state == {"cookies": []}


def test_import_storage_state_after_the_session_started_raises() -> None:
    page = _FakePage(url="https://app.example.com/")
    session = _session_with_fake_page(page)
    session._context = _FakeContext()
    with pytest.raises(RuntimeError, match="before the session starts"):
        session.import_storage_state({"cookies": []})
