"""Hermetic tests for BrowserSession: scope-gated navigation, real Chromium
never started (a fake page object stands in). One real end-to-end test with a
genuine headless Chromium session lives in test_browser_live.py
(@pytest.mark.integration - this repo's existing marker for tests needing a
real browser/external process)."""

from __future__ import annotations

from dataclasses import dataclass, field

from lalo.browser.session import BrowserSession
from lalo.execution.scope import ScopeGuard
from lalo.execution.target import Engagement


def _scope() -> ScopeGuard:
    return ScopeGuard(Engagement.from_specs(["app.example.com"]))


@dataclass
class _FakePage:
    url: str = "about:blank"
    body_text: str = "hello"
    goto_calls: list[str] = field(default_factory=list)
    click_calls: list[str] = field(default_factory=list)
    fill_calls: list[tuple[str, str]] = field(default_factory=list)
    click_navigates_to: str | None = None
    raise_on_click: Exception | None = None
    raise_on_goto: Exception | None = None

    def goto(self, url: str, timeout: float = 0) -> None:
        if self.raise_on_goto is not None:
            raise self.raise_on_goto
        self.goto_calls.append(url)
        self.url = url

    def click(self, selector: str, timeout: float = 0) -> None:
        if self.raise_on_click is not None:
            raise self.raise_on_click
        self.click_calls.append(selector)
        if self.click_navigates_to is not None:
            self.url = self.click_navigates_to

    def fill(self, selector: str, value: str, timeout: float = 0) -> None:
        self.fill_calls.append((selector, value))

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
    page = _FakePage()
    session = _session_with_fake_page(page)
    result = session.fill("#username", "admin")
    assert result.ok is True
    assert page.fill_calls == [("#username", "admin")]


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
