"""Tests for the browser agent tool: dispatch-by-action over a BrowserSession."""

from __future__ import annotations

from dataclasses import dataclass, field

from lalo.browser.session import BrowserActionResult
from lalo.browser.tool import build_browser_tool


@dataclass
class _FakeSession:
    navigate_result: BrowserActionResult = field(
        default_factory=lambda: BrowserActionResult(ok=True, observation="page text")
    )
    click_result: BrowserActionResult = field(
        default_factory=lambda: BrowserActionResult(ok=True, observation="clicked text")
    )
    fill_result: BrowserActionResult = field(
        default_factory=lambda: BrowserActionResult(ok=True, observation="filled")
    )
    hover_result: BrowserActionResult = field(
        default_factory=lambda: BrowserActionResult(ok=True, observation="hovered")
    )
    select_option_result: BrowserActionResult = field(
        default_factory=lambda: BrowserActionResult(ok=True, observation="selected")
    )
    press_result: BrowserActionResult = field(
        default_factory=lambda: BrowserActionResult(ok=True, observation="pressed")
    )
    type_result: BrowserActionResult = field(
        default_factory=lambda: BrowserActionResult(ok=True, observation="typed")
    )
    text: str = "current page text"
    navigate_calls: list[str] = field(default_factory=list)
    click_calls: list[str] = field(default_factory=list)
    fill_calls: list[tuple[str, str]] = field(default_factory=list)
    hover_calls: list[str] = field(default_factory=list)
    select_option_calls: list[tuple[str, str]] = field(default_factory=list)
    press_calls: list[tuple[str, str]] = field(default_factory=list)
    type_calls: list[tuple[str, str]] = field(default_factory=list)

    def navigate(self, url: str) -> BrowserActionResult:
        self.navigate_calls.append(url)
        return self.navigate_result

    def click(self, selector: str) -> BrowserActionResult:
        self.click_calls.append(selector)
        return self.click_result

    def fill(self, selector: str, value: str) -> BrowserActionResult:
        self.fill_calls.append((selector, value))
        return self.fill_result

    def hover(self, selector: str) -> BrowserActionResult:
        self.hover_calls.append(selector)
        return self.hover_result

    def select_option(self, selector: str, value: str) -> BrowserActionResult:
        self.select_option_calls.append((selector, value))
        return self.select_option_result

    def press(self, selector: str, key: str) -> BrowserActionResult:
        self.press_calls.append((selector, key))
        return self.press_result

    def type_text(self, selector: str, text: str) -> BrowserActionResult:
        self.type_calls.append((selector, text))
        return self.type_result

    def visible_text(self) -> str:
        return self.text


def test_navigate_requires_a_url() -> None:
    tool = build_browser_tool(_FakeSession())  # type: ignore[arg-type]
    result = tool.run({"action": "navigate"})
    assert result.ok is False


def test_navigate_dispatches_to_the_session() -> None:
    session = _FakeSession()
    tool = build_browser_tool(session)  # type: ignore[arg-type]
    result = tool.run({"action": "navigate", "url": "https://app.example.com/"})
    assert result.ok is True
    assert result.observation == "page text"
    assert session.navigate_calls == ["https://app.example.com/"]


def test_click_requires_a_selector() -> None:
    tool = build_browser_tool(_FakeSession())  # type: ignore[arg-type]
    result = tool.run({"action": "click"})
    assert result.ok is False


def test_click_dispatches_to_the_session() -> None:
    session = _FakeSession()
    tool = build_browser_tool(session)  # type: ignore[arg-type]
    result = tool.run({"action": "click", "selector": "#submit"})
    assert result.ok is True
    assert session.click_calls == ["#submit"]


def test_fill_requires_a_selector() -> None:
    tool = build_browser_tool(_FakeSession())  # type: ignore[arg-type]
    result = tool.run({"action": "fill", "value": "admin"})
    assert result.ok is False


def test_fill_dispatches_to_the_session() -> None:
    session = _FakeSession()
    tool = build_browser_tool(session)  # type: ignore[arg-type]
    result = tool.run({"action": "fill", "selector": "#username", "value": "admin"})
    assert result.ok is True
    assert session.fill_calls == [("#username", "admin")]


def test_hover_requires_a_selector() -> None:
    tool = build_browser_tool(_FakeSession())  # type: ignore[arg-type]
    result = tool.run({"action": "hover"})
    assert result.ok is False


def test_hover_dispatches_to_the_session() -> None:
    session = _FakeSession()
    tool = build_browser_tool(session)  # type: ignore[arg-type]
    result = tool.run({"action": "hover", "selector": "#menu"})
    assert result.ok is True
    assert session.hover_calls == ["#menu"]


def test_select_option_requires_a_selector() -> None:
    tool = build_browser_tool(_FakeSession())  # type: ignore[arg-type]
    result = tool.run({"action": "select_option", "value": "US"})
    assert result.ok is False


def test_select_option_dispatches_to_the_session() -> None:
    session = _FakeSession()
    tool = build_browser_tool(session)  # type: ignore[arg-type]
    result = tool.run({"action": "select_option", "selector": "#country", "value": "US"})
    assert result.ok is True
    assert session.select_option_calls == [("#country", "US")]


def test_press_requires_a_selector_and_key() -> None:
    tool = build_browser_tool(_FakeSession())  # type: ignore[arg-type]
    result = tool.run({"action": "press", "selector": "#search"})
    assert result.ok is False


def test_press_dispatches_to_the_session() -> None:
    session = _FakeSession()
    tool = build_browser_tool(session)  # type: ignore[arg-type]
    result = tool.run({"action": "press", "selector": "#search", "key": "Enter"})
    assert result.ok is True
    assert session.press_calls == [("#search", "Enter")]


def test_type_requires_a_selector() -> None:
    tool = build_browser_tool(_FakeSession())  # type: ignore[arg-type]
    result = tool.run({"action": "type", "value": "sql"})
    assert result.ok is False


def test_type_dispatches_to_the_session() -> None:
    session = _FakeSession()
    tool = build_browser_tool(session)  # type: ignore[arg-type]
    result = tool.run({"action": "type", "selector": "#query", "value": "sql"})
    assert result.ok is True
    assert session.type_calls == [("#query", "sql")]


def test_get_text_returns_the_sessions_visible_text() -> None:
    session = _FakeSession(text="hello world")
    tool = build_browser_tool(session)  # type: ignore[arg-type]
    result = tool.run({"action": "get_text"})
    assert result.ok is True
    assert result.observation == "hello world"


def test_get_text_on_an_empty_page_says_so() -> None:
    session = _FakeSession(text="")
    tool = build_browser_tool(session)  # type: ignore[arg-type]
    result = tool.run({"action": "get_text"})
    assert result.observation == "(empty page)"


def test_unknown_action_is_a_failed_result() -> None:
    tool = build_browser_tool(_FakeSession())  # type: ignore[arg-type]
    result = tool.run({"action": "nope"})
    assert result.ok is False
