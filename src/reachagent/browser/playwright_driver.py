"""Playwright-backed BrowserDriver implementation (Phase 3 Task 6).

Wraps a Playwright ``Page`` behind the ``BrowserDriver`` Protocol so the live
MCP path uses a real browser while tests keep the hermetic ``FakeBrowser`` seam.
"""

from __future__ import annotations

from reachagent.browser.shim import BrowserDriver


class PlaywrightDriver:
    """Live ``BrowserDriver`` backed by a Playwright ``Page``.

    Satisfies the ``BrowserDriver`` Protocol: ``add_init_script``, ``navigate``,
    ``evaluate``. Constructed server-side in ``fire_browser``; never crosses the
    JSON boundary.
    """

    def __init__(self, page: object) -> None:
        self._page = page  # playwright.sync_api.Page — typed as object to avoid hard dep at import

    def add_init_script(self, script: str) -> None:
        self._page.add_init_script(script)  # type: ignore[attr-defined]

    def navigate(self, url: str) -> None:
        self._page.goto(url, wait_until="load")  # type: ignore[attr-defined]

    def evaluate(self, expression: str) -> object:
        return self._page.evaluate(expression)  # type: ignore[attr-defined]


# Runtime check — PlaywrightDriver must satisfy the Protocol.
_driver_check: BrowserDriver = PlaywrightDriver.__new__(PlaywrightDriver)
del _driver_check
