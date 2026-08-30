"""Playwright-backed BrowserDriver implementation (Phase 3 Task 6).

Wraps a Playwright ``Page`` behind the ``BrowserDriver`` Protocol so the live
MCP path uses a real browser while tests keep the hermetic ``FakeBrowser`` seam.
"""

from __future__ import annotations


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

    def navigate(self, url: str) -> object:
        return self._page.goto(url, wait_until="load")  # type: ignore[attr-defined]

    def evaluate(self, expression: str) -> object:
        return self._page.evaluate(expression)  # type: ignore[attr-defined]

    def get_cookies(self) -> object:
        """Return the page context cookie records for server-side session binding."""
        context = getattr(self._page, "context", None)
        cookies = getattr(context, "cookies", None)
        return cookies() if callable(cookies) else ()


class AsyncPlaywrightDriver:
    """Async BrowserDriver-shaped wrapper for MCP's asyncio execution path."""

    def __init__(self, page: object, context: object | None = None) -> None:
        self._page = page
        self._context = context

    async def add_init_script(self, script: str) -> None:
        await self._page.add_init_script(script)  # type: ignore[attr-defined]

    async def navigate(self, url: str) -> object:
        return await self._page.goto(url, wait_until="load")  # type: ignore[attr-defined]

    async def evaluate(self, expression: str) -> object:
        return await self._page.evaluate(expression)  # type: ignore[attr-defined]

    async def get_cookies(self) -> object:
        """Return cookie records without exposing them beyond the runtime."""
        cookies = getattr(self._context or getattr(self._page, "context", None), "cookies", None)
        if callable(cookies):
            return await cookies()
        return ()
