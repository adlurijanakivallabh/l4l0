"""Scope-checked headless browser automation — the ``browser`` flat-toolset tool."""

from .session import BrowserActionResult, BrowserSession
from .tool import build_browser_tool

__all__ = ["BrowserActionResult", "BrowserSession", "build_browser_tool"]
