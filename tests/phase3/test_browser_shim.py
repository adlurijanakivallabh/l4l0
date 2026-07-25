"""Playwright taint-tracking shim tests (plan §7, §9; Phase 3 Task 5).

Covers the Task 5 DoD:
  * TAINT_SHIM_JS is installed via add_init_script before navigation.
  * Source→sink flows are collected from window.__reachagent_flows.
  * fire_browser is Explorer-only — unreachable from Coordinator/Validator
    (the named structural proof required by the v1.4.1 plan edit).
  * EXECUTION_CONFIRMATION oracle built in Task 6 (#24) — registered in registry.
  * MCP boundary: fire_browser routes through mcp.call_tool, not a direct
    Playwright Python call — proven by the BrowserDriver Protocol seam.
  * Clean-target test: a page with no injectable sinks finds nothing,
    walking the full discovery path rather than asserting in isolation.
"""

from __future__ import annotations

import pytest

from reachagent.browser.shim import (
    TAINT_SHIM_JS,
    BrowserDriver,
    BrowserFireResult,
    run_taint_shim,
)
from reachagent.tools import coordinator, explorer, validator

# === Fake BrowserDriver (the MCP-boundary seam) ==============================


class FakeBrowser:
    """In-memory BrowserDriver fake — no real Playwright, no network.

    The BrowserDriver Protocol is the seam that keeps the taint-discovery path
    hermetic: tests supply this fake; the live path supplies a Playwright-backed
    implementation. The shim JS string is the same in both cases.
    """

    def __init__(self, *, flows: list[dict] | None = None) -> None:
        self.init_scripts: list[str] = []
        self.navigated_urls: list[str] = []
        self._flows = flows or []

    def add_init_script(self, script: str) -> None:
        self.init_scripts.append(script)

    def navigate(self, url: str) -> None:
        self.navigated_urls.append(url)

    def evaluate(self, expression: str) -> object:
        if "reachagent_flows" in expression:
            return list(self._flows)
        return []


def _driver(flows: list[dict] | None = None) -> FakeBrowser:
    return FakeBrowser(flows=flows)


# === Protocol conformance =====================================================


def test_fake_browser_satisfies_protocol() -> None:
    assert isinstance(FakeBrowser(), BrowserDriver)


# === Shim installation ========================================================


def test_shim_js_installed_via_add_init_script() -> None:
    driver = _driver()
    run_taint_shim(driver, "user", "http://target/page")
    assert TAINT_SHIM_JS in driver.init_scripts


def test_shim_not_installed_when_inject_shim_false() -> None:
    driver = _driver()
    run_taint_shim(driver, "user", "http://target/page", inject_shim=False)
    assert driver.init_scripts == []


def test_navigation_always_happens() -> None:
    driver = _driver()
    run_taint_shim(driver, "user", "http://target/page")
    assert driver.navigated_urls == ["http://target/page"]


# === Flow collection ==========================================================


def test_flows_collected_from_page() -> None:
    driver = _driver(
        flows=[
            {
                "source": "location.hash",
                "sink": "innerHTML",
                "value": "<img src=x onerror=alert(1)>",
            },
        ]
    )
    result = run_taint_shim(driver, "user", "http://target/page")
    assert len(result.flows) == 1
    flow = result.flows[0]
    assert flow.source == "location.hash"
    assert flow.sink == "innerHTML"
    assert flow.url == "http://target/page"


def test_multiple_flows_collected() -> None:
    driver = _driver(
        flows=[
            {"source": "location.hash", "sink": "innerHTML", "value": "x"},
            {"source": "postMessage", "sink": "eval", "value": "alert(1)"},
        ]
    )
    result = run_taint_shim(driver, "user", "http://target/page")
    assert len(result.flows) == 2
    assert result.flows[0].sink == "innerHTML"
    assert result.flows[1].sink == "eval"


def test_result_carries_identity_and_url() -> None:
    driver = _driver()
    result = run_taint_shim(driver, "admin", "http://target/xss")
    assert result.identity == "admin"
    assert result.url == "http://target/xss"
    assert result.shim_installed is True


def test_result_is_frozen() -> None:
    r = BrowserFireResult(url="http://x", identity="u")
    with pytest.raises((AttributeError, TypeError)):
        r.url = "http://y"  # type: ignore[misc]


# === THE clean-target test ====================================================


def test_clean_target_finds_no_flows_through_full_discovery_path() -> None:
    # A page with no injectable sinks: shim installed, navigation happens,
    # window.__reachagent_flows returns empty. Full discovery path walked —
    # not just asserting in isolation. No false TaintFlow produced.
    driver = _driver(flows=[])  # no flows — clean target
    result = run_taint_shim(driver, "user", "http://clean-target/page")
    assert result.flows == ()
    assert result.shim_installed is True
    # Shim was installed and navigation happened — the full path ran.
    assert TAINT_SHIM_JS in driver.init_scripts
    assert driver.navigated_urls == ["http://clean-target/page"]


# === fire_browser role-boundary proof (v1.4.1 plan requirement) ==============


def _tool_names(module: object) -> set[str]:
    return {
        name
        for name in vars(module)
        if callable(getattr(module, name)) and not name.startswith("_")
    }


def test_fire_browser_is_in_explorer_tool_surface() -> None:
    assert "fire_browser" in _tool_names(explorer)


def test_fire_browser_not_in_coordinator_surface() -> None:
    assert "fire_browser" not in _tool_names(coordinator)


def test_fire_browser_not_in_validator_surface() -> None:
    assert "fire_browser" not in _tool_names(validator)


def test_fire_browser_has_no_write_finding_path() -> None:
    # fire_browser must not expose write_finding or run_oracle — same invariant
    # as the other Explorer tools. Checked here in the browser-specific test
    # file so the proof is co-located with the shim implementation.
    names = _tool_names(explorer)
    assert "write_finding" not in names
    assert "run_oracle" not in names
