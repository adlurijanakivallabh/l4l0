"""Client-side prototype pollution detection via a headless browser (§7, v2 W9).

Appends an injected ``__proto__``-shaped query parameter (in several common encodings a
client-side merge library might parse) to each discovered HTML GET endpoint, loads the page,
then evaluates a single in-page JS check: does a brand-new ``{}`` object literal carry the
marker property? A fresh POJO can never have an arbitrary own or inherited property unless the
page's own client-side code actually polluted ``Object.prototype`` while processing our query
string — so this one in-page observation is unambiguous, no baseline/differential needed.

Same shape as ``scan/xss_dom.py`` (its established Playwright-driving pattern): a standalone
module, a bounded per-probe timeout, browser fires recorded on the shared ``TransportDispatcher``
for scope/audit, and the STRUCTURAL oracle (not a new family) makes the actual decision.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING, Any

from reachagent.execution.firer import RequestFirer
from reachagent.execution.transports import TransportDispatcher

if TYPE_CHECKING:
    from reachagent.graph.store import ReachabilityGraph
    from reachagent.scan.orchestrator import ScanEvent

# Several common client-side merge-library encodings tried in ONE page load — a plain
# object destructured from `location.search` may accept any of these shapes depending on
# how the app parses query strings (bracket notation, dot notation, or a constructor-chain
# bypass some `__proto__`-blocking merges miss).
_QUERY_VARIANTS = (
    "__proto__[{marker}]=polluted",
    "__proto__.{marker}=polluted",
    "constructor[prototype][{marker}]=polluted",
)

_PROBE_TIMEOUT = 25.0
_MAX_ENDPOINTS = 5


def pollution_query(marker: str) -> str:
    """The injected query string for one probe (several encodings, one marker)."""
    return "&".join(v.format(marker=marker) for v in _QUERY_VARIANTS)


def pollution_check_js(marker: str) -> str:
    """The in-page JS check: does a brand-new object literal carry ``marker``?"""
    return (
        f"() => {{ try {{ return ({{}}).{marker} === 'polluted'; }}"
        " catch (e) { return false; } }"
    )


async def probe_prototype_pollution(driver: Any, url: str, check_js: str) -> tuple[int, bool]:
    """Navigate ``driver`` to ``url`` and evaluate ``check_js`` — the testable core.

    Takes an already-constructed ``AsyncBrowserDriver``-shaped object (real or fake), same
    seam ``browser/shim.py``'s ``run_taint_shim_async`` uses — hermetic tests inject a fake
    driver here; only the real browser launch/close in ``run_prototype_pollution`` below is
    untested plumbing, exactly mirroring ``scan/xss_dom.py``'s established split.
    """
    response = await driver.navigate(url)
    status = int(getattr(response, "status", 0) or 0)
    polluted = bool(await driver.evaluate(check_js))
    return status, polluted


def run_prototype_pollution(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    seam: Any,
    events: list[ScanEvent],
) -> list[str]:
    """Probe HTML endpoints for client-side prototype pollution via a headless browser."""
    from playwright.async_api import async_playwright as pw_ctx

    from reachagent.browser.playwright_driver import AsyncPlaywrightDriver
    from reachagent.oracles import OracleMechanism
    from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence
    from reachagent.scan.orchestrator import ScanEvent

    html_endpoints = [
        ep
        for _, ep in graph.endpoints()
        if ep.method == "GET" and "html" in (ep.content_type or "").lower()
    ]
    if not html_endpoints:
        events.append(
            ScanEvent(
                phase="payloads",
                kind="not-applicable",
                message="prototype_pollution: no HTML endpoints discovered",
            )
        )
        return []

    found: list[str] = []
    for endpoint in html_endpoints[:_MAX_ENDPOINTS]:
        marker = f"rapp{uuid.uuid4().hex[:10]}"
        separator = "&" if "?" in endpoint.path else "?"
        url = f"{base_url.rstrip('/')}{endpoint.path}{separator}{pollution_query(marker)}"
        check_js = pollution_check_js(marker)

        async def _probe(url: str = url, check_js: str = check_js) -> tuple[int, bool]:
            async with pw_ctx() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    page = await browser.new_page()
                    return await probe_prototype_pollution(
                        AsyncPlaywrightDriver(page), url, check_js
                    )
                finally:
                    await browser.close()

        try:
            dispatcher = TransportDispatcher(firer)
            dispatcher.prepare_browser(identity, url)
            status, polluted = asyncio.run(asyncio.wait_for(_probe(), timeout=_PROBE_TIMEOUT))
            dispatcher.record_browser(identity, url, method="GET", status_code=status)
        except Exception as exc:  # noqa: BLE001 — one probe's browser crash can't abort others
            events.append(
                ScanEvent(
                    phase="payloads",
                    kind="error",
                    message=f"prototype_pollution {endpoint.path}: {type(exc).__name__}",
                )
            )
            continue

        verdict = seam.run(
            OracleMechanism.STRUCTURAL,
            StructuralEvidence(
                check_type=StructuralCheckType.PROTOTYPE_POLLUTION,
                probe_status=status,
                polluted=polluted,
                evidence_ref=f"orchestrator/prototype_pollution{endpoint.path}",
            ),
        )
        if verdict.is_violation:
            nid = seam.write("prototype_pollution", seam.last, severity="high")
            if nid:
                found.append(nid)
                events.append(
                    ScanEvent(
                        phase="payloads",
                        kind="finding",
                        message=f"prototype pollution at {endpoint.path}",
                        details={"path": endpoint.path},
                    )
                )

    if not found:
        events.append(
            ScanEvent(
                phase="payloads",
                kind="not-applicable",
                message="prototype_pollution: no pollution confirmed",
            )
        )
    return found
