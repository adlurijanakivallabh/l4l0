"""DOM XSS detection via the taint-tracking shim and execution oracle."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from reachagent.execution.firer import RequestFirer
from reachagent.execution.transports import TransportDispatcher

if TYPE_CHECKING:
    from reachagent.graph.store import ReachabilityGraph
    from reachagent.scan.orchestrator import ScanEvent


def run_xss_dom(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    seam: Any,
    events: list[ScanEvent],
) -> list[str]:
    """Probe HTML endpoints with a headless browser taint shim."""
    from playwright.async_api import async_playwright as pw_ctx

    from reachagent.browser.playwright_driver import AsyncPlaywrightDriver
    from reachagent.browser.shim import run_taint_shim_async
    from reachagent.oracles import OracleMechanism
    from reachagent.oracles.execution_confirmation import (
        ExecutionConfirmationEvidence,
    )
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
                message="xss_dom: no HTML endpoints discovered",
            )
        )
        return []

    # Playwright's navigation timeout doesn't cover evaluate() — a page whose
    # injected JS never returns (an infinite loop) hangs that await forever
    # with no built-in recovery. Bounding the whole probe guarantees the
    # browser process gets killed instead of pinning a CPU core indefinitely.
    _PROBE_TIMEOUT = 25.0

    found = []
    for endpoint in html_endpoints[:5]:
        url = base_url.rstrip("/") + endpoint.path + "#__reachagent_taint=1"

        async def _probe(url: str = url) -> Any:
            async with pw_ctx() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    page = await browser.new_page()
                    drv = AsyncPlaywrightDriver(page)
                    return await run_taint_shim_async(drv, identity, url, inject_shim=True)
                finally:
                    await browser.close()

        try:
            dispatcher = TransportDispatcher(firer)
            dispatcher.prepare_browser(identity, url)
            probe_result = asyncio.run(asyncio.wait_for(_probe(), timeout=_PROBE_TIMEOUT))
            dispatcher.record_browser(
                identity,
                probe_result.final_url or url,
                method="GET",
                status_code=probe_result.status_code,
            )
        except Exception as exc:
            events.append(
                ScanEvent(
                    phase="payloads",
                    kind="error",
                    message=f"xss_dom {endpoint.path}: {type(exc).__name__}",
                )
            )
            continue

        flows = probe_result.flows
        executed = probe_result.executed
        if not flows and not executed:
            continue

        kwargs: dict[str, Any] = {
            "executed": executed,
            "evidence_ref": f"orchestrator/xss_dom{endpoint.path}",
        }
        if flows:
            kwargs["flows"] = flows

        verdict = seam.run(
            OracleMechanism.EXECUTION_CONFIRMATION,
            ExecutionConfirmationEvidence(**kwargs),
        )
        if verdict.is_violation:
            nid = seam.write("xss_dom", seam.last, severity="high")
            if nid:
                found.append(nid)
                events.append(
                    ScanEvent(
                        phase="payloads",
                        kind="finding",
                        message=f"dom xss at {endpoint.path}",
                        details={"path": endpoint.path},
                    )
                )

    if not found:
        events.append(
            ScanEvent(
                phase="payloads",
                kind="not-applicable",
                message="xss_dom: no DOM sinks confirmed",
            )
        )
    return found
