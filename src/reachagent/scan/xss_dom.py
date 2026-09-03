"""DOM XSS detection via the taint-tracking shim and execution oracle.

Technique-diversity corroboration (v3 V3): a confirmed flow is corroborated
against a SECOND, independent browser navigation to the same URL before being
trusted — ruling out a one-off flake in async JS execution or the taint
shim's own instrumentation rather than a genuinely reproducible sink. This
driver predates ``xss/detector.py``'s ``XssProber`` pattern (it dispatches the
oracle inline rather than through that module) so the corroboration is wired
directly here, following the same ``corroborate_with_variant`` shape as every
other v3 V3 slice. No opt-in flag: the second navigation only ever fires on
an already-confirmed candidate (never speculative), and — like every browser
probe in this module — is read-only (no state-changing request).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
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
    from reachagent.confirmation.corroboration import corroborate_with_variant
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
        if not verdict.is_violation:
            continue

        def _second_attempt(
            _url: str = url,
            _path: str = endpoint.path,
            _dispatcher: TransportDispatcher = dispatcher,
        ) -> object:
            try:
                _dispatcher.prepare_browser(identity, _url)
                second_result = asyncio.run(asyncio.wait_for(_probe(_url), timeout=_PROBE_TIMEOUT))
            except Exception:  # noqa: BLE001 — a flaky corroborating probe fails closed, not loudly
                return SimpleNamespace(is_violation=False)
            _dispatcher.record_browser(
                identity,
                second_result.final_url or _url,
                method="GET",
                status_code=second_result.status_code,
            )
            if not second_result.flows and not second_result.executed:
                return SimpleNamespace(is_violation=False)
            second_kwargs: dict[str, Any] = {
                "executed": second_result.executed,
                "evidence_ref": f"orchestrator/xss_dom{_path}",
            }
            if second_result.flows:
                second_kwargs["flows"] = second_result.flows
            return seam.run(
                OracleMechanism.EXECUTION_CONFIRMATION,
                ExecutionConfirmationEvidence(**second_kwargs),
            )

        result = corroborate_with_variant(verdict, _second_attempt)
        if not result.corroborated:
            continue
        nid = seam.write("xss_dom", seam.last, severity="high", metadata={"corroborated": "1"})
        if nid:
            found.append(nid)
            events.append(
                ScanEvent(
                    phase="payloads",
                    kind="finding",
                    message=f"dom xss at {endpoint.path} (corroborated by a second navigation)",
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
