"""General Explorer browser recon for SPA targets (v2 W11; link discovery v2 Phase 6
Stage C).

Runs the browser recon shim (``browser/shim.py::run_browser_recon_async``) against
discovered HTML endpoints, then materializes any rendered forms AND links as new graph
facts — so a form/link ReachAgent could only see because a JS framework rendered it
(invisible to the static HTML parser, which sees only the empty ``<div id="root">``
shell a React/Vue app renders into) becomes a real ``Endpoint``/``Parameter`` fact,
reusing ``recon/surface.py``'s existing ``_form_endpoint`` builder for both (a link is
just a GET "form" with no controls) — no parallel endpoint-spec mechanism. Pure facts:
never a finding, never touches ``run_oracle``/``write_finding``.

Link materialization exists specifically so this driver, when re-invoked under a
freshly-derived identity by ``_run_attack_path_chain`` (v2 W17), can surface content a
privilege escalation unlocks: an admin nav link a SPA only renders for an elevated
session becomes a real ``Endpoint`` fact the same pass — narrowing (not fully closing)
the disclosed "re-hunts only already-discovered endpoints" limit for anything the app
itself reveals through conditional rendering (not a general crawler/brute-force
replacement — an endpoint nothing on any rendered page links to is still invisible).
Endpoint-level STRUCTURAL checks (clickjacking, CORS, BOLA's path-pattern probing) can
test the new endpoint in that same pass; per-parameter injection classes (nosqli, sqli,
...) still need the separate fingerprinting pass below before they will — the same
disclosed limit newly-materialized FORM parameters already had.

**Disclosed scope limit**: newly-materialized parameters here are NOT automatically
fingerprinted (``inferred_sink_type`` stays ``None``) — sink-type inference
(``tools/explorer.py``'s ``fingerprint`` tool) is a separate, on-demand Explorer pass
in the live agentic loop, not a bulk step this driver can safely trigger inline. A
follow-up would wire fingerprinting for post-recon-discovered parameters; until then,
these new endpoints are genuinely visible (in the graph/report/GUI, and to LLM-driven
candidate generation) but not yet auto-tested by the injection drivers that gate on
``inferred_sink_type``.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from reachagent.execution.firer import RequestFirer
    from reachagent.graph.store import ReachabilityGraph
    from reachagent.scan.orchestrator import ScanEvent

_PROBE_TIMEOUT = 25.0
_MAX_ENDPOINTS = 5
_MAX_STORAGE_KEYS_LOGGED = 20
_MAX_LINKS_PER_PAGE = 25


def run_browser_recon(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    events: list[ScanEvent],
) -> int:
    """Probe HTML endpoints for SPA-rendered forms; materialize new endpoint facts.

    Returns the number of NEW endpoints materialized (0 if none, or the browser is
    unavailable) — an observability count, not a finding count.
    """
    from playwright.async_api import async_playwright as pw_ctx

    from reachagent.browser.playwright_driver import AsyncPlaywrightDriver
    from reachagent.browser.shim import run_browser_recon_async
    from reachagent.execution.transports import TransportDispatcher
    from reachagent.graph.nodes import Endpoint, Parameter
    from reachagent.recon.surface import _form_endpoint
    from reachagent.scan.orchestrator import ScanEvent

    html_endpoints = [
        ep
        for _, ep in graph.endpoints()
        if ep.method == "GET" and "html" in (ep.content_type or "").lower()
    ]
    if not html_endpoints:
        events.append(
            ScanEvent(
                phase="endpoints",
                kind="not-applicable",
                message="browser_recon: no HTML endpoints discovered",
            )
        )
        return 0

    existing_paths = {ep.path for _, ep in graph.endpoints()}
    materialized = 0
    storage_hits: set[str] = set()

    for endpoint in html_endpoints[:_MAX_ENDPOINTS]:
        url = f"{base_url.rstrip('/')}{endpoint.path}"

        async def _probe(url: str = url) -> Any:
            async with pw_ctx() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    page = await browser.new_page()
                    return await run_browser_recon_async(AsyncPlaywrightDriver(page), url)
                finally:
                    await browser.close()

        try:
            dispatcher = TransportDispatcher(firer)
            dispatcher.prepare_browser(identity, url)
            result = asyncio.run(asyncio.wait_for(_probe(), timeout=_PROBE_TIMEOUT))
            dispatcher.record_browser(identity, url, method="GET", status_code=result.status_code)
        except Exception as exc:  # noqa: BLE001 — one probe's browser crash can't abort others
            events.append(
                ScanEvent(
                    phase="endpoints",
                    kind="error",
                    message=f"browser_recon {endpoint.path}: {type(exc).__name__}",
                )
            )
            continue

        storage_hits.update(result.local_storage_keys)
        storage_hits.update(result.session_storage_keys)

        for index, form in enumerate(result.forms):
            spec = _form_endpoint(
                {
                    "action": form.action,
                    "method": form.method,
                    "controls": [{"name": name} for name in form.inputs],
                },
                url,
                index,
            )
            if spec is None or spec.path in existing_paths:
                continue
            existing_paths.add(spec.path)
            endpoint_node = graph.add_endpoint(
                Endpoint(
                    method=spec.method,
                    path=spec.path,
                    content_type=spec.content_type,
                    state_changing=spec.state_changing,
                    source=f"browser_recon:{spec.source}",
                    confidence=spec.confidence,
                    evidence_ref=spec.evidence_ref,
                )
            )
            for param in spec.parameters:
                graph.add_parameter(
                    endpoint_node,
                    Parameter(
                        name=param.name,
                        location=param.location,
                        serialization=param.serialization,
                        required=param.required,
                        example=param.example,
                        source=param.source,
                        confidence=param.confidence,
                        evidence_ref=param.evidence_ref,
                    ),
                )
            materialized += 1
            events.append(
                ScanEvent(
                    phase="endpoints",
                    # "info", not "finding" — this is a recon fact (a new endpoint
                    # exists), never a confirmed vulnerability; "finding" is
                    # reserved for a real run_oracle-confirmed Finding.
                    kind="info",
                    message=f"browser_recon: SPA-rendered endpoint discovered {spec.path}",
                    details={"path": spec.path, "method": spec.method},
                )
            )

        for link_index, href in enumerate(result.links[:_MAX_LINKS_PER_PAGE]):
            link_spec = _form_endpoint(
                {"action": href, "method": "GET", "controls": []}, url, link_index
            )
            if link_spec is None or link_spec.path in existing_paths:
                continue
            existing_paths.add(link_spec.path)
            link_node = graph.add_endpoint(
                Endpoint(
                    method=link_spec.method,
                    path=link_spec.path,
                    content_type=link_spec.content_type,
                    state_changing=link_spec.state_changing,
                    source=f"browser_recon_link:{link_spec.source}",
                    confidence=link_spec.confidence,
                    evidence_ref=link_spec.evidence_ref,
                )
            )
            for param in link_spec.parameters:
                graph.add_parameter(
                    link_node,
                    Parameter(
                        name=param.name,
                        location=param.location,
                        serialization=param.serialization,
                        required=param.required,
                        example=param.example,
                        source=param.source,
                        confidence=param.confidence,
                        evidence_ref=param.evidence_ref,
                    ),
                )
            materialized += 1
            events.append(
                ScanEvent(
                    phase="endpoints",
                    kind="info",
                    message=f"browser_recon: rendered link discovered {link_spec.path}",
                    details={"path": link_spec.path, "method": link_spec.method},
                )
            )

    if storage_hits:
        events.append(
            ScanEvent(
                phase="endpoints",
                kind="info",
                message=(
                    f"browser_recon: {len(storage_hits)} client-side storage "
                    "key(s) observed (names only, values never captured)"
                ),
                details={"keys": sorted(storage_hits)[:_MAX_STORAGE_KEYS_LOGGED]},
            )
        )
    if not materialized and not storage_hits:
        events.append(
            ScanEvent(
                phase="endpoints",
                kind="not-applicable",
                message="browser_recon: no new SPA facts discovered",
            )
        )
    return materialized
