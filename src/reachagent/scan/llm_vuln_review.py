"""LLM-driven vulnerability review (v4 R1) — a broad surface-shape survey whose
own judgment is now a real confirmed finding when it holds up under confirmation.

This module lets an LLM look at a target's discovered surface and propose
specific things it believes are vulnerable, the same broad judgment style
common to autonomous pentest agents generally. ReachAgent's own `run_oracle`
seam already made this move for every other detector: `judge()`
(`oracles/llm_judgment.py`) has full, unconditional decision authority — no
fixed `decide()` logic left anywhere. This module used to carve out an
exception for its OWN broad survey judgment, writing a permanently-unconfirmed
tier instead of ever calling `run_oracle` — an inconsistency the operator
explicitly overrode (v4 R1): every LLM judgment is a real, confirmed finding,
this one included, one findings list.

Two-stage, same as before: one bounded survey call proposes up to `_MAX_ITEMS` specific
leads from the discovered surface shape; each proposed lead then gets its own real
`run_oracle` judgment call (`oracles/surface_judgment.py::SurfaceJudgmentEvidence`) before
anything is written — the survey call alone was never enough to write a Finding, exactly
the same two-step shape every other signal-gated candidate in this codebase already uses
(a source proposes, `run_oracle` decides).

Called at two bounded points in a scan (a structural surface digest — paths/methods/
params/sink types/app-domain/tech — plus what is already confirmed, so it doesn't repeat
itself): once after recon/surface-mapping (before Phase 3 vulnerability testing starts),
so a first batch is visible live well before the report phase, and once more after Phase 3
confirms its own findings, so the final review sees the fuller surface and the now-larger
confirmed list. Each call passes the OTHER call's own already-confirmed findings through
"already CONFIRMED" so the two passes don't repeat each other (operator feedback: leads
were previously all written in one silent batch at the very end of the scan, reading as
"dumped at once" rather than found live).
**Disclosed limit**: this reviews structure, not live response content — ReachAgent's
audit trail deliberately never persists response bodies (secrets/privacy), so this is
not a review of actual traffic the way a human manually reading responses would do.
Fails open (nothing written) on any error, exactly like ``classify_app_domain``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from reachagent.graph.nodes import Finding
from reachagent.graph.store import ReachabilityGraph
from reachagent.llm.client import build_openai_compatible_client
from reachagent.oracles import OracleMechanism
from reachagent.oracles.surface_judgment import SurfaceJudgmentEvidence
from reachagent.tools import validator

if TYPE_CHECKING:
    from reachagent.scan.orchestrator import ScanEvent

_log = logging.getLogger(__name__)

_MAX_ITEMS = 12
_MAX_ENDPOINTS_IN_PROMPT = 60
_MAX_FIELD = 200
_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

_PROMPT = (
    "You are an experienced web/API pentester reviewing a scan's discovered surface for an "
    "AUTHORIZED assessment. Findings listed as CONFIRMED below are already proven — do not "
    "repeat those. Based on your own judgment (naming conventions, parameter shapes, missing "
    "controls, what this kind of application usually gets wrong), flag up to {max_items} "
    "SPECIFIC things you believe are real vulnerabilities, worth reporting. Name the actual "
    "endpoint/parameter — never a generic category with no target. Each one you name will be "
    "independently judged against this same context before being reported — only name things "
    "you're actually confident hold up.\n\n"
    'Reply ONLY as JSON: {{"leads": [{{"vuln_class": "...", "endpoint": "...", '
    '"location": "...", "reason": "one short sentence", "severity": '
    '"critical|high|medium|low|info"}}]}} (empty list if nothing stands out).\n\n'
    "Application: {app_domain}\n\n"
    "CONFIRMED (do not repeat):\n{confirmed}\n\n"
    "Discovered surface:\n{surface}"
)


def _surface_digest(
    graph: ReachabilityGraph, *, max_endpoints: int = _MAX_ENDPOINTS_IN_PROMPT
) -> str:
    endpoints = sorted(graph.endpoints(), key=lambda pair: pair[1].path)
    lines: list[str] = []
    for ep_node, ep in endpoints[:max_endpoints]:
        params = []
        for _pn, param in graph.parameters_of(ep_node):
            sink = f" ({param.inferred_sink_type.value})" if param.inferred_sink_type else ""
            params.append(f"{param.name}[{param.location}]{sink}")
        line = f"{ep.method} {ep.path}"
        if params:
            line += " params: " + ", ".join(params)
        lines.append(line)
    if len(endpoints) > max_endpoints:
        lines.append(f"... ({len(endpoints) - max_endpoints} more endpoint(s) omitted)")
    return "\n".join(lines) or "(no endpoints discovered)"


def _findings_digest(pairs: list[tuple[str, str]]) -> str:
    return "\n".join(f"- {line}" for line in pairs[:40]) or "(none)"


def _clean(value: object, *, maximum: int = _MAX_FIELD) -> str:
    return str(value or "").replace("\n", " ").replace("\r", " ").strip()[:maximum]


def run_llm_vulnerability_review(
    *,
    graph: ReachabilityGraph,
    client: object | None = None,
    events: list[ScanEvent] | None = None,
) -> int:
    """One bounded LLM survey pass, each lead independently confirmed before writing.

    Returns the number of new ``Finding`` nodes written (0 on any failure, an empty
    model reply, when nothing was discovered yet, or when no proposed lead's own
    confirmation judgment holds up). ``client`` (any object exposing ``propose_json``)
    is injectable for tests, and reused for BOTH the survey call and every per-lead
    confirmation call in this pass (one client, not one build per lead). ``events``,
    when given, gets one event PER confirmed finding as it's written (not just a final
    count) — operator feedback: leads only ever showed up via the next GUI poll
    re-reading the whole graph, reading as a silent batch dump rather than something
    found live, the same class of gap every other driver in this codebase already
    avoids by emitting its own per-item event.
    """
    if not list(graph.endpoints()):
        return 0
    app_domain = next((h.app_domain for _n, h in graph.hosts() if h.app_domain), "") or "unknown"
    confirmed = _findings_digest(
        [f"{f.vuln_class}: {f.evidence_ref[:120]}" for _fid, f in graph.findings()]
    )
    surface = _surface_digest(graph)
    try:
        reviewer = client if client is not None else build_openai_compatible_client()
        if reviewer is None:
            return 0
        result = reviewer.propose_json(  # type: ignore[attr-defined]
            _PROMPT.format(
                max_items=_MAX_ITEMS,
                app_domain=app_domain,
                confirmed=confirmed,
                surface=surface,
            ),
            max_tokens=1500,
        )
    except Exception as exc:  # noqa: BLE001 — this pass must never break the scan
        _log.warning("LLM vulnerability review failed (%s); no leads added", exc)
        return 0
    raw_leads = result.get("leads") if isinstance(result, dict) else None
    if not isinstance(raw_leads, list):
        return 0
    written = 0
    for raw in raw_leads[:_MAX_ITEMS]:
        if not isinstance(raw, dict):
            continue
        vuln_class = _clean(raw.get("vuln_class"), maximum=60)
        if not vuln_class:
            continue
        endpoint = _clean(raw.get("endpoint"))
        location = _clean(raw.get("location"), maximum=60)
        severity = _clean(raw.get("severity"), maximum=20).lower()
        if severity not in _VALID_SEVERITIES:
            severity = "info"
        reason = _clean(raw.get("reason")) or "flagged by LLM surface review"
        evidence = SurfaceJudgmentEvidence(
            vuln_class=vuln_class,
            endpoint=endpoint,
            location=location,
            reason=reason,
            surface_context=surface,
            evidence_ref=f"llm-vuln-review/{vuln_class}/{endpoint or 'unspecified'}",
        )
        try:
            verdict = validator.run_oracle(OracleMechanism.STRUCTURAL, evidence, client=reviewer)
        except Exception as exc:  # noqa: BLE001 — one lead's confirmation failing must not
            # abort the rest of the review pass.
            _log.warning("surface-judgment confirmation failed (%s); lead dropped", exc)
            continue
        if not verdict.is_violation:
            continue  # the LLM's own confirmation judgment did not hold up — dropped, not written
        finding = Finding(vuln_class=vuln_class, severity=severity, oracle_used="", evidence_ref="")
        node_id = validator.write_finding(graph, finding, verdict)
        written += 1
        if events is not None:
            from reachagent.scan.orchestrator import ScanEvent as _ScanEvent

            events.append(
                _ScanEvent(
                    phase="payloads",
                    kind="finding",
                    message=(
                        f"LLM review confirmed: {vuln_class} at {endpoint or '(unspecified)'}"
                    ),
                    details={"path": endpoint, "severity": severity, "finding": node_id},
                )
            )
    return written
