"""LLM-driven vulnerability review (v2, operator-requested) — Shannon/Strix-style LLM
judgment, WITHOUT weakening "no Finding without run_oracle".

The reference projects (Shannon, Strix, CAI, ...) let an LLM look at a target's surface
and directly decide "this is vulnerable" — their own code shows this is literal
self-attestation (e.g. Shannon's exploit validator is ``async () => true``). ReachAgent
keeps the deterministic-oracle proof gate (CLAUDE.md non-negotiable, kept deliberately
after this project's own research into those references), so this module gives the LLM
that same judgment call, but its output can only ever land in the structurally-separate
``SuspectedFinding`` tier — exactly like a signal-gated scanner's unverified claim
(``_make_signal_reconfirm``'s ``_suspect`` helper) or a white-box ``StaticAdvisory``. It
NEVER calls ``run_oracle``/``write_finding``/``add_finding``, and is rendered in the
report's permanently separate "Suspected / Unconfirmed (not oracle-verified)" section,
never counted in confirmed severity stats.

One bounded LLM call per scan (a structural surface digest — paths/methods/params/sink
types/app-domain/tech — plus what is already confirmed/suspected, so it doesn't repeat
them), reasoning the same way a human pentester would from surface shape alone.
**Disclosed limit**: this reviews structure, not live response content — ReachAgent's
audit trail deliberately never persists response bodies (secrets/privacy), so this is
not a review of actual traffic the way a human manually reading responses would do.
Fails open (empty / no leads) on any error, exactly like ``classify_app_domain``.
"""

from __future__ import annotations

import logging

from reachagent.graph.nodes import SuspectedFinding
from reachagent.graph.store import ReachabilityGraph
from reachagent.llm.client import build_openai_compatible_client

_log = logging.getLogger(__name__)

_MAX_ITEMS = 12
_MAX_ENDPOINTS_IN_PROMPT = 60
_MAX_FIELD = 200
_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

_PROMPT = (
    "You are an experienced web/API pentester reviewing a scan's discovered surface for an "
    "AUTHORIZED assessment. A separate deterministic verifier has ALREADY independently "
    "confirmed the findings listed as CONFIRMED below — do not repeat those, and do not "
    "repeat anything already listed as SUSPECTED. Based on your own judgment (naming "
    "conventions, parameter shapes, missing controls, what this kind of application "
    "usually gets wrong), flag up to {max_items} SPECIFIC things you suspect could be "
    "vulnerabilities and are worth a human testing by hand. Name the actual endpoint/"
    "parameter — never a generic category with no target. This is advisory only: it will "
    "be shown as 'Suspected, not oracle-verified', never as a proven finding.\n\n"
    'Reply ONLY as JSON: {{"leads": [{{"vuln_class": "...", "endpoint": "...", '
    '"location": "...", "reason": "one short sentence", "severity": '
    '"critical|high|medium|low|info"}}]}} (empty list if nothing stands out).\n\n'
    "Application: {app_domain}\n\n"
    "CONFIRMED (do not repeat):\n{confirmed}\n\n"
    "Already SUSPECTED (do not repeat):\n{already_suspected}\n\n"
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


def run_llm_vulnerability_review(*, graph: ReachabilityGraph, client: object | None = None) -> int:
    """One bounded LLM pass proposing Suspected leads from surface judgment alone.

    Returns the number of new ``SuspectedFinding`` nodes written (0 on any failure, an
    empty model reply, or when nothing was discovered yet). ``client`` (any object
    exposing ``propose_json``) is injectable for tests.
    """
    if not list(graph.endpoints()):
        return 0
    app_domain = next((h.app_domain for _n, h in graph.hosts() if h.app_domain), "") or "unknown"
    confirmed = _findings_digest(
        [f"{f.vuln_class}: {f.evidence_ref[:120]}" for _fid, f in graph.findings()]
    )
    already_suspected = _findings_digest(
        [f"{s.vuln_class}: {s.endpoint} ({s.location})" for _sid, s in graph.suspected_findings()]
    )
    try:
        reviewer = client if client is not None else build_openai_compatible_client()
        if reviewer is None:
            return 0
        result = reviewer.propose_json(  # type: ignore[attr-defined]
            _PROMPT.format(
                max_items=_MAX_ITEMS,
                app_domain=app_domain,
                confirmed=confirmed,
                already_suspected=already_suspected,
                surface=_surface_digest(graph),
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
        graph.add_suspected_finding(
            SuspectedFinding(
                vuln_class=vuln_class,
                endpoint=endpoint,
                location=location,
                source="llm_judgment",
                reason=_clean(raw.get("reason")) or "flagged by LLM surface review",
                severity=severity,
                confidence="advisory — not oracle-verified",
            )
        )
        written += 1
    return written
