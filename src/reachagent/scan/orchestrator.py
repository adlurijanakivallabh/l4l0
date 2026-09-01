"""All-class, LLM-driven scan orchestrator (23 classes → six oracle families).

The user prompt drives the plan; the deterministic engine confirms. Core phases:

  1. RECON     — cold-start facts + spec-first API discovery (reused from scan_target).
  2. ENDPOINTS — graph Endpoint/Parameter/Host shape; the LLM picks vuln-class priority
                 (allowlist-validated) — fallback is deterministic sink-matching.
  3. PAYLOADS  — per class, drive the existing deterministic machinery (tagged payloads →
                 fire → run_oracle → write_finding). Every finding is written only by the
                 Validator on an ``is_violation`` verdict.
  4. REPORT    — LLM narrative over ``CONFIRMED_VIOLATION`` findings + chain paths.

Confirmation is role-bounded and deterministic. The orchestrator is a **Validator-side
caller** — the documented validator seam injects
``validator.run_oracle`` / ``validator.write_finding`` into the per-class detectors. No
LLM proposer ever fires a request, calls an oracle, or writes a finding. Six oracle
families held; ``ScopeGuard`` + read-only-first + audit hold on every fire.

Classes that need conditions the discovered surface does not provide are reported as
``not-applicable`` (an honest event), never a fabricated finding.
"""

from __future__ import annotations

import logging
import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx

from reachagent.detection.oracle_gateway import OracleOutcome
from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import Endpoint, Finding, SinkType
from reachagent.graph.store import ReachabilityGraph, identity_id
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import OracleVerdict
from reachagent.tools import validator

if TYPE_CHECKING:
    from reachagent.identity.store import IdentityStore
    from reachagent.llm.planner import PlannerClient
    from reachagent.scan.agentic_loop import LoopAdvisorClient

_log = logging.getLogger(__name__)

# The "Phase 3: structural + authz + advanced classes" dispatch order (below,
# in scan_all_classes) — unlike the generic sink-matched classes (which get
# real per-candidate LLM class targeting via scan_target()'s nested
# REACHAGENT_VULN_TUNING call), these ~20 drivers run in one fixed, hardcoded
# sequence with zero LLM input. This is the default/fallback order.
_PHASE3_CLASS_ORDER: tuple[str, ...] = (
    "default_credentials",
    "rate_limit_absence",
    "structural_headers",
    "file_upload",
    "mass_assignment",
    "xss_stored",
    "open_redirect",
    "cache_poisoning",
    "request_smuggling",
    "subdomain_takeover",
    "jwt_forgery",
    "sqli_blind",
    "nosqli",
    "ldap",
    "command_injection",
    "authz_bola",
    "authz_idor",
    "graphql",
    "business_logic",
    "race",
    "xxe",
    "xss_dom",
)

# Named specialist personas (Agentic Coordinator, Phase 2) — a grouping of the
# Phase 3 drivers above, purely for narration: the GUI's live event feed
# shows which "specialist" is working, matching a multi-agent hand-off feel,
# without changing what actually runs. Every class still routes through the
# exact same driver function and oracle it always did.
_SPECIALIST_OF_CLASS: dict[str, str] = {
    "default_credentials": "auth",
    "rate_limit_absence": "auth",
    "structural_headers": "client_side",
    "open_redirect": "client_side",
    "cache_poisoning": "client_side",
    "xss_stored": "client_side",
    "xss_dom": "client_side",
    "file_upload": "injection",
    "sqli_blind": "injection",
    "nosqli": "injection",
    "ldap": "injection",
    "command_injection": "injection",
    "xxe": "injection",
    "request_smuggling": "protocol",
    "subdomain_takeover": "protocol",
    "jwt_forgery": "auth",
    "authz_bola": "auth",
    "authz_idor": "auth",
    "mass_assignment": "auth",
    "graphql": "api_logic",
    "business_logic": "api_logic",
    "race": "api_logic",
}

_SPECIALIST_LABELS: dict[str, str] = {
    "client_side": "Client-Side Specialist",
    "injection": "Injection Specialist",
    "protocol": "Protocol Specialist",
    "auth": "Auth & Authorization Specialist",
    "api_logic": "API & Business-Logic Specialist",
}

_PHASE3_RANK_PROMPT = """You are prioritizing the ORDER in which vulnerability-class \
checks run against a web/API target, given what recon has discovered so far. You are \
NOT deciding whether anything is vulnerable, and every class listed still runs \
regardless of order — only sequencing changes.

Return ONLY a JSON object: {{"order": [...], "reason": "one sentence"}}. "order" must \
contain every one of these class names exactly once, spelled exactly as given, in your \
preferred priority order (most relevant to this target first):

{classes}

Target signals:
{signals}
"""


def _class_priority_signals(
    graph: ReachabilityGraph, operator_prompt: str | None
) -> dict[str, str]:
    """Compact, bounded graph-derived signals for the class-priority LLM call."""
    signals: dict[str, str] = {}
    endpoints = list(graph.endpoints())
    signals["endpoint_count"] = str(len(endpoints))
    methods = sorted({ep.method for _, ep in endpoints if ep.method})
    if methods:
        signals["methods"] = ",".join(methods)[:120]
    techs = sorted({h.technology for _, h in graph.hosts() if h.technology})
    if techs:
        signals["host_tech"] = ",".join(techs)[:200]
    if graph.sessions():
        signals["auth_surface"] = "yes"
    if operator_prompt:
        signals["operator_goal"] = operator_prompt[:500]
    return signals


def rank_vuln_classes(
    class_names: tuple[str, ...],
    graph: ReachabilityGraph,
    *,
    operator_prompt: str | None = None,
    client: object | None = None,
) -> tuple[tuple[str, ...], str]:
    """LLM-proposed priority ORDER for the Phase 3 class dispatch (§9 resilience).

    Order only — every class in ``class_names`` still runs; the LLM can never
    remove one (any name it omits or hallucinates past is appended back in
    its original relative order). Flag-gated on ``REACHAGENT_VULN_TUNING``
    (already enabled for every GUI scan via ``llm.runtime.override``, so this
    activates with zero new configuration). Falls back to the original order
    on any failure or invalid response — this is a strategy convenience, not
    something a scan should ever abort over.
    """
    from reachagent.llm.runtime import flag_enabled

    if not flag_enabled("REACHAGENT_VULN_TUNING"):
        return class_names, (
            "class-priority tuning disabled (REACHAGENT_VULN_TUNING unset) — default order"
        )
    try:
        from reachagent.llm.client import build_openai_compatible_client

        tuner = client or build_openai_compatible_client()
        if tuner is None:
            raise RuntimeError("no LLM provider configured for class-priority ranking")
        signals = _class_priority_signals(graph, operator_prompt)
        prompt = _PHASE3_RANK_PROMPT.format(
            classes=", ".join(class_names),
            signals="\n".join(f"{k}: {v}" for k, v in signals.items()) or "(none collected)",
        )
        raw = tuner.propose_json(prompt, max_tokens=512)
        proposed = raw.get("order")
        reason = str(raw.get("reason", "") or "")[:300]
        if not isinstance(proposed, list):
            raise ValueError("response missing a valid 'order' list")
        seen: set[str] = set()
        ordered: list[str] = []
        for name in proposed:
            if isinstance(name, str) and name in class_names and name not in seen:
                ordered.append(name)
                seen.add(name)
        ordered.extend(name for name in class_names if name not in seen)
        return tuple(ordered), reason or "LLM-prioritized class order"
    except Exception as exc:  # noqa: BLE001 — an ordering convenience must never break a scan
        _log.warning("class-priority ranking failed (%s); falling back to default order", exc)
        return class_names, (
            f"class-priority ranking unavailable ({type(exc).__name__}) — default order"
        )


# Every attack class the orchestrator can dispatch. This is the §9 coverage target —
# each class below maps to one of the six §7 oracle families; nothing here invents a
# seventh family or a non-§6 edge.
ALL_CLASSES: tuple[str, ...] = (
    "sqli",
    "sqli_blind",
    "nosqli",
    "ldap_injection",
    "command_injection",
    "xss_reflected",
    "xss_stored",
    "xss_dom",
    "ssti",
    "ssrf",
    "xxe",
    "path_traversal",
    "file_upload",
    "jwt_forgery",
    "bola",
    "bfla",
    "mass_assignment",
    "idor",
    "business_logic",
    "clickjacking",
    "cors_misconfig",
    "open_redirect",
    "csrf_missing_protection",
    "web_cache_poisoning",
    "request_smuggling",
    "subdomain_takeover",
    "graphql",
    "race",
)

_GENERIC_CLASSES = frozenset(
    {
        "sqli",
        "xss_reflected",
        "path_traversal",
        "ssti",
        "nosqli",
        "ldap_injection",
        "command_injection",
        "ssrf",
    }
)

_ATTACKER_ORIGIN = "https://reachagent.evil.example"
_UPLOAD_PATHS = (
    "/upload",
    "/file-upload",
    "/files",
    "/api/upload",
    "/uploads",
    "/profile/image/file",
)
_AUTH_PATH_HINTS = ("auth", "login", "jwt", "token", "session", "signin", "user", "api/user")
_CSRF_BODY_MARKERS = re.compile(r"csrf|authenticity_token|_token|csrfmiddleware", re.I)
_TIMING_TRIALS = 10


@dataclass
class ScanEvent:
    """One streamable event from the orchestrator → GUI (phase timeline)."""

    phase: str  # plan | recon | endpoints | insertion-points | payloads | verification | report
    kind: str  # info | plan | step | verdict | finding | not-applicable | error
    message: str
    details: dict[str, Any] = field(default_factory=dict)


def _emit(events: list[ScanEvent], phase: str, kind: str, message: str, **details: Any) -> None:
    events.append(ScanEvent(phase=phase, kind=kind, message=message, details=details))


class _ValidatorSeam:
    """Validator-side seam: real run_oracle / write_finding.

    Detectors get ``seam.run`` as their ``oracle_runner`` (duck-compatible with
    ``OracleOutcome``: ``OracleVerdict`` exposes ``is_violation``/``confirmed``/``status``).
    Findings are written only via ``validator.write_finding`` on an ``is_violation``
    verdict — the CLAUDE.md non-negotiable, unchanged.
    """

    def __init__(self, graph: ReachabilityGraph) -> None:
        self.graph = graph
        self._last: OracleVerdict | None = None

    def run(self, mechanism: OracleMechanism, evidence: object) -> OracleOutcome:
        """Satisfy the detectors' ``OracleRunner`` protocol (which returns OracleOutcome)."""
        self._last = validator.run_oracle(mechanism, evidence)
        return OracleOutcome(self._last)

    @property
    def last(self) -> OracleVerdict | None:
        """The most recent oracle verdict — the one a multi-probe detector confirmed on."""
        return self._last

    def write(
        self,
        vuln_class: str,
        verdict: OracleVerdict | None,
        *,
        severity: str = "high",
        metadata: dict[str, str] | None = None,
    ) -> str | None:
        if verdict is None or not verdict.is_violation:
            return None
        finding = Finding(
            vuln_class=vuln_class,
            severity=severity,
            oracle_used="",
            evidence_ref="",
        )
        return validator.write_finding(self.graph, finding, verdict, metadata=metadata)


def _fire_readonly(
    firer: RequestFirer,
    identity: str,
    method: str,
    url: str,
    *,
    events: list[ScanEvent],
    label: str,
    headers: Mapping[str, str] | None = None,
) -> Any | None:
    """Fire one read-only request through the gated firer; ``None`` on refusal/error."""
    try:
        return firer.fire(identity, method, url, state_changing=False, headers=dict(headers or {}))
    except Exception as exc:  # noqa: BLE001 — a refused/errored probe is not a signal
        _emit(events, "payloads", "error", f"{label}: fire refused ({type(exc).__name__})")
        return None


def _identity_for_scan(
    identities: IdentityStore | None, events: list[ScanEvent]
) -> tuple[str, Mapping[str, str]]:
    """Pick the scan identity + its auth header mapping, or a seeded unauth identity."""
    if identities is not None and identities.names():
        name = identities.names()[0]
        return name, identities.auth_headers(name)
    _emit(events, "endpoints", "info", "no identities seeded — scanning unauth")
    return "seed", {}


# ---------------------------------------------------------------------------
# Phase 3 — structural-header classes (clickjacking / CORS / CSRF)
# ---------------------------------------------------------------------------


def run_structural_headers(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    auth_headers: Mapping[str, str],
    seam: _ValidatorSeam,
    events: list[ScanEvent],
) -> list[str]:
    """Read-only header checks on ``/`` + HTML endpoints for the three client-side classes.

    Each check fires a GET through the gated firer, reads response headers, and runs the
    STRUCTURAL oracle with the exact evidence shape the existing detectors use. The server
    response is the only input; nothing is state-changing.
    """
    from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence

    targets: list[str] = []
    for _, ep in graph.endpoints():
        ct = (ep.content_type or "").lower()
        if ep.method == "GET" and ep.path not in targets and ("html" in ct or not ct):
            targets.append(ep.path)
    targets = (["/"] + targets)[:8]
    found: list[str] = []

    for path in targets:
        url = f"{base_url.rstrip('/')}{path}"
        label = f"header {path}"
        result = _fire_readonly(
            firer, identity, "GET", url, events=events, label=label, headers=auth_headers
        )
        if result is None:
            continue
        # CORS needs an attacker Origin to observe reflection.
        cors_headers: dict[str, str] = dict(auth_headers)
        cors_headers["Origin"] = _ATTACKER_ORIGIN
        cors_result = _fire_readonly(
            firer,
            identity,
            "GET",
            url,
            events=events,
            label=f"{label}/cors",
            headers=cors_headers,
        )

        def _hdr(response: Any | None, name: str) -> str:
            return str(response.headers.get(name, "")) if response is not None else ""

        # Clickjacking only applies to pages a user actually frames. A JSON/XML/API
        # response with no X-Frame-Options is NOT a clickjacking finding — running the
        # check on it would be a false positive. CORS + CSRF still apply to any endpoint.
        is_html = "html" in _hdr(result, "content-type").lower()
        if not is_html:
            _emit(events, "payloads", "not-applicable", f"{label}: not HTML — clickjacking skipped")

        # 1. Clickjacking — both framing defenses absent (HTML responses only).
        verdict = None
        if is_html:
            verdict = seam.run(
                OracleMechanism.STRUCTURAL,
                StructuralEvidence(
                    check_type=StructuralCheckType.CLICKJACKING,
                    x_frame_options=_hdr(result, "x-frame-options"),
                    csp=_hdr(result, "content-security-policy"),
                    evidence_ref=f"orchestrator/clickjacking{path}",
                ),
            )
        if verdict is not None and verdict.is_violation:
            nid = seam.write("clickjacking", seam.last, severity="medium")
            if nid:
                found.append(nid)
                _emit(events, "payloads", "finding", "clickjacking — no framing defense", path=path)

        # 2. CSRF precondition — SameSite=None cross-site session cookie, no token.
        body = result.body.decode("utf-8", errors="replace")
        token_present = bool(_CSRF_BODY_MARKERS.search(body)) or any(
            "csrf" in k.lower() for k in result.headers.keys()
        )
        verdict = seam.run(
            OracleMechanism.STRUCTURAL,
            StructuralEvidence(
                check_type=StructuralCheckType.CSRF_MISSING_PROTECTION,
                set_cookie=_hdr(result, "set-cookie"),
                csrf_token_present=token_present,
                evidence_ref=f"orchestrator/csrf{path}",
            ),
        )
        if verdict.is_violation:
            nid = seam.write("csrf_missing_protection", seam.last, severity="medium")
            if nid:
                found.append(nid)
                _emit(
                    events,
                    "payloads",
                    "finding",
                    "csrf — SameSite=None cookie, no anti-CSRF token",
                    path=path,
                )

        # 3. CORS — origin-reflected ACAO with credentials allowed.
        verdict = seam.run(
            OracleMechanism.STRUCTURAL,
            StructuralEvidence(
                check_type=StructuralCheckType.CORS_MISCONFIG,
                acao=_hdr(cors_result, "access-control-allow-origin"),
                acac=_hdr(cors_result, "access-control-allow-credentials"),
                probe_origin=_ATTACKER_ORIGIN,
                evidence_ref=f"orchestrator/cors{path}",
            ),
        )
        if verdict.is_violation:
            nid = seam.write("cors_misconfig", seam.last, severity="medium")
            if nid:
                found.append(nid)
                _emit(
                    events,
                    "payloads",
                    "finding",
                    "cors — credentialed origin reflection",
                    path=path,
                )
    return found


# ---------------------------------------------------------------------------
# Phase 3 — file_upload (multipart baseline + disguised probe)
# ---------------------------------------------------------------------------


def run_file_upload(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    auth_headers: Mapping[str, str],
    seam: _ValidatorSeam,
    events: list[ScanEvent],
) -> list[str]:
    """Structural FILE_UPLOAD_BYPASS on known upload endpoints.

    Baseline = a legitimately allowed file (``.txt``); probe = a disguised file
    (``.php`` with text content). A 2xx on both is the bypass. Read-only-first: an
    OPTIONS preflight must clear the endpoint before the POST fires; if the endpoint
    refuses a read-only probe, upload is reported not-applicable (no state change).
    """
    from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence

    found: list[str] = []
    seen: set[str] = set()
    for path in _UPLOAD_PATHS:
        if path in seen:
            continue
        seen.add(path)
        url = f"{base_url.rstrip('/')}{path}"
        label = f"upload {path}"
        # Read-only-first: a 2xx OPTIONS (or GET) clears the endpoint before any POST.
        preflight = _fire_readonly(
            firer,
            identity,
            "OPTIONS",
            url,
            events=events,
            label=f"{label}/preflight",
            headers=auth_headers,
        )
        if preflight is None or not (200 <= preflight.status_code < 300):
            _emit(events, "payloads", "not-applicable", f"{label}: no read-only clearance")
            continue
        # Baseline: an allowed plain file.
        try:
            baseline = firer.fire(
                identity,
                "POST",
                url,
                state_changing=True,
                headers=dict(auth_headers),
                files={"file": ("ok.txt", b"reachagent baseline", "text/plain")},
            )
        except Exception:  # noqa: BLE001 — refused upload is not a bypass
            _emit(events, "payloads", "not-applicable", f"{label}: upload refused")
            continue
        # Probe: a disguised executable file (extension-only bypass).
        try:
            probe = firer.fire(
                identity,
                "POST",
                url,
                state_changing=True,
                headers=dict(auth_headers),
                files={"file": ("shell.php", b"<?php echo 'reachagent'; ?>", "application/x-php")},
            )
        except Exception as exc:  # noqa: BLE001
            _emit(
                events, "payloads", "error", f"{label}: probe fire refused ({type(exc).__name__})"
            )
            continue
        verdict = seam.run(
            OracleMechanism.STRUCTURAL,
            StructuralEvidence(
                check_type=StructuralCheckType.FILE_UPLOAD_BYPASS,
                baseline_status=baseline.status_code,
                probe_status=probe.status_code,
                evidence_ref=f"orchestrator/file_upload{path}",
            ),
        )
        if verdict.is_violation:
            nid = seam.write("file_upload", seam.last, severity="high")
            if nid:
                found.append(nid)
                _emit(events, "payloads", "finding", f"file upload bypass {path}", path=path)
    return found


# ---------------------------------------------------------------------------
# Phase 3 — jwt_forgery (precomputed tokens on token-bearing endpoints)
# ---------------------------------------------------------------------------


def run_jwt_forgery(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    auth_headers: Mapping[str, str],
    seam: _ValidatorSeam,
    events: list[ScanEvent],
) -> list[str]:
    """Structural JWT_FORGERY on endpoints that look token-bearing.

    Baseline = a valid bearer token (from the identity's session) must be accepted;
    probe = each precomputed forged token (none-alg / HS256-key-confusion / weak-secret /
    kid-injection)
    from the tagged library. A forged token accepted (2xx) is the violation.
    """
    from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence
    from reachagent.payloads.payload_resolver import _TEMPLATES

    _FORGED = (
        ("jwt_forgery/none-alg", "none-alg"),
        ("jwt_forgery/hs256-key-confusion", "hs256-key-confusion"),
        ("jwt_forgery/weak-secret", "weak-secret"),
        ("jwt_forgery/kid-injection", "kid-injection"),
    )
    found: list[str] = []
    valid_token = auth_headers.get("Authorization", "")
    if not valid_token.lower().startswith("bearer "):
        valid_token = ""
    targets: list[str] = []
    for _, ep in graph.endpoints():
        low = ep.path.lower()
        if any(hint in low for hint in _AUTH_PATH_HINTS) and ep.method == "GET":
            targets.append(ep.path)
    for path in targets[:6]:
        url = f"{base_url.rstrip('/')}{path}"
        label = f"jwt {path}"
        if not valid_token:
            _emit(events, "payloads", "not-applicable", f"{label}: no valid token to baseline")
            continue
        baseline = _fire_readonly(
            firer,
            identity,
            "GET",
            url,
            events=events,
            label=f"{label}/baseline",
            headers=auth_headers,
        )
        if baseline is None:
            continue
        for ref, name in _FORGED:
            forged = _TEMPLATES.get(ref)
            if not forged:
                continue
            probe = _fire_readonly(
                firer,
                identity,
                "GET",
                url,
                events=events,
                label=f"{label}/{name}",
                headers={**auth_headers, "Authorization": f"Bearer {forged}"},
            )
            if probe is None:
                continue
            verdict = seam.run(
                OracleMechanism.STRUCTURAL,
                StructuralEvidence(
                    check_type=StructuralCheckType.JWT_FORGERY,
                    baseline_status=baseline.status_code,
                    probe_status=probe.status_code,
                    evidence_ref=f"orchestrator/jwt_forgery/{name}{path}",
                ),
            )
            if verdict.is_violation:
                nid = seam.write(
                    "jwt_forgery", seam.last, severity="high", metadata={"forged": name}
                )
                if nid:
                    found.append(nid)
                    _emit(
                        events, "payloads", "finding", f"jwt forgery accepted ({name})", path=path
                    )
                break
    return found


# ---------------------------------------------------------------------------
# Phase 3 — sqli_blind (OOB-first → timing paired trials → boolean)
# ---------------------------------------------------------------------------


def run_sqli_blind(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    seam: _ValidatorSeam,
    events: list[ScanEvent],
    library: Any | None = None,
    payload_ref: str = "sqli/blind/timing-sleep-paired",
) -> list[str]:
    """Blind SQLi via the existing detector (OOB-first, timing fallback, boolean).

    Timing uses ≥10 paired probe/baseline trials through the gated firer — the
    ``timing_statistical`` oracle is the honest fallback when no OOB collaborator is
    configured. Runs on parameters whose sink is SQL.
    """
    from reachagent.payloads.payload_resolver import resolve
    from reachagent.sqli.blind_detector import (
        BlindSqliProber,
        TimingProbe,
        detect_blind_sqli,
    )
    from reachagent.tools.explorer import _fire_with_value
    from reachagent.tools.explorer_context import ExplorerContext

    ctx = ExplorerContext(
        graph=graph, firer=firer, library=library or _library(), base_url=base_url
    )
    delay_payload = resolve(payload_ref, sleep="5")

    def _probe_param(ep: Endpoint, param: Any, label: str) -> str | None:
        """Paired-trial blind-SQLi probe for ONE sql-sink parameter (no closure capture)."""
        base_url_path = f"{base_url.rstrip('/')}{ep.path}"

        def _fire_value(value: str, method: str = "GET") -> Any | None:
            try:
                return _fire_with_value(
                    ctx,
                    identity,
                    method,
                    base_url_path,
                    param.location,
                    param.name,
                    value,
                    state_changing=False,
                )
            except Exception as exc:  # noqa: BLE001
                _emit(events, "payloads", "error", f"{label}: fire failed ({type(exc).__name__})")
                return None

        def fire_timing() -> TimingProbe:
            probe_ms: list[float] = []
            baseline_ms: list[float] = []
            for _ in range(_TIMING_TRIALS):
                p = _fire_value(delay_payload)
                if p is not None:
                    probe_ms.append(p.elapsed_seconds * 1000)
                b = _fire_value("baseline")
                if b is not None:
                    baseline_ms.append(b.elapsed_seconds * 1000)
            return TimingProbe(tuple(probe_ms), tuple(baseline_ms))

        # OOB collaborator: active when env is configured, dormant otherwise.
        oob_collaborator = None
        if os.environ.get("REACHAGENT_OOB_BASE_DOMAIN"):
            from reachagent.oob.collaborator import InteractshCollaborator

            try:
                oob_collaborator = InteractshCollaborator()
            except Exception:  # noqa: BLE001, S110 — no OOB domain configured is valid
                pass

        if oob_collaborator is not None:

            def fire_oob() -> Any:
                from reachagent.sqli.blind_detector import OOBProbe

                nonce = "ra" + uuid.uuid4().hex[:12]
                domain = oob_collaborator.callback_domain(nonce)
                return OOBProbe(nonce=nonce, callback_domain=domain)

            observed_nonces_fn = lambda: oob_collaborator.observed_nonces()  # noqa: E731
            oob_domain = oob_collaborator._base_domain
            _emit(events, "payloads", "step", f"OOB collaborator active ({oob_domain})")
        else:

            def fire_oob() -> Any:
                return None  # OOB dormant without a collaborator (honest)

            def observed_nonces_fn() -> frozenset[str]:
                return frozenset()

        prober = BlindSqliProber(
            fire_oob=fire_oob,
            observed_nonces=observed_nonces_fn,
            fire_timing=fire_timing,
            oracle_runner=seam.run,
        )
        result = detect_blind_sqli(
            prober, evidence_ref=f"orchestrator/sqli_blind{label}", try_boolean=False
        )
        if not result.confirmed:
            return None
        verdict = seam.last
        if verdict is None:
            return None
        mechanism = result.mechanism.value if result.mechanism is not None else "unknown"
        nid = seam.write(
            "sqli_blind",
            verdict,
            severity="high",
            metadata={"mechanism": mechanism},
        )
        if nid:
            _emit(
                events,
                "payloads",
                "finding",
                f"blind sqli via {mechanism}",
                path=ep.path,
                param=param.name,
            )
        return nid

    found: list[str] = []
    for ep_node, ep in graph.endpoints():
        for _param_node, param in graph.parameters_of(ep_node):
            if param.inferred_sink_type is not SinkType.SQL:
                continue
            if param.location not in ("query", "path", "body"):
                continue
            label = f"sqli-blind {ep.path} {param.name}"
            nid = _probe_param(ep, param, label)
            if nid:
                found.append(nid)
    return found


# ---------------------------------------------------------------------------
# Phase 3 — blind / auth-bypass injection drivers (nosqli / ldap / command
# injection). Their sinks now route (B1a), but the refused->granted auth-bypass
# and blind time-delay patterns are only confirmable by their dedicated
# deterministic detectors — the generic fire-and-diff chain cannot express them
# (methodology: auth/blind classes are not payload spray). Every probe is a
# read-only GET through the gated firer; the oracles fail closed (auth-bypass
# needs a 4xx baseline -> 2xx probe, timing needs >=10 paired trials past a
# 3-sigma control), so a non-vulnerable param yields no finding.
# ---------------------------------------------------------------------------

# Canonical, best-effort injection primitives (stimulus only; the oracle, not the
# payload, decides). Kept here, not in the corpus, because these drive a fixed
# detector rather than the tagged-library chain.
_NOSQL_BYPASS_VALUE = '{"$ne": null}'
_NOSQL_TIMING_VALUE = '{"$where": "sleep(5000)"}'
_LDAP_BYPASS_VALUE = "*)(uid=*))(|(uid=*"
_LDAP_TIMING_VALUE = "*)(&(uid=*)(|(sleep=5)))"
_CMD_TIMING_VALUE = ";sleep 5"
_INJECTABLE_LOCATIONS = ("query", "path", "body")


def _fire_value_fn(ctx: Any, identity: str, base_url: str, ep: Endpoint, param: Any) -> Any:
    """A ``fire(value) -> FireResult | None`` closure for one param (read-only GET)."""
    from reachagent.tools.explorer import _fire_with_value

    url = f"{base_url.rstrip('/')}{ep.path}"

    def _fire(value: str) -> Any | None:
        try:
            return _fire_with_value(
                ctx,
                identity,
                "GET",
                url,
                param.location,
                param.name,
                value,
                state_changing=False,
            )
        except Exception:  # noqa: BLE001 — a failed probe is a dead lead, never a finding
            return None

    return _fire


def _paired_timing(fire: Any, delay_value: str) -> tuple[tuple[float, ...], tuple[float, ...]]:
    """``_TIMING_TRIALS`` paired (delay, baseline) latencies in ms for the timing oracle."""
    probe_ms: list[float] = []
    baseline_ms: list[float] = []
    for _ in range(_TIMING_TRIALS):
        probe = fire(delay_value)
        if probe is not None:
            probe_ms.append(probe.elapsed_seconds * 1000)
        base = fire("baseline")
        if base is not None:
            baseline_ms.append(base.elapsed_seconds * 1000)
    return tuple(probe_ms), tuple(baseline_ms)


def _drives_param(param: Any, sink: SinkType) -> bool:
    """A param is a candidate only once it is OBSERVED/hinted as this class's sink.

    Strict match — the same rule ``run_sqli_blind`` uses for ``SinkType.SQL`` — not
    "sink or None". These sinks have no canary fingerprint of their own (B1a): a
    param only reaches ``sink`` once something has already tagged it (the generic
    loop trying this vuln_class's hint, or a prior probe). Requiring the match
    (rather than accepting an untyped ``None`` param too) is a plausibility gate,
    not a formality: the timing fallback below is a NOISY statistical oracle, and
    spraying it across every untyped param in the graph turns rare scheduler
    jitter into a near-certain false positive over a whole-graph scan (the exact
    "blind-probe every field" anti-pattern the funnel methodology forbids — blind
    escalation is reserved for points whose type makes the class plausible).
    """
    return param.location in _INJECTABLE_LOCATIONS and param.inferred_sink_type is sink


def run_nosqli(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    seam: _ValidatorSeam,
    events: list[ScanEvent],
    library: Any | None = None,
) -> list[str]:
    """NoSQL injection via the dedicated detector — auth-bypass first, timing fallback."""
    from reachagent.nosql.detector import (
        AuthBypassProbe,
        NoSqliProber,
        TimingProbe,
        detect_nosqli,
    )
    from reachagent.oracles.differential import Observation
    from reachagent.tools.explorer_context import ExplorerContext

    ctx = ExplorerContext(
        graph=graph, firer=firer, library=library or _library(), base_url=base_url
    )
    found: list[str] = []

    def _probe(ep: Endpoint, param: Any) -> None:
        fire = _fire_value_fn(ctx, identity, base_url, ep, param)

        def _obs(value: str, label: str) -> Observation:
            result = fire(value)
            body = result.body.decode("utf-8", errors="replace") if result is not None else ""
            status = result.status_code if result is not None else 0
            return Observation(label=label, status_code=status, body=body)

        def fire_auth_bypass() -> AuthBypassProbe:
            return AuthBypassProbe(
                baseline=_obs("baseline", "benign"),
                probe=_obs(_NOSQL_BYPASS_VALUE, "injected"),
            )

        def fire_timing() -> TimingProbe:
            probe_ms, baseline_ms = _paired_timing(fire, _NOSQL_TIMING_VALUE)
            return TimingProbe(probe_ms, baseline_ms)

        prober = NoSqliProber(
            fire_auth_bypass=fire_auth_bypass, fire_timing=fire_timing, oracle_runner=seam.run
        )
        result = detect_nosqli(prober, evidence_ref=f"orchestrator/nosqli {ep.path} {param.name}")
        if result.confirmed and seam.last is not None:
            mech = result.mechanism.value if result.mechanism is not None else "unknown"
            nid = seam.write("nosqli", seam.last, severity="high", metadata={"mechanism": mech})
            if nid:
                _emit(
                    events,
                    "payloads",
                    "finding",
                    f"nosqli via {mech}",
                    path=ep.path,
                    param=param.name,
                )
                found.append(nid)

    for ep_node, ep in graph.endpoints():
        for _param_node, param in graph.parameters_of(ep_node):
            if _drives_param(param, SinkType.NOSQL):
                _probe(ep, param)
    return found


def run_ldap(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    seam: _ValidatorSeam,
    events: list[ScanEvent],
    library: Any | None = None,
) -> list[str]:
    """LDAP injection via the dedicated detector — wildcard auth-bypass, timing fallback.

    No OOB path: LDAP has no out-of-band channel (§5) — the detector omits it.
    """
    from reachagent.ldap.detector import (
        AuthBypassProbe,
        LdapiProber,
        TimingProbe,
        detect_ldapi,
    )
    from reachagent.oracles.differential import Observation
    from reachagent.tools.explorer_context import ExplorerContext

    ctx = ExplorerContext(
        graph=graph, firer=firer, library=library or _library(), base_url=base_url
    )
    found: list[str] = []

    def _probe(ep: Endpoint, param: Any) -> None:
        fire = _fire_value_fn(ctx, identity, base_url, ep, param)

        def _obs(value: str, label: str) -> Observation:
            result = fire(value)
            body = result.body.decode("utf-8", errors="replace") if result is not None else ""
            status = result.status_code if result is not None else 0
            return Observation(label=label, status_code=status, body=body)

        def fire_auth_bypass() -> AuthBypassProbe:
            return AuthBypassProbe(
                baseline=_obs("baseline", "benign-bind"),
                probe=_obs(_LDAP_BYPASS_VALUE, "wildcard-inject"),
            )

        def fire_timing() -> TimingProbe:
            probe_ms, baseline_ms = _paired_timing(fire, _LDAP_TIMING_VALUE)
            return TimingProbe(probe_ms, baseline_ms)

        prober = LdapiProber(
            fire_auth_bypass=fire_auth_bypass, fire_timing=fire_timing, oracle_runner=seam.run
        )
        result = detect_ldapi(
            prober, evidence_ref=f"orchestrator/ldap_injection {ep.path} {param.name}"
        )
        if result.confirmed and seam.last is not None:
            mech = result.mechanism.value if result.mechanism is not None else "unknown"
            nid = seam.write(
                "ldap_injection", seam.last, severity="high", metadata={"mechanism": mech}
            )
            if nid:
                _emit(
                    events,
                    "payloads",
                    "finding",
                    f"ldap injection via {mech}",
                    path=ep.path,
                    param=param.name,
                )
                found.append(nid)

    for ep_node, ep in graph.endpoints():
        for _param_node, param in graph.parameters_of(ep_node):
            if _drives_param(param, SinkType.LDAP):
                _probe(ep, param)
    return found


def run_command_injection(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    seam: _ValidatorSeam,
    events: list[ScanEvent],
    library: Any | None = None,
) -> list[str]:
    """Blind command injection via time-delay (the shared blind prober, timing path).

    OOB (DNS/HTTP callback) is the higher-confidence path but requires a live
    collaborator; the honest default without one is the statistical timing oracle,
    exactly as blind SQLi falls back.
    """
    from reachagent.sqli.blind_detector import BlindSqliProber, TimingProbe, detect_blind_sqli
    from reachagent.tools.explorer_context import ExplorerContext

    ctx = ExplorerContext(
        graph=graph, firer=firer, library=library or _library(), base_url=base_url
    )
    found: list[str] = []

    def _probe(ep: Endpoint, param: Any) -> None:
        fire = _fire_value_fn(ctx, identity, base_url, ep, param)

        def fire_timing() -> TimingProbe:
            probe_ms, baseline_ms = _paired_timing(fire, _CMD_TIMING_VALUE)
            return TimingProbe(probe_ms, baseline_ms)

        prober = BlindSqliProber(
            fire_oob=lambda: None,
            observed_nonces=frozenset,
            fire_timing=fire_timing,
            oracle_runner=seam.run,
        )
        result = detect_blind_sqli(
            prober,
            evidence_ref=f"orchestrator/command_injection {ep.path} {param.name}",
            try_boolean=False,
        )
        if result.confirmed and seam.last is not None:
            mech = result.mechanism.value if result.mechanism is not None else "timing_statistical"
            nid = seam.write(
                "command_injection", seam.last, severity="high", metadata={"mechanism": mech}
            )
            if nid:
                _emit(
                    events,
                    "payloads",
                    "finding",
                    f"command injection via {mech}",
                    path=ep.path,
                    param=param.name,
                )
                found.append(nid)

    for ep_node, ep in graph.endpoints():
        for _param_node, param in graph.parameters_of(ep_node):
            if _drives_param(param, SinkType.SHELL):
                _probe(ep, param)
    return found


# ---------------------------------------------------------------------------
# Phase 3 — mass assignment: write a privileged field, independently reread
# ---------------------------------------------------------------------------

_MASS_ASSIGN_PRIV_FIELDS: tuple[str, ...] = ("admin", "isAdmin", "is_admin")
_PLACEHOLDER = re.compile(r"\{[^}]+\}")


def _synth_body_value(param: Any) -> object:
    """A per-run-unique benign value for a legitimate body field.

    # ponytail: name-heuristic, not a schema-aware synthesizer — upgrade if a
    # target needs typed/enum body fields (e.g. a required boolean/int).
    """
    if param.example:
        return param.example
    name = param.name.lower()
    if any(tok in name for tok in ("id", "count", "amount", "price", "qty")):
        return 1
    if "email" in name or "mail" in name:
        return f"ra-{uuid.uuid4().hex[:6]}@reachagent.test"
    return f"ra-{uuid.uuid4().hex[:8]}"


def _sibling_read_endpoint(
    graph: ReachabilityGraph, write_path: str
) -> tuple[str, Endpoint] | None:
    """The read-back endpoint for a write path: same-path GET, else a sibling
    prefix GET with an unresolved ``{placeholder}`` (registration-style create).
    """
    for node, ep in graph.endpoints():
        if ep.method.upper() == "GET" and ep.path == write_path:
            return node, ep
    prefix = write_path.rsplit("/", 1)[0] + "/"
    for node, ep in graph.endpoints():
        if (
            ep.method.upper() == "GET"
            and ep.path.startswith(prefix)
            and _PLACEHOLDER.search(ep.path)
        ):
            return node, ep
    return None


def run_mass_assignment(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    auth_headers: Mapping[str, str],
    seam: _ValidatorSeam,
    events: list[ScanEvent],
) -> list[str]:
    """Inject a privileged field alongside a legitimate write; confirm via
    an INDEPENDENT re-read of the resource, never the write's own response.

    Read-only-first: an OPTIONS-or-GET preflight must clear the write
    endpoint's path before the state-changing fire (mirrors ``run_file_upload``
    exactly). Stops at the first field that confirms per endpoint.
    """
    import json as _json

    from reachagent.mass_assignment.detector import (
        MassAssignmentProbe,
        MassAssignmentProber,
        detect_mass_assignment,
    )
    from reachagent.oracles.differential import Observation
    from reachagent.payloads.payload_resolver import resolve

    found: list[str] = []
    for ep_node, ep in graph.endpoints():
        if ep.method.upper() not in ("POST", "PUT", "PATCH"):
            continue
        body_params = [(n, p) for n, p in graph.parameters_of(ep_node) if p.location == "json"]
        if not body_params:
            continue
        label = f"mass_assignment {ep.path}"
        sibling = _sibling_read_endpoint(graph, ep.path)
        if sibling is None:
            _emit(
                events,
                "payloads",
                "not-applicable",
                f"{label}: no independent read-back endpoint discovered",
            )
            continue
        _sibling_node, sibling_ep = sibling
        write_url = f"{base_url.rstrip('/')}{ep.path}"
        preflight = _fire_readonly(
            firer,
            identity,
            "OPTIONS",
            write_url,
            events=events,
            label=f"{label}/preflight",
            headers=auth_headers,
        )
        if preflight is None or not (200 <= preflight.status_code < 300):
            preflight = _fire_readonly(
                firer,
                identity,
                "GET",
                write_url,
                events=events,
                label=f"{label}/preflight-get",
                headers=auth_headers,
            )
        if preflight is None or not (200 <= preflight.status_code < 300):
            _emit(events, "payloads", "not-applicable", f"{label}: no read-only clearance")
            continue
        legit_body = {p.name: _synth_body_value(p) for _n, p in body_params}
        confirmed_this_endpoint = False
        for priv_field_name in _MASS_ASSIGN_PRIV_FIELDS:
            if confirmed_this_endpoint:
                break
            injected = _json.loads(
                resolve("mass-assignment/admin-flag-injection", priv_field=priv_field_name)
            )
            write_body = {**legit_body, **injected}
            try:
                write_result = firer.fire(
                    identity,
                    ep.method,
                    write_url,
                    state_changing=True,
                    headers=dict(auth_headers),
                    json=write_body,
                )
            except Exception:  # noqa: BLE001, S112 — a refused write is a dead lead
                continue
            if not (200 <= write_result.status_code < 300):
                continue
            read_id = (
                write_body.get("username") or write_body.get("email") or write_body.get("id", "")
            )
            read_path = (
                _PLACEHOLDER.sub(str(read_id), sibling_ep.path)
                if _PLACEHOLDER.search(sibling_ep.path)
                else sibling_ep.path
            )
            read_url = f"{base_url.rstrip('/')}{read_path}"
            try:
                reread = firer.fire(
                    identity, "GET", read_url, state_changing=False, headers=dict(auth_headers)
                )
            except Exception:  # noqa: BLE001, S112 — a failed reread is a dead lead
                continue
            extracted = ""
            try:
                parsed = _json.loads(reread.body.decode("utf-8", errors="replace"))
                if isinstance(parsed, dict) and priv_field_name in parsed:
                    extracted = str(parsed[priv_field_name]).lower()
            except Exception:  # noqa: BLE001, S110 — non-JSON reread body: no signal
                pass

            def _fire_probe(
                status: int = reread.status_code,
                value: str = extracted,
                priv_field_name: str = priv_field_name,
            ) -> MassAssignmentProbe:
                return MassAssignmentProbe(
                    reference=Observation("expected-privileged-value", 200, "true"),
                    reread=Observation(f"reread-after-mutation:{priv_field_name}", status, value),
                )

            prober = MassAssignmentProber(fire_probe=_fire_probe, oracle_runner=seam.run)
            result = detect_mass_assignment(
                prober, evidence_ref=f"orchestrator/mass_assignment{ep.path}:{priv_field_name}"
            )
            if result.confirmed and seam.last is not None:
                nid = seam.write(
                    "mass_assignment",
                    seam.last,
                    severity="high",
                    metadata={"field": priv_field_name, "endpoint": ep.path},
                )
                if nid:
                    found.append(nid)
                    confirmed_this_endpoint = True
                    _emit(
                        events,
                        "payloads",
                        "finding",
                        f"mass assignment — {priv_field_name} persisted after write",
                        path=ep.path,
                        priv_field_name=priv_field_name,
                    )
    return found


def run_xss_stored(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    auth_headers: Mapping[str, str],
    seam: _ValidatorSeam,
    events: list[ScanEvent],
) -> list[str]:
    """Inject a tagged script payload into one write field; confirm via an
    INDEPENDENT re-read of the resource reflecting the tag verbatim.

    Read-only-first: mirrors ``run_mass_assignment`` exactly — an OPTIONS-or-GET
    preflight must clear the write endpoint before the state-changing fire.
    Reuses ``xss/detector.py``'s stored path (no new oracle wiring): ``fire_dom``
    is a no-op (no browser in this context, and DOM XSS is separately driven by
    ``run_xss_dom``), so ``detect_xss`` falls through to the stored write→reread
    confirmation on the first call.
    """
    from reachagent.browser.shim import BrowserFireResult
    from reachagent.payloads.payload_resolver import resolve
    from reachagent.xss.detector import DomProbe, StoredProbe, XssProber, detect_xss

    found: list[str] = []
    for ep_node, ep in graph.endpoints():
        if ep.method.upper() not in ("POST", "PUT", "PATCH"):
            continue
        body_params = [(n, p) for n, p in graph.parameters_of(ep_node) if p.location == "json"]
        if not body_params:
            continue
        label = f"xss_stored {ep.path}"
        sibling = _sibling_read_endpoint(graph, ep.path)
        if sibling is None:
            _emit(
                events,
                "payloads",
                "not-applicable",
                f"{label}: no independent read-back endpoint discovered",
            )
            continue
        _sibling_node, sibling_ep = sibling
        write_url = f"{base_url.rstrip('/')}{ep.path}"
        preflight = _fire_readonly(
            firer,
            identity,
            "OPTIONS",
            write_url,
            events=events,
            label=f"{label}/preflight",
            headers=auth_headers,
        )
        if preflight is None or not (200 <= preflight.status_code < 300):
            preflight = _fire_readonly(
                firer,
                identity,
                "GET",
                write_url,
                events=events,
                label=f"{label}/preflight-get",
                headers=auth_headers,
            )
        if preflight is None or not (200 <= preflight.status_code < 300):
            _emit(events, "payloads", "not-applicable", f"{label}: no read-only clearance")
            continue

        legit_body = {p.name: _synth_body_value(p) for _n, p in body_params}
        tag = f"ra{uuid.uuid4().hex[:10]}"
        # Never inject into the field the reread URL is resolved from below
        # (username/email/id) — corrupting it would break our own lookup.
        target_field = next(
            (p.name for _n, p in body_params if p.name not in ("username", "email", "id")),
            body_params[0][1].name,
        )
        payload = resolve("xss/reflected/script-tag-canary", canary=tag)
        write_body = {**legit_body, target_field: payload}
        try:
            write_result = firer.fire(
                identity,
                ep.method,
                write_url,
                state_changing=True,
                headers=dict(auth_headers),
                json=write_body,
            )
        except Exception:  # noqa: BLE001, S112 — a refused write is a dead lead
            continue
        if not (200 <= write_result.status_code < 300):
            continue

        read_id = write_body.get("username") or write_body.get("email") or write_body.get("id", "")
        read_path = (
            _PLACEHOLDER.sub(str(read_id), sibling_ep.path)
            if _PLACEHOLDER.search(sibling_ep.path)
            else sibling_ep.path
        )
        read_url = f"{base_url.rstrip('/')}{read_path}"
        try:
            reread = firer.fire(
                identity, "GET", read_url, state_changing=False, headers=dict(auth_headers)
            )
        except Exception:  # noqa: BLE001, S112 — a failed reread is a dead lead
            continue
        readback_body = reread.body.decode("utf-8", errors="replace")

        def _fire_dom(_url: str = write_url, _identity: str = identity) -> DomProbe:
            return DomProbe(result=BrowserFireResult(url=_url, identity=_identity))

        def _fire_stored(_tag: str = tag, _body: str = readback_body) -> StoredProbe:
            return StoredProbe(payload_tag=_tag, readback_body=_body, write_logged=True)

        prober = XssProber(fire_dom=_fire_dom, fire_stored=_fire_stored, oracle_runner=seam.run)
        result = detect_xss(prober, evidence_ref=f"orchestrator/xss_stored{ep.path}")
        if result.confirmed and seam.last is not None:
            nid = seam.write(
                "xss_stored", seam.last, severity="high", metadata={"endpoint": ep.path}
            )
            if nid:
                found.append(nid)
                _emit(
                    events,
                    "payloads",
                    "finding",
                    f"stored xss — tag reflected in independent reread of {ep.path}",
                    path=ep.path,
                )

    if not found:
        _emit(events, "payloads", "not-applicable", "xss_stored: no stored injection confirmed")
    return found


_REDIRECT_PARAM_NAMES = frozenset(
    {
        "redirect",
        "redirecturl",
        "redirect_uri",
        "redirecturi",
        "next",
        "return",
        "returnurl",
        "return_to",
        "returnto",
        "url",
        "target",
        "dest",
        "destination",
        "continue",
        "callback",
        "callbackurl",
        "redir",
        "out",
        "view",
        "to",
    }
)


def run_open_redirect(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    auth_headers: Mapping[str, str],
    seam: _ValidatorSeam,
    events: list[ScanEvent],
) -> list[str]:
    """Inject an attacker URL into a redirect-shaped query parameter; confirm
    via the ``Location`` header of a 3xx response echoing it verbatim.

    Read-only GET (§10): the firer never follows redirects (hardcoded in
    ``RequestFirer.fire``), so the attacker destination is never visited.
    Reuses ``openredirect/detector.py`` (no inline oracle wiring).
    """
    from reachagent.openredirect.detector import (
        OpenRedirectProber,
        RedirectProbe,
        detect_open_redirect,
    )

    target = f"{_ATTACKER_ORIGIN}/reachagent-open-redirect-probe"
    found: list[str] = []
    for ep_node, ep in graph.endpoints():
        if ep.method.upper() != "GET":
            continue
        redirect_params = [
            p
            for _n, p in graph.parameters_of(ep_node)
            if p.location == "query" and p.name.lower() in _REDIRECT_PARAM_NAMES
        ]
        if not redirect_params:
            continue
        param_name = redirect_params[0].name
        label = f"open_redirect {ep.path}?{param_name}"
        probe_url = f"{base_url.rstrip('/')}{ep.path}?{param_name}={target}"

        def _fire_probe(_url: str = probe_url, _label: str = label) -> RedirectProbe:
            response = _fire_readonly(
                firer, identity, "GET", _url, events=events, label=_label, headers=auth_headers
            )
            if response is None:
                return RedirectProbe()
            return RedirectProbe(
                status=response.status_code,
                location=str(response.headers.get("location", "")),
            )

        prober = OpenRedirectProber(
            fire_probe=_fire_probe, probe_target=target, oracle_runner=seam.run
        )
        result = detect_open_redirect(prober, evidence_ref=f"orchestrator/open_redirect{ep.path}")
        if result.confirmed and seam.last is not None:
            nid = seam.write(
                "open_redirect", seam.last, severity="medium", metadata={"param": param_name}
            )
            if nid:
                found.append(nid)
                _emit(
                    events,
                    "payloads",
                    "finding",
                    f"open redirect — {param_name} echoed into Location",
                    path=ep.path,
                )

    if not found:
        _emit(events, "payloads", "not-applicable", "open_redirect: no redirect param confirmed")
    return found


# ---------------------------------------------------------------------------
# Web cache poisoning — unkeyed-header reflection replayed from a shared cache
# ---------------------------------------------------------------------------

_UNKEYED_HEADER = "X-Forwarded-Host"


def run_cache_poisoning(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    auth_headers: Mapping[str, str],
    seam: _ValidatorSeam,
    events: list[ScanEvent],
) -> list[str]:
    """Inject a run-unique marker into an unkeyed header; confirm via replay
    into an independent, header-free re-read of the same cache-busted URL.

    Read-only GETs (§10). Every candidate URL carries its own run-unique
    cache-buster query param, so a poisoned entry only ever exists at a URL
    this run itself minted — no other visitor can ever request it. Reuses
    ``cachepoisoning/detector.py`` (no inline oracle wiring).
    """
    from reachagent.cachepoisoning.detector import (
        CachePoisoningProbe,
        CachePoisoningProber,
        detect_cache_poisoning,
    )

    targets: list[str] = []
    for _, ep in graph.endpoints():
        if ep.method == "GET" and ep.path not in targets:
            targets.append(ep.path)
    targets = (["/"] + targets)[:5]
    found: list[str] = []

    for path in targets:
        cache_buster = uuid.uuid4().hex[:12]
        marker = f"reachagent-cache-poison-{uuid.uuid4().hex[:12]}"
        url = f"{base_url.rstrip('/')}{path}?_rachk={cache_buster}"
        label = f"cache_poisoning {path}"

        def _fire_probe(
            _url: str = url, _label: str = label, _marker: str = marker
        ) -> CachePoisoningProbe:
            poison_headers = dict(auth_headers)
            poison_headers[_UNKEYED_HEADER] = _marker
            poisoned = _fire_readonly(
                firer, identity, "GET", _url, events=events, label=_label, headers=poison_headers
            )
            if poisoned is None:
                return CachePoisoningProbe()
            reread = _fire_readonly(
                firer,
                identity,
                "GET",
                _url,
                events=events,
                label=f"{_label}/reread",
                headers=auth_headers,
            )
            return CachePoisoningProbe(
                poisoned_status=poisoned.status_code,
                poisoned_body=poisoned.body.decode("utf-8", errors="replace"),
                reread_body=reread.body.decode("utf-8", errors="replace") if reread else "",
            )

        prober = CachePoisoningProber(fire_probe=_fire_probe, marker=marker, oracle_runner=seam.run)
        result = detect_cache_poisoning(prober, evidence_ref=f"orchestrator/cache_poisoning{path}")
        if result.confirmed and seam.last is not None:
            nid = seam.write("web_cache_poisoning", seam.last, severity="medium")
            if nid:
                found.append(nid)
                _emit(
                    events,
                    "payloads",
                    "finding",
                    f"web cache poisoning — {_UNKEYED_HEADER} replayed from cache",
                    path=path,
                )

    if not found:
        _emit(
            events, "payloads", "not-applicable", "cache_poisoning: no marker replayed from cache"
        )
    return found


# ---------------------------------------------------------------------------
# Request smuggling — CL.TE desync via a raw-socket timing probe
# ---------------------------------------------------------------------------


def run_request_smuggling(
    *,
    base_url: str,
    seam: _ValidatorSeam,
    events: list[ScanEvent],
) -> list[str]:
    """Fire the CL.TE raw-socket timing probe once per scan (§7, §10).

    A transport-level property of the host:port, not any one endpoint — unlike
    the other structural checks this runs once against the target root, not
    per discovered path. Reuses the existing TIMING_STATISTICAL oracle
    unchanged (same ≥10-trial paired-trial rigor as blind SQLi/NoSQLi/LDAP);
    reuses ``smuggling/detector.py`` (no inline oracle wiring). The raw-socket
    transport lives entirely in ``smuggling/raw_probe.py`` — this function
    never touches a socket directly.
    """
    from reachagent.smuggling.detector import (
        SmugglingProber,
        SmugglingTimingProbe,
        detect_request_smuggling,
    )
    from reachagent.smuggling.raw_probe import RawProbeTarget, fire_timing_trials

    target = RawProbeTarget.from_base_url(base_url)
    found: list[str] = []
    if not target.host:
        _emit(events, "payloads", "not-applicable", "request_smuggling: no resolvable host")
        return found

    def _fire_timing() -> SmugglingTimingProbe:
        probe_ms, baseline_ms = fire_timing_trials(target)
        return SmugglingTimingProbe(probe_latencies_ms=probe_ms, baseline_latencies_ms=baseline_ms)

    prober = SmugglingProber(fire_timing=_fire_timing, oracle_runner=seam.run)
    result = detect_request_smuggling(
        prober, evidence_ref=f"orchestrator/request_smuggling/{target.host}:{target.port}"
    )
    if result.confirmed and seam.last is not None:
        nid = seam.write("request_smuggling", seam.last, severity="high")
        if nid:
            found.append(nid)
            _emit(
                events,
                "payloads",
                "finding",
                "request smuggling — CL.TE desync confirmed via timing",
                path="/",
            )
    else:
        _emit(events, "payloads", "not-applicable", "request_smuggling: no CL.TE timing signal")
    return found


# ---------------------------------------------------------------------------
# Subdomain takeover — dangling-CNAME fingerprint match
# ---------------------------------------------------------------------------


def run_subdomain_takeover(
    *,
    graph: ReachabilityGraph,
    seam: _ValidatorSeam,
    events: list[ScanEvent],
    transport: httpx.BaseTransport | None = None,
) -> list[str]:
    """Probe dangling CNAME targets for a known "unclaimed service" marker (§7, §10).

    A subdomain's CNAME pointing at a known cloud-service pattern (S3, GitHub
    Pages, Heroku, ...) is checked with exactly one read-only GET to that CNAME
    target — a third-party domain the target's OWN DNS configuration points
    at, never the target itself and never attacker-controlled. That target
    falls outside the scanned host's own ScopeGuard by construction (the whole
    point of this class is a name pointing OFF the target's domain), so this
    deliberately does not go through RequestFirer — the same reasoning that
    gives ``smuggling/raw_probe.py`` its own dedicated transport outside the
    firer. Never state-changing (GET only); every probe URL and outcome is
    narrated into the live event feed since it bypasses the firer's own audit.
    """
    from reachagent.subdomain_takeover.detector import (
        SubdomainTakeoverProbe,
        SubdomainTakeoverProber,
        detect_subdomain_takeover,
        match_fingerprint,
    )

    found: list[str] = []
    checked = 0
    for _node, host in graph.hosts():
        if not host.cname:
            continue
        sentinel = match_fingerprint(host.cname)
        if sentinel is None:
            continue
        checked += 1
        cname = host.cname
        url = f"https://{cname}/"
        _emit(
            events,
            "payloads",
            "step",
            f"subdomain_takeover: probing CNAME target {cname}",
            path=host.hostname or host.address,
        )

        def _fire_probe(_url: str = url) -> SubdomainTakeoverProbe:
            try:
                with httpx.Client(
                    transport=transport, timeout=10.0, follow_redirects=True
                ) as client:
                    response = client.get(_url)
                return SubdomainTakeoverProbe(status=response.status_code, body=response.text)
            except httpx.HTTPError:
                return SubdomainTakeoverProbe(status=0, body="")

        prober = SubdomainTakeoverProber(fire_probe=_fire_probe, oracle_runner=seam.run)
        result = detect_subdomain_takeover(
            prober, sentinel=sentinel, evidence_ref=f"orchestrator/subdomain_takeover/{cname}"
        )
        if result.confirmed and seam.last is not None:
            nid = seam.write("subdomain_takeover", seam.last, severity="high")
            if nid:
                found.append(nid)
                _emit(
                    events,
                    "payloads",
                    "finding",
                    f"subdomain takeover — {cname} reports itself unclaimed",
                    path=host.hostname or host.address,
                )

    if checked == 0:
        _emit(
            events,
            "payloads",
            "not-applicable",
            "subdomain_takeover: no CNAME matched a known unclaimed-service pattern",
        )
    return found


def run_default_credentials(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    seam: _ValidatorSeam,
    events: list[ScanEvent],
) -> list[str]:
    """Try well-known default credentials against a discovered login form (§7, Build Order 0).

    Reuses the exact login-submission mechanism already used for a real
    operator-supplied identity (``identity.login.submit_login``) — a login
    attempt is a normal authentication action, not a new capability. The
    credential pairs themselves are a closed, fixed allowlist; the LLM may
    only reorder/subset that allowlist from target-tech context, never
    invent a pair (`default_creds.propose_credential_order`).
    """
    from reachagent.default_creds.detector import (
        detect_default_credentials,
        propose_credential_order,
    )
    from reachagent.identity.login import CapturedSession, detect_login_forms, submit_login
    from reachagent.recon.live_tuning import _graph_tech_signal

    found: list[str] = []
    try:
        forms = detect_login_forms(firer, base_url, identity, graph)
    except Exception as exc:  # noqa: BLE001 — discovery failure is not a violation
        _emit(events, "payloads", "error", f"default_credentials: login discovery failed ({exc})")
        return found
    if not forms:
        _emit(events, "payloads", "not-applicable", "default_credentials: no login form found")
        return found

    tech_signal = _graph_tech_signal(base_url, graph)
    signals = {"target": base_url}
    if tech_signal is not None:
        signals["detected_technology"] = tech_signal[0]
    order = propose_credential_order(signals)

    for form in forms[:3]:  # bounded: at most 3 discovered forms tried
        _emit(
            events,
            "payloads",
            "step",
            f"default_credentials: trying {len(order)} known pairs against {form.url}",
        )

        def _attempt(username: str, password: str, _form: object = form) -> CapturedSession:
            return submit_login(firer, identity, _form, username, password)  # type: ignore[arg-type]

        result = detect_default_credentials(
            form,
            attempt_login=_attempt,
            order=order,
            oracle_runner=seam.run,
            evidence_ref=f"orchestrator/default_credentials/{form.url}",
        )
        if result.confirmed and seam.last is not None:
            nid = seam.write("default_credentials", seam.last, severity="high")
            if nid:
                found.append(nid)
                _emit(
                    events,
                    "payloads",
                    "finding",
                    f"default credentials — {result.username}:*** works at {form.url}",
                )
                break  # one confirmed default-credential login is enough
    return found


# A deliberately-wrong pair — never a real credential, never mutating state,
# used only to observe whether repeated failed attempts ever change behavior.
_RATE_LIMIT_PROBE_CREDENTIAL = ("ra-probe-user", "ra-probe-wrong-password")


def run_rate_limit_absence(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    seam: _ValidatorSeam,
    events: list[ScanEvent],
) -> list[str]:
    """Bounded burst of wrong-credential login attempts (§7, Build Order 0).

    Fires a small, fixed number of attempts (never a real brute force — see
    ``rate_limit.detector._BURST_SIZE``) and checks whether any of them ever
    triggered a defensive signal. Every attempt uses the same deliberately-
    wrong, never-real credential pair — the point is observing whether
    *behavior* changes across repeats, not guessing a real password.
    """
    from reachagent.identity.login import detect_login_forms
    from reachagent.rate_limit.detector import (
        RateLimitProbe,
        RateLimitProber,
        detect_rate_limit_absence,
    )

    found: list[str] = []
    try:
        forms = detect_login_forms(firer, base_url, identity, graph)
    except Exception as exc:  # noqa: BLE001 — discovery failure is not a violation
        _emit(events, "payloads", "error", f"rate_limit_absence: login discovery failed ({exc})")
        return found
    if not forms:
        _emit(events, "payloads", "not-applicable", "rate_limit_absence: no login form found")
        return found

    form = forms[0]
    if form.kind != "html_form":
        # Scoped ceiling: only the common HTML-form login shape is probed
        # here (graphql/generic-JSON login forms are a different firing
        # shape this driver doesn't build) — not applicable, not a miss.
        _emit(
            events,
            "payloads",
            "not-applicable",
            f"rate_limit_absence: login form kind {form.kind!r} not supported",
        )
        return found
    username, password = _RATE_LIMIT_PROBE_CREDENTIAL
    _emit(events, "payloads", "step", f"rate_limit_absence: bounded burst against {form.url}")

    def _fire_attempt(_index: int) -> RateLimitProbe:
        data = dict(form.extra_fields)
        if form.username_field:
            data[form.username_field] = username
        data[form.password_field] = password
        result = firer.fire(
            identity,
            form.method,
            form.url,
            state_changing=True,
            authentication=True,
            data=data,
            headers={"Content-Type": form.enctype},
        )
        return RateLimitProbe(
            status=result.status_code, body=result.body.decode("utf-8", errors="replace")
        )

    prober = RateLimitProber(fire_attempt=_fire_attempt, oracle_runner=seam.run)
    result = detect_rate_limit_absence(
        prober, evidence_ref=f"orchestrator/rate_limit_absence/{form.url}"
    )
    if result.confirmed and seam.last is not None:
        nid = seam.write("rate_limit_absence", seam.last, severity="medium")
        if nid:
            found.append(nid)
            _emit(
                events,
                "payloads",
                "finding",
                f"no login rate limiting observed after {result.attempts_completed} attempts "
                f"at {form.url}",
            )
    return found


# ---------------------------------------------------------------------------
# Phase 3 — authz (bola/bfla) via the generic BOLA detector
# ---------------------------------------------------------------------------


def run_authz_bola(
    *,
    graph: ReachabilityGraph,
    base_url: str,
    identities: IdentityStore,
    events: list[ScanEvent],
    transport: httpx.BaseTransport | None = None,
) -> list[str]:
    """Cross-identity BOLA via ``bola.detector.detect`` — generic over graph owns edges.

    Needs ≥2 identities with sessions and an ``owns``-anchored object (recon/surface
    populated). Otherwise reported not-applicable — a cross-identity diff needs a real
    owner and a real non-owner.
    """
    from reachagent.bola import detector as bola_detector

    names = identities.names()
    if len(names) < 2:
        _emit(events, "payloads", "not-applicable", "bola/bfla: need ≥2 identities")
        return []
    owners = {src for src, _ in graph.owns_edges()}
    owner_tokens: dict[str, str] = {}
    non_owner_tokens: dict[str, str] = {}
    owner_headers: dict[str, Mapping[str, str]] = {}
    non_owner_headers: dict[str, Mapping[str, str]] = {}
    for name in names:
        headers = identities.auth_headers(name)
        if not headers:
            continue
        id_ = identity_id(name)
        if id_ in owners:
            owner_headers[id_] = headers
            token = identities.token_store(name).get_token()
            if token:
                owner_tokens[id_] = token
        else:
            non_owner_headers[id_] = headers
            token = identities.token_store(name).get_token()
            if token:
                non_owner_tokens[id_] = token
    if not owner_headers or not non_owner_headers:
        _emit(events, "payloads", "not-applicable", "bola/bfla: no owner+non-owner token pair")
        return []
    result = bola_detector.detect(
        graph,
        base_url,
        owner_tokens=owner_tokens,
        non_owner_tokens=non_owner_tokens,
        owner_headers=owner_headers,
        non_owner_headers=non_owner_headers,
        transport=transport,
    )
    for hop in result.confirmed_hops:
        _emit(
            events,
            "payloads",
            "finding",
            f"bola/bfla: cross-identity read of {hop.path}",
            finding=hop.finding_node,
        )
    return [hop.finding_node for hop in result.confirmed_hops]


def run_authz_idor(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identities: IdentityStore,
    seam: _ValidatorSeam,
    events: list[ScanEvent],
    allow_cross_user_writes: bool = False,
) -> list[str]:
    """Cross-identity IDOR via a genuine state-changing write (§7 differential).

    Sibling to ``run_authz_bola``, not a replacement — that driver is
    read-only-first (GET only) and its ``vuln_class="bola"`` findings/
    enumerable-disclosed preconditions are untouched here. This confirms the
    one case a read can't: a PUT/PATCH against ANOTHER identity's live object
    actually succeeds when it should be refused.

    Opt-in only (``allow_cross_user_writes`` defaults False): the non-owner's
    probe write is the single most invasive action this project ever takes —
    it mutates a real identity's real data on the live target. DELETE is
    deliberately excluded even when enabled — irreversible destruction is a
    materially larger blast radius than an overwrite, beyond what this opt-in
    was scoped for.

    Candidate discovery is deliberately narrower than BOLA's three strategies:
    only an owned object with a known ``instance_key`` substituted into a
    ``{placeholder}`` of a write-method endpoint path — the one unambiguous
    case where "this write targets exactly this owner's object" is a graph
    fact, not a guess. The owner's own write must succeed first (proves the
    endpoint is a genuinely live write for this object) before the
    non-owner's probe — the intentionally risky step — ever fires.
    """
    if not allow_cross_user_writes:
        _emit(
            events,
            "payloads",
            "not-applicable",
            "idor: cross-user write probing disabled (allow_cross_user_writes=False)",
        )
        return []

    names = identities.names()
    auth_ok = {identity_id(n) for n in names if identities.auth_headers(n)}
    if len(auth_ok) < 2:
        _emit(events, "payloads", "not-applicable", "idor: need ≥2 identities with sessions")
        return []

    from reachagent.bola.idor_detector import IdorProbe, IdorProber, detect_idor

    found: list[str] = []
    seen: set[tuple[str, str]] = set()
    for obj_node, obj in graph.objects():
        if obj.sensitivity_tier < 2 or not obj.instance_key:
            continue
        owner = graph.owner_of(obj_node)
        if owner is None or owner not in auth_ok:
            continue
        non_owner = next((nid for nid in auth_ok if nid != owner), None)
        if non_owner is None:
            continue
        for ep_node, ep in graph.endpoints():
            if ep.method.upper() not in ("PUT", "PATCH"):
                continue
            if not _PLACEHOLDER.search(ep.path):
                continue
            concrete_path = _PLACEHOLDER.sub(obj.instance_key, ep.path)
            key = (ep.method, concrete_path)
            if key in seen:
                continue
            seen.add(key)

            label = f"idor {ep.method} {concrete_path}"
            url = f"{base_url.rstrip('/')}{concrete_path}"

            def _clear(identity: str, sub_label: str, _url: str = url) -> Any | None:
                ready = _fire_readonly(
                    firer, identity, "OPTIONS", _url, events=events, label=f"{sub_label}/preflight"
                )
                if ready is None or not (200 <= ready.status_code < 300):
                    ready = _fire_readonly(
                        firer,
                        identity,
                        "GET",
                        _url,
                        events=events,
                        label=f"{sub_label}/preflight-get",
                    )
                return ready

            owner_ready = _clear(owner, f"{label}/owner")
            non_owner_ready = _clear(non_owner, f"{label}/non-owner")
            if (
                owner_ready is None
                or not (200 <= owner_ready.status_code < 300)
                or non_owner_ready is None
                or not (200 <= non_owner_ready.status_code < 300)
            ):
                _emit(events, "payloads", "not-applicable", f"{label}: no read-only clearance")
                continue

            body_params = [(n, p) for n, p in graph.parameters_of(ep_node) if p.location == "json"]
            write_body = {p.name: _synth_body_value(p) for _n, p in body_params} or None
            fire_kwargs: dict[str, object] = {"state_changing": True}
            if write_body is not None:
                fire_kwargs["json"] = write_body

            try:
                owner_result = firer.fire(owner, ep.method, url, **fire_kwargs)
            except Exception as exc:  # noqa: BLE001, S112 — a refused write is a dead lead
                _emit(
                    events,
                    "payloads",
                    "error",
                    f"{label}: owner write refused ({type(exc).__name__})",
                )
                continue
            if not (200 <= owner_result.status_code < 300):
                _emit(
                    events,
                    "payloads",
                    "not-applicable",
                    f"{label}: owner's own write did not succeed — not a live write endpoint",
                )
                continue

            try:
                probe_result = firer.fire(non_owner, ep.method, url, **fire_kwargs)
            except Exception as exc:  # noqa: BLE001, S112 — a refused probe is not a violation
                _emit(
                    events,
                    "payloads",
                    "error",
                    f"{label}: non-owner probe refused ({type(exc).__name__})",
                )
                continue

            def _fire_probe(status: int = probe_result.status_code) -> IdorProbe:
                return IdorProbe(non_owner_status=status)

            prober = IdorProber(fire_probe=_fire_probe, oracle_runner=seam.run)
            result = detect_idor(prober, evidence_ref=f"orchestrator/{label}")
            if result.confirmed and seam.last is not None:
                nid = seam.write(
                    "idor", seam.last, severity="critical", metadata={"path": concrete_path}
                )
                if nid:
                    found.append(nid)
                    _emit(
                        events,
                        "payloads",
                        "finding",
                        f"idor — cross-user write succeeded at {concrete_path}",
                        path=concrete_path,
                    )

    if not found:
        _emit(events, "payloads", "not-applicable", "idor: no cross-user write confirmed")
    return found


# ---------------------------------------------------------------------------
# Phase 3 — graphql (when a /graphql endpoint exists)
# ---------------------------------------------------------------------------


def run_graphql(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    seam: _ValidatorSeam,
    events: list[ScanEvent],
    identities: IdentityStore | None = None,
) -> list[str]:
    """GraphQL resolver-BOLA when introspection discovered the schema.

    Resolver-BOLA is a cross-identity diff, so it needs an owner and a non-owner
    identity (the same identity re-read twice would not prove anything). Without two
    token-bearing identities the resolver checks are reported not-applicable; the
    schema discovery itself still materializes Endpoint facts.
    """
    from reachagent.graphql.module import (
        GraphQLClient,
        discover_schema,
        resolver_bola_check,
    )

    gql_endpoint = next(
        (
            nid
            for nid, ep in graph.endpoints()
            if ep.protocol.value == "graphql" or ep.path == "/graphql"
        ),
        None,
    )
    if gql_endpoint is None:
        _emit(events, "payloads", "not-applicable", "graphql: no /graphql endpoint discovered")
        return []
    client = GraphQLClient(firer, base_url=base_url.rstrip("/"), endpoint_path="/graphql")
    schema = discover_schema(client, identity)
    if schema is None:
        _emit(events, "payloads", "not-applicable", "graphql: introspection disabled/refused")
        return []

    authenticated: list[str] = []
    if identities is not None:
        authenticated = [name for name in identities.names() if identities.auth_headers(name)]
    if len(authenticated) < 2:
        _emit(events, "payloads", "not-applicable", "graphql: resolver-BOLA needs ≥2 identities")
        return []
    owner_id, non_owner_id = authenticated[:2]
    found: list[str] = []
    for gql_field in schema.fields[:10]:
        if gql_field.public is not None:
            baseline = client.query(owner_id, _field_query(gql_field.name))
            probe = client.query(non_owner_id, _field_query(gql_field.name))
            outcome = resolver_bola_check(
                baseline, probe, public=bool(gql_field.public), oracle_runner=seam.run
            )
            if outcome.is_violation:
                verdict = seam.last
                if verdict is not None:
                    nid = seam.write("graphql", seam.last, severity="high")
                    if nid:
                        found.append(nid)
                        _emit(
                            events,
                            "payloads",
                            "finding",
                            f"graphql resolver bola on {gql_field.name}",
                        )
    return found


def _field_query(name: str) -> str:
    return f"{{ {name} }}" if name and not name.startswith("{") else name


def _library() -> Any:
    from reachagent.payloads import build_library

    return build_library()


# ---------------------------------------------------------------------------
# Phase 3 — business_logic (4-template invariant library, fully generic)
# ---------------------------------------------------------------------------


def run_business_logic(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    seam: _ValidatorSeam,
    events: list[ScanEvent],
) -> list[str]:
    """Business-logic invariant break via the 4-template library (plan §5/§7/§9).

    ``instantiate_all`` recognises single-use / quantity / price / step-order resources
    from the graph's generic commerce vocabulary. Nothing recognised → not-applicable.
    Each check is fired as a sequential replay through the gated firer (a read-only probe
    precedes every state-changing step, so read-only-first holds), then confirmed by the
    ``business_rule_invariant`` oracle.

    ``SINGLE_USE_REUSE`` checks are excluded here — ``run_race`` drives those exclusively
    (sequential-first, escalating to concurrent delivery) so the same limited resource is
    never consumed twice by two independent drivers.
    """
    from reachagent.business_logic.runner import SequentialReplayRunner
    from reachagent.business_logic.templates import instantiate_all
    from reachagent.oracles.business_rule import BusinessRule

    checks = [
        c for c in instantiate_all(graph).checks if c.rule is not BusinessRule.SINGLE_USE_REUSE
    ]
    if not checks:
        _emit(
            events,
            "payloads",
            "not-applicable",
            "business_logic: no coupon/quantity/price/flow resources in the graph",
        )
        return []
    runner = SequentialReplayRunner(firer, base_url)
    found: list[str] = []
    for check in checks:
        try:
            outcome = runner.run(identity, check)
        except Exception as exc:  # noqa: BLE001 — a refused replay is not a violation
            _emit(
                events,
                "payloads",
                "error",
                f"business_logic replay refused ({type(exc).__name__})",
                rule=check.rule.value,
            )
            continue
        verdict = seam.run(OracleMechanism.BUSINESS_RULE_INVARIANT, outcome.evidence)
        if verdict.is_violation:
            nid = seam.write(
                "business_logic",
                seam.last,
                severity="high",
                metadata={"rule": check.rule.value},
            )
            if nid:
                found.append(nid)
                _emit(
                    events,
                    "payloads",
                    "finding",
                    f"business-logic violation ({check.rule.value})",
                    rule=check.rule.value,
                )
    return found


def run_race(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    seam: _ValidatorSeam,
    events: list[ScanEvent],
) -> list[str]:
    """Sequential-first race probing over single-use/reuse resources (plan §7/§9).

    Reuses ``race/module.py``'s ``probe_race`` + ``RequestFirerDeliveryRunner`` —
    same ``business_rule_invariant`` oracle ``run_business_logic`` uses, no new
    mechanism. ``run_business_logic`` explicitly excludes ``SINGLE_USE_REUSE``
    checks so the same limited resource is never consumed twice by two drivers.

    Concurrent single-packet delivery needs a fresh target-specific consumable
    minted per resource (``FreshDeliveryProvider``) — a generic driver has no
    way to mint one, so this stops at the sequential replay (still a genuine
    confirmation: a secure app refuses the second redemption outright). The
    opt-in PortSwigger live gate (``race/module.py``'s ``live_gate_config``)
    is where the concurrent escalation is exercised.
    """
    from reachagent.business_logic.templates import instantiate_all
    from reachagent.oracles.business_rule import BusinessRule
    from reachagent.race import RequestFirerDeliveryRunner, probe_race

    checks = [c for c in instantiate_all(graph).checks if c.rule is BusinessRule.SINGLE_USE_REUSE]
    if not checks:
        _emit(
            events,
            "payloads",
            "not-applicable",
            "race: no single-use/reuse resource in the graph",
        )
        return []
    runner = RequestFirerDeliveryRunner(firer, base_url=base_url)
    found: list[str] = []
    for check in checks:
        try:
            _evidence, outcome = probe_race(graph, identity, check, runner, oracle_runner=seam.run)
        except Exception as exc:  # noqa: BLE001, S112 — a refused replay is not a violation
            _emit(events, "payloads", "error", f"race replay refused ({type(exc).__name__})")
            continue
        if outcome.is_violation:
            nid = seam.write("race", seam.last, severity="high")
            if nid:
                found.append(nid)
                _emit(events, "payloads", "finding", "race — single-use resource redeemed twice")
    if not found:
        _emit(events, "payloads", "not-applicable", "race: no reuse confirmed")
    return found


def run_xxe(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    auth_headers: Mapping[str, str],
    seam: _ValidatorSeam,
    events: list[ScanEvent],
) -> list[str]:
    """Blind XXE — OOB external-entity exfiltration (§7 ``oob_callback``).

    Fires the existing ``sqli_blind/oob-xxe-exfil`` template (previously
    reserved: payloads available, no confirming adapter — see
    ``corpus._RESERVED_CLASS_TOKENS``) as a raw XML body against endpoints
    whose spec-declared request Content-Type is XML — sink-matched (§9), never
    a content-type guess. Gated on ``REACHAGENT_OOB_BASE_DOMAIN``: with no
    collaborator there is no channel to ever observe a callback on, so the
    class is honestly skipped rather than firing a payload nothing could
    confirm. OPTIONS-or-GET preflight clears read-only-first (§10) before the
    XML body fires, mirroring ``run_mass_assignment``/``run_xss_stored``.
    """
    if not os.environ.get("REACHAGENT_OOB_BASE_DOMAIN"):
        _emit(events, "payloads", "not-applicable", "xxe: no REACHAGENT_OOB_BASE_DOMAIN configured")
        return []

    xml_endpoints = [
        (ep_node, ep)
        for ep_node, ep in graph.endpoints()
        if ep.method.upper() in ("POST", "PUT", "PATCH")
        and "xml" in (ep.content_type or "").lower()
    ]
    if not xml_endpoints:
        _emit(events, "payloads", "not-applicable", "xxe: no endpoint declares an XML request body")
        return []

    from reachagent.oob.collaborator import InteractshCollaborator
    from reachagent.oracles.oob_callback import OOBCallbackEvidence
    from reachagent.payloads.payload_resolver import resolve

    try:
        collaborator = InteractshCollaborator()
    except Exception:  # noqa: BLE001, S110 — no OOB domain configured is valid
        _emit(events, "payloads", "not-applicable", "xxe: OOB collaborator unavailable")
        return []

    found: list[str] = []
    for _ep_node, ep in xml_endpoints:
        label = f"xxe {ep.path}"
        url = f"{base_url.rstrip('/')}{ep.path}"
        preflight = _fire_readonly(
            firer,
            identity,
            "OPTIONS",
            url,
            events=events,
            label=f"{label}/preflight",
            headers=auth_headers,
        )
        if preflight is None or not (200 <= preflight.status_code < 300):
            preflight = _fire_readonly(
                firer,
                identity,
                "GET",
                url,
                events=events,
                label=f"{label}/preflight-get",
                headers=auth_headers,
            )
        if preflight is None or not (200 <= preflight.status_code < 300):
            _emit(events, "payloads", "not-applicable", f"{label}: no read-only clearance")
            continue

        nonce = "ra" + uuid.uuid4().hex[:12]
        body = resolve("sqli_blind/oob-xxe-exfil", nonce=nonce, collab=collaborator._base_domain)
        try:
            firer.fire(
                identity,
                ep.method,
                url,
                state_changing=False,
                headers={**dict(auth_headers), "Content-Type": "application/xml"},
                content=body.encode("utf-8"),
            )
        except Exception as exc:  # noqa: BLE001, S112 — a refused probe is not a violation
            _emit(events, "payloads", "error", f"{label}: fire refused ({type(exc).__name__})")
            continue

        verdict = seam.run(
            OracleMechanism.OOB_CALLBACK,
            OOBCallbackEvidence(
                probe_nonce=nonce,
                observed_nonces=collaborator.observed_nonces(),
                evidence_ref=f"orchestrator/{label}",
            ),
        )
        if verdict.is_violation:
            nid = seam.write("xxe", seam.last, severity="critical")
            if nid:
                found.append(nid)
                _emit(
                    events,
                    "payloads",
                    "finding",
                    f"blind xxe — oob callback at {ep.path}",
                    path=ep.path,
                )

    if not found:
        _emit(events, "payloads", "not-applicable", "xxe: no OOB callback observed")
    return found


# ---------------------------------------------------------------------------
# Signal-gated reconfirm seam (§9 W5/D3)
#
# A signal-gated tool (the wrappers registered in recon/tools/signal_gated.py)
# emits a CLAIM as an inert Candidate; run_signal_tools drops every claim on the
# floor (an honest "reconfirmation_required" event) unless a `reconfirm`
# callback is supplied. This section is that callback: it independently
# re-fires ONE fresh probe against the candidate's own endpoint/param and
# builds real §7 evidence, then hands it to signal_gated.reconfirm_candidate
# — the one place a tool-sourced claim can become a Finding, and only via a
# fresh run_oracle verdict, never the tool's own say-so.
#
# Narrow scope, deliberately: only the (vuln_class, suggested_oracle) pairs
# with an existing deterministic confirmation shape to reuse are handled —
# (sqli, DIFFERENTIAL), (xss_reflected, EXECUTION_CONFIRMATION),
# (command_injection, OOB_CALLBACK), (jwt_forgery, STRUCTURAL),
# (information_exposure, STRUCTURAL) — Build Order 0 upgraded this last one.
# Every other claim (ssti, ssrf, path_traversal, cve_match,
# server_misconfiguration, and sqli/command_injection claims suggesting a
# different oracle than above) still gets dropped with the same honest event
# as before this change — no regression, just not yet upgraded.
# ---------------------------------------------------------------------------

_SQL_ERROR_SIGNATURES: tuple[str, ...] = (
    "sql syntax",
    "sqlite3.operationalerror",
    "sqlite_error",
    "psycopg2",
    "you have an error in your sql",
    "unclosed quotation mark",
    "sqlalchemy",
    'near "',
)


def _reconfirm_jwt_forgery(
    candidate: Any,
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    auth_headers: Mapping[str, str],
    events: list[ScanEvent],
    ctx: Any,
) -> object | None:
    del ctx  # unused — no ExplorerContext needed for the header-only JWT probe
    from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence
    from reachagent.payloads.payload_resolver import _TEMPLATES

    valid_token = auth_headers.get("Authorization", "")
    if not valid_token.lower().startswith("bearer "):
        return None
    forged = _TEMPLATES.get("jwt_forgery/none-alg")
    if not forged:
        return None
    ep = graph.endpoint(candidate.endpoint_node)
    url = f"{base_url.rstrip('/')}{ep.path}"
    label = f"signal-reconfirm jwt {ep.path}"
    baseline = _fire_readonly(
        firer, identity, "GET", url, events=events, label=f"{label}/baseline", headers=auth_headers
    )
    if baseline is None:
        return None
    probe = _fire_readonly(
        firer,
        identity,
        "GET",
        url,
        events=events,
        label=f"{label}/probe",
        headers={**auth_headers, "Authorization": f"Bearer {forged}"},
    )
    if probe is None:
        return None
    return StructuralEvidence(
        check_type=StructuralCheckType.JWT_FORGERY,
        baseline_status=baseline.status_code,
        probe_status=probe.status_code,
        evidence_ref=f"signal-reconfirm/jwt{ep.path}",
    )


def _reconfirm_xss_reflected(
    candidate: Any,
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    auth_headers: Mapping[str, str],
    events: list[ScanEvent],
    ctx: Any,
) -> object | None:
    from reachagent.oracles.execution_confirmation import ExecutionConfirmationEvidence
    from reachagent.payloads.payload_resolver import resolve
    from reachagent.tools.explorer import _fire_with_value

    if candidate.param_node is None:
        return None
    ep = graph.endpoint(candidate.endpoint_node)
    param = graph.parameter(candidate.param_node)
    url = f"{base_url.rstrip('/')}{ep.path}"
    label = f"signal-reconfirm xss {ep.path}"
    mutating = ep.method.upper() not in ("GET", "HEAD", "OPTIONS")
    if mutating:
        preflight = _fire_readonly(
            firer, identity, "OPTIONS", url, events=events, label=f"{label}/preflight"
        )
        if preflight is None or not (200 <= preflight.status_code < 300):
            preflight = _fire_readonly(
                firer, identity, "GET", url, events=events, label=f"{label}/preflight-get"
            )
        if preflight is None or not (200 <= preflight.status_code < 300):
            return None
    tag = f"ra{uuid.uuid4().hex[:10]}"
    payload = resolve("xss/reflected/script-tag-canary", canary=tag)
    try:
        result = _fire_with_value(
            ctx,
            identity,
            ep.method,
            url,
            param.location,
            param.name,
            payload,
            state_changing=mutating,
        )
    except Exception:  # noqa: BLE001 — a refused probe is not a violation
        return None
    body = result.body.decode("utf-8", errors="replace")
    return ExecutionConfirmationEvidence(
        payload_tag=tag, response_body=body, evidence_ref=f"signal-reconfirm/xss{ep.path}"
    )


def _reconfirm_command_injection(
    candidate: Any,
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    auth_headers: Mapping[str, str],
    events: list[ScanEvent],
    ctx: Any,
) -> object | None:
    if not os.environ.get("REACHAGENT_OOB_BASE_DOMAIN") or candidate.param_node is None:
        return None
    from reachagent.oob.collaborator import InteractshCollaborator
    from reachagent.oracles.oob_callback import OOBCallbackEvidence
    from reachagent.payloads.payload_resolver import resolve
    from reachagent.tools.explorer import _fire_with_value

    try:
        collaborator = InteractshCollaborator()
    except Exception:  # noqa: BLE001, S110 — no OOB domain configured is valid
        return None
    ep = graph.endpoint(candidate.endpoint_node)
    param = graph.parameter(candidate.param_node)
    url = f"{base_url.rstrip('/')}{ep.path}"
    label = f"signal-reconfirm cmdi {ep.path}"
    mutating = ep.method.upper() not in ("GET", "HEAD", "OPTIONS")
    if mutating:
        preflight = _fire_readonly(
            firer, identity, "OPTIONS", url, events=events, label=f"{label}/preflight"
        )
        if preflight is None or not (200 <= preflight.status_code < 300):
            preflight = _fire_readonly(
                firer, identity, "GET", url, events=events, label=f"{label}/preflight-get"
            )
        if preflight is None or not (200 <= preflight.status_code < 300):
            return None
    nonce = "ra" + uuid.uuid4().hex[:12]
    payload = resolve(
        "command_injection/oob-dns-callback", nonce=nonce, collab=collaborator._base_domain
    )
    try:
        _fire_with_value(
            ctx,
            identity,
            ep.method,
            url,
            param.location,
            param.name,
            payload,
            state_changing=mutating,
        )
    except Exception:  # noqa: BLE001 — a refused probe is not a violation
        return None
    return OOBCallbackEvidence(
        probe_nonce=nonce,
        observed_nonces=collaborator.observed_nonces(),
        evidence_ref=f"signal-reconfirm/cmdi{ep.path}",
    )


def _reconfirm_sqli(
    candidate: Any,
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    auth_headers: Mapping[str, str],
    events: list[ScanEvent],
    ctx: Any,
) -> object | None:
    from reachagent.oracles.differential import (
        DiffAxis,
        DifferentialEvidence,
        DiffExpectation,
        Observation,
    )
    from reachagent.tools.explorer import _fire_with_value

    if candidate.param_node is None:
        return None
    ep = graph.endpoint(candidate.endpoint_node)
    param = graph.parameter(candidate.param_node)
    url = f"{base_url.rstrip('/')}{ep.path}"
    label = f"signal-reconfirm sqli {ep.path}"
    mutating = ep.method.upper() not in ("GET", "HEAD", "OPTIONS")
    if mutating:
        preflight = _fire_readonly(
            firer, identity, "OPTIONS", url, events=events, label=f"{label}/preflight"
        )
        if preflight is None or not (200 <= preflight.status_code < 300):
            preflight = _fire_readonly(
                firer, identity, "GET", url, events=events, label=f"{label}/preflight-get"
            )
        if preflight is None or not (200 <= preflight.status_code < 300):
            return None
    try:
        baseline = _fire_with_value(
            ctx, identity, ep.method, url, param.location, param.name, "1", state_changing=mutating
        )
        probe = _fire_with_value(
            ctx, identity, ep.method, url, param.location, param.name, "1'", state_changing=mutating
        )
    except Exception:  # noqa: BLE001 — a refused probe is not a violation
        return None
    return DifferentialEvidence(
        axis=DiffAxis.CROSS_CONDITION,
        expectation=DiffExpectation.DATABASE_ERROR,
        baseline=Observation("baseline", baseline.status_code, ""),
        probe=Observation("probe", probe.status_code, probe.body.decode("utf-8", errors="replace")),
        error_signatures=_SQL_ERROR_SIGNATURES,
        evidence_ref=f"signal-reconfirm/sqli{ep.path}",
    )


def _reconfirm_information_exposure(
    candidate: Any,
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    auth_headers: Mapping[str, str],
    events: list[ScanEvent],
    ctx: Any,
) -> object | None:
    del ctx  # unused — a plain read-only GET is all this check needs
    from reachagent.info_disclosure.detector import match_marker
    from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence

    ep = graph.endpoint(candidate.endpoint_node)
    url = f"{base_url.rstrip('/')}{ep.path}"
    label = f"signal-reconfirm information_exposure {ep.path}"
    probe = _fire_readonly(
        firer, identity, "GET", url, events=events, label=label, headers=auth_headers
    )
    if probe is None:
        return None
    body = probe.body.decode("utf-8", errors="replace")
    return StructuralEvidence(
        check_type=StructuralCheckType.INFO_DISCLOSURE,
        sentinel=match_marker(body) or "",
        probe_status=probe.status_code,
        response_body=body,
        evidence_ref=f"signal-reconfirm/info-disclosure{ep.path}",
    )


_RECONFIRM_BUILDERS: dict[tuple[str, OracleMechanism], Callable[..., object | None]] = {
    ("jwt_forgery", OracleMechanism.STRUCTURAL): _reconfirm_jwt_forgery,
    ("xss_reflected", OracleMechanism.EXECUTION_CONFIRMATION): _reconfirm_xss_reflected,
    ("command_injection", OracleMechanism.OOB_CALLBACK): _reconfirm_command_injection,
    ("sqli", OracleMechanism.DIFFERENTIAL): _reconfirm_sqli,
    ("information_exposure", OracleMechanism.STRUCTURAL): _reconfirm_information_exposure,
}


def _make_signal_reconfirm(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    auth_headers: Mapping[str, str],
    events: list[ScanEvent],
    library: Any | None = None,
) -> Callable[[Any], object]:
    """Build the ``reconfirm`` callback ``run_signal_tools`` calls per candidate.

    Builds the ``ExplorerContext`` (and its payload library) once here, not once
    per candidate inside each builder — ``build_library()`` re-parses the whole
    vendored corpus from disk on every call and is uncached, so this is the
    difference between one library load per scan and one per candidate.
    ``library`` lets the caller pass its own already-built instance (avoiding a
    second full corpus parse in the same scan) when it has one.
    """
    from reachagent.recon.tools.signal_gated import reconfirm_candidate
    from reachagent.tools import validator
    from reachagent.tools.explorer_context import ExplorerContext

    ctx = ExplorerContext(
        graph=graph, firer=firer, library=library or _library(), base_url=base_url
    )

    def _finding_factory(candidate: Any, verdict: object) -> Finding:
        # information_exposure is a leaked-implementation-detail signal, not an
        # exploitable access/injection primitive — "high" would overstate it.
        severity = "informational" if candidate.vuln_class == "information_exposure" else "high"
        return Finding(
            vuln_class=candidate.vuln_class, severity=severity, oracle_used="", evidence_ref=""
        )

    def _reconfirm(candidate: Any) -> object:
        builder = _RECONFIRM_BUILDERS.get((candidate.vuln_class, candidate.suggested_oracle))
        if builder is None:
            return None
        try:
            evidence = builder(
                candidate,
                graph=graph,
                firer=firer,
                base_url=base_url,
                identity=identity,
                auth_headers=auth_headers,
                events=events,
                ctx=ctx,
            )
        except Exception as exc:  # noqa: BLE001 — one candidate cannot abort others
            _emit(
                events,
                "verification",
                "error",
                f"signal-gated reconfirm probe failed: {type(exc).__name__}",
            )
            return None
        if evidence is None:
            return None
        node_id = reconfirm_candidate(
            candidate,
            evidence,
            run_oracle=validator.run_oracle,
            write_finding=validator.write_finding,
            graph=graph,
            finding_factory=_finding_factory,
        )
        if node_id:
            _emit(
                events,
                "payloads",
                "finding",
                f"signal-gated reconfirm — {candidate.vuln_class} independently confirmed",
                finding=node_id,
                endpoint=candidate.endpoint_node,
            )
        return node_id

    return _reconfirm


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------


def scan_all_classes(
    *,
    base_url: str,
    in_scope: str,
    out_of_scope: str | None = None,
    max_attempts: int = 20,
    surface_path: str | None = None,
    identities: IdentityStore | None = None,
    events: list[ScanEvent] | None = None,
    transport: httpx.BaseTransport | None = None,
    library: Any | None = None,
    graph: ReachabilityGraph | None = None,
    audit: AuditLog | None = None,
    operator_prompt: str | None = None,
    require_llm: bool = False,
    planner_client: PlannerClient | None = None,
    live_recon: bool = False,
    cancel_check: object | None = None,
    control_client: LoopAdvisorClient | None = None,
    checkpoint_path: str | None = None,
    resume_checkpoint: str | None = None,
    idle_timeout: float = 900.0,
    allow_cross_user_writes: bool = False,
) -> dict[str, Any]:
    """Run the validated multi-phase LLM-driven loop over ALL attack classes.

    Phase 1+2+3-sink reuse ``scan_target`` (cold-start recon, api_discovery, the generic
    sink-matched payload chain). The remaining classes run through their deterministic
    drivers above. Every finding is ``run_oracle → is_violation → write_finding``.
    ``library`` is built once and shared by ``scan_target`` and the blind-SQLi driver.
    ``graph``/``audit`` may be injected so the caller holds live references to the state
    the scan is writing (the GUI streams them while the scan runs).

    ``allow_cross_user_writes`` gates ``run_authz_idor`` alone (default False): the one
    driver whose confirmed path fires a genuine state-changing write against ANOTHER
    identity's live object, so it never runs without explicit opt-in.
    """
    from reachagent.scan.agentic_loop import (
        AdaptiveControlLoop,
        AdaptiveControlState,
        ModelControlError,
        PhaseDecision,
        ScanCancelled,
        check_cancel,
    )
    from reachagent.scan.entrypoint import detect_target_type, scan_target

    if checkpoint_path and resume_checkpoint:
        raise ValueError("checkpoint_path and resume_checkpoint are mutually exclusive")
    control_checkpoint = checkpoint_path or resume_checkpoint
    if resume_checkpoint:
        control_state = AdaptiveControlState.load(resume_checkpoint)
    else:
        control_state = AdaptiveControlState(
            checkpoint_path=control_checkpoint,
            idle_timeout=idle_timeout,
        )
    control = AdaptiveControlLoop(
        control_state,
        advisor=control_client,
        operator_prompt=operator_prompt or "",
        strict=require_llm,
        cancel=cancel_check,
        identities=identities,
        audit=audit,
    )

    def _adapt(phase: str, remaining: tuple[str, ...]) -> PhaseDecision | None:
        """Record a compact snapshot and apply scheduling-only model output."""
        check_cancel(cancel_check)
        try:
            # A resumed or explicitly skipped phase is already represented in the
            # checkpoint. Rebuild its snapshot for the GUI, but do not spend a
            # second model turn or execute a phase the model marked inapplicable.
            if phase in control_state.skipped:
                _emit(events_out, phase, "not-applicable", f"{phase} skipped by adaptive control")
                return None
            # A resumed phase is already represented in the checkpoint.  Rebuild
            # its snapshot for the GUI, but do not spend a second model turn.
            if phase in control_state.completed:
                from reachagent.scan.agentic_loop import build_phase_snapshot

                snapshot = build_phase_snapshot(
                    graph,
                    phase,
                    audit=audit,
                    identities=identities,
                    run_id=control_state.run_id,
                    revision=control_state.revision,
                )
                _emit(
                    events_out,
                    phase,
                    "snapshot",
                    f"{phase} state restored from checkpoint",
                    snapshot=snapshot.as_dict(),
                    digest=snapshot.digest,
                )
                return None
            control.state.phases = tuple(dict.fromkeys((*control.state.phases, *remaining)))
            failed_payloads = [
                {
                    "phase": event.phase,
                    "message": event.message,
                    "category": event.details.get("error_category", "target"),
                }
                for event in events_out
                if event.kind in {"error", "target-error"}
            ][-20:]
            snapshot, decision = control.after_phase(
                graph,
                phase,
                failed_payloads=failed_payloads,
            )
            _emit(
                events_out,
                phase,
                "snapshot",
                f"{phase} compact state snapshot",
                snapshot=snapshot.as_dict(),
                digest=snapshot.digest,
            )
            if decision is not None:
                if decision.action == "revise" and decision.hint:
                    control.operator_prompt = (
                        f"{control.operator_prompt[:1_000]}\nAdaptive focus: {decision.hint}"
                    ).strip()
                _emit(
                    events_out,
                    phase,
                    "step",
                    f"LLM loop decision after {phase}: {decision.action} — {decision.rationale}",
                    hint=decision.hint,
                    target_phase=decision.target_phase,
                )
            return decision
        except ScanCancelled:
            control_state.cancel()
            _emit(events_out, phase, "cancelled", "scan cancelled by operator")
            raise
        except ModelControlError as exc:
            _emit(
                events_out,
                phase,
                "model-error",
                f"adaptive control unavailable: {exc}",
                error_category="model",
            )
            if require_llm:
                raise
            return None

    events_out = events if events is not None else []
    check_cancel(cancel_check)
    execution_plan = None
    planned_recon_tools: tuple[str, ...] | None = None
    planned_signal_tools: tuple[str, ...] = ()
    recon_selector = None
    recon_candidates: tuple[str, ...] | None = None
    plan_client = None
    own_plan_client = False
    scan_budget = max_attempts
    if require_llm:
        # The GUI path has one model-controlled plan boundary. Validation is
        # strict and provider errors propagate; deterministic drivers still own
        # all request/oracle/finding capabilities after this proposal.
        from reachagent.llm.planner import (
            PlanningContext,
            build_planner_client,
            build_tool_catalog,
            plan_execution,
            select_recon_tools,
        )

        target_type = detect_target_type(base_url)
        context = PlanningContext(
            target=base_url,
            target_type=target_type,
            in_scope=tuple(part.strip() for part in in_scope.split(",") if part.strip()),
            graph_facts={"phase": "recon", "target": base_url},
            operator_prompt=operator_prompt or "",
            max_request_budget=max(1, max_attempts),
            max_tool_budget=16,
        )
        own_plan_client = planner_client is None
        plan_client = planner_client or build_planner_client()
        try:
            execution_plan = plan_execution(context, plan_client)
        except Exception:
            if own_plan_client and hasattr(plan_client, "close"):
                plan_client.close()
            raise
        catalog_by_name = {entry.name: entry for entry in build_tool_catalog()}
        recon_names: list[str] = []
        signal_names: list[str] = []
        for phase in execution_plan.phases:
            for tool_name in phase.tools:
                entry = catalog_by_name[tool_name]
                if entry.signal_gated:
                    signal_names.append(tool_name)
                elif entry.phase == "recon":
                    # Insertion-point adapters are deliberately not executed
                    # during cold-start recon; they run after the surface exists.
                    recon_names.append(tool_name)
        planned_recon_tools = tuple(dict.fromkeys(recon_names))
        planned_signal_tools = tuple(dict.fromkeys(signal_names))
        recon_candidates = tuple(
            entry.name
            for entry in catalog_by_name.values()
            if entry.phase == "recon" and target_type in entry.target_types
        )

        def _select_recon(
            state: dict[str, str],
            available: tuple[str, ...],
            completed: tuple[str, ...],
        ) -> object:
            if plan_client is None:
                raise RuntimeError("adaptive recon planner client is unavailable")
            remaining_budget = execution_plan.tool_budget - len(completed)
            if remaining_budget <= 0:
                from reachagent.llm.planner import ReconSelection

                return ReconSelection((), "recon tool budget exhausted", True)
            # The enforced limit IS remaining_budget (validate_recon_selection's
            # `max_tools`), not the plan's full tool_budget — the prompt must show
            # the same number the validator enforces. Building the context with the
            # full static budget here (while the validator checked the remaining
            # one) is exactly the divergence that made a correct, budget-aware
            # selection get rejected with "recon selection exceeds the remaining
            # tool budget": the model was never told the real, shrinking limit.
            max_tools = min(remaining_budget, len(available))
            adaptive_context = PlanningContext(
                target=context.target,
                target_type=context.target_type,
                in_scope=context.in_scope,
                graph_facts=state,
                operator_prompt=context.operator_prompt,
                max_request_budget=context.max_request_budget,
                max_tool_budget=max(1, max_tools),
            )
            return select_recon_tools(
                adaptive_context,
                plan_client,
                state=state,
                available_tools=available,
                completed_tools=completed,
                max_tools=max_tools,
            )

        recon_selector = _select_recon
        scan_budget = min(max_attempts, execution_plan.request_budget)
        _emit(
            events_out,
            "plan",
            "plan",
            "LLM execution plan accepted",
            rationale=execution_plan.rationale,
            request_budget=execution_plan.request_budget,
            tool_budget=execution_plan.tool_budget,
            phases=[
                {
                    "name": phase.name,
                    "rationale": phase.rationale,
                    "tools": list(phase.tools),
                }
                for phase in execution_plan.phases
            ],
        )
        for phase in execution_plan.phases:
            _emit(
                events_out,
                phase.name,
                "plan",
                f"LLM planned {phase.name} phase",
                rationale=phase.rationale,
                tools=list(phase.tools),
            )
    _emit(events_out, "recon", "info", "phase 1: recon and technology discovery", target=base_url)
    # The recon-profile decision is real data the GUI shows first: which profile the LLM
    # picked for this target and why (or the safe-default reason when LLM is off/failed).
    from reachagent.recon.live_tuning import profile_decision

    profile = profile_decision(base_url, operator_prompt=operator_prompt)
    if operator_prompt:
        _emit(
            events_out,
            "recon",
            "step",
            "operator objective supplied to the proposal phases",
            objective=operator_prompt[:500],
        )
    _emit(
        events_out,
        "recon",
        "step",
        profile["reason"],
        profile=profile["profile"],
        signals=profile["signals"],
    )

    _emit(events_out, "endpoints", "info", "phase 2: endpoints and insertion points")
    lib = library if library is not None else _library()

    try:
        result = scan_target(
            base_url=base_url,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            dry_run=False,
            max_attempts=scan_budget,
            surface_path=surface_path,
            identities=identities,
            operator_prompt=operator_prompt,
            recon_tools=planned_recon_tools,
            recon_candidates=recon_candidates,
            recon_selector=recon_selector,
            live_recon=live_recon,
            events=events_out,
            transport=transport,
            library=lib,
            graph=graph,
            audit=audit,
            cancel_check=cancel_check,
        )
    except ScanCancelled:
        control_state.cancel()
        _emit(events_out, "recon", "cancelled", "scan cancelled by operator")
        raise
    finally:
        if own_plan_client and plan_client is not None and hasattr(plan_client, "close"):
            plan_client.close()
    graph = result["graph"] if graph is None else graph
    audit = result["audit"] if audit is None else audit
    # Recon and endpoint mapping are performed by the same deterministic
    # discovery entrypoint, but receive separate compact snapshots so the
    # model can adapt before expensive payload work begins.
    control.audit = audit
    _adapt("recon", ("endpoints", "payloads", "verification", "report"))
    _emit(
        events_out,
        "endpoints",
        "info",
        "phase 2 done — insertion points ready for payload selection",
        endpoints=len(list(graph.endpoints())),
        parameters=sum(len(graph.parameters_of(ep)) for ep, _ in graph.endpoints()),
        hosts=len([n for n, _ in graph.hosts()]),
        selected_tools=list(result.get("recon_tools", ())),
        planned_signal_tools=list(planned_signal_tools),
    )

    # LLM-driven surface prioritization (flag-gated, ordering only): after
    # recon completes, send the discovered surface to the LLM and get back a
    # ranked list of which endpoints to attack first. The Coordinator still
    # scores/selects with its deterministic formula — this only changes the
    # order in which candidates are presented so high-value endpoints are
    # scored first when budget runs out before coverage does.
    from reachagent.recon.surface_tuning import propose_surface_priority

    # Reset any stale priority from a prior scan before proposing anew.
    from reachagent.tools.coordinator_support import clear_surface_priority

    clear_surface_priority()
    priority = propose_surface_priority(
        graph,
        target_type=detect_target_type(base_url),
        operator_prompt=control.operator_prompt,
    )
    if priority is not None:
        from reachagent.tools.coordinator_support import (
            set_insertion_priority,
            set_surface_priority,
        )

        set_surface_priority(priority.ranked_ids)
        set_insertion_priority(priority.ranked_parameter_ids)
        _emit(
            events_out,
            "endpoints",
            "step",
            f"LLM surface prioritization: {priority.rationale}",
            ranked_count=len(priority.ranked_ids),
            ranked_ids=list(priority.ranked_ids[:10]),
            ranked_parameter_count=len(priority.ranked_parameter_ids),
            ranked_parameter_ids=list(priority.ranked_parameter_ids[:20]),
        )

    # A revisit request is bounded by AdaptiveControlState and is implemented
    # as a fresh deterministic priority proposal over the observed surface.
    # It does not replay a request or manufacture a verdict.
    if decision_recon := next(
        (
            item
            for item in reversed(control_state.decisions)
            if item.get("phase") == "recon" and item.get("action") == "revisit"
        ),
        None,
    ):
        revisit_priority = propose_surface_priority(
            graph,
            target_type=detect_target_type(base_url),
            operator_prompt=(
                f"{control.operator_prompt}\nRevisit focus: "
                f"{str(decision_recon.get('hint', ''))[:200]}"
            ),
        )
        if revisit_priority is not None:
            from reachagent.tools.coordinator_support import (
                set_insertion_priority,
                set_surface_priority,
            )

            set_surface_priority(revisit_priority.ranked_ids)
            set_insertion_priority(revisit_priority.ranked_parameter_ids)
            _emit(
                events_out,
                "endpoints",
                "step",
                "revisited surface priority from observed state",
                ranked_count=len(revisit_priority.ranked_ids),
            )

    scope = ScopeGuard.from_raw(in_scope, out_of_scope)
    from reachagent.recon.signal_dispatch import run_signal_tools

    # Endpoint state is now complete; the adaptive controller may suppress an
    # optional verification pass or revise its evidence focus.  It only changes
    # scheduling and priority inputs, never a fire or oracle call.
    decision_2 = _adapt("endpoints", ("payloads", "verification", "report"))

    # LLM-driven signal-tool selection (flag-gated): after recon + surface
    # prioritization, the LLM reasons about which verification tools to invoke.
    # The signal-gated base still enforces has_signal() — this is a reasoning
    # filter on top of the safety gate, never a bypass. When the flag is off
    # (or the LLM fails), the planner's upfront selection is used unchanged.
    from reachagent.recon.signal_tuning import propose_signal_tools

    signal_choice = propose_signal_tools(graph, operator_prompt=control.operator_prompt)
    effective_signal_tools = planned_signal_tools
    decision_2_target = getattr(decision_2, "target_phase", None) if decision_2 else None
    if (
        decision_2 is not None
        and decision_2.action == "skip"
        and (decision_2_target in {None, "verification"})
    ):
        _emit(
            events_out,
            "verification",
            "info",
            f"verification skipped by LLM loop decision: {decision_2.rationale}",
        )
        effective_signal_tools = ()
    elif signal_choice is not None:
        _emit(
            events_out,
            "verification",
            "step",
            f"LLM signal-tool selection: {signal_choice.rationale}",
            selected=list(signal_choice.selected_tools),
        )
        effective_signal_tools = signal_choice.selected_tools

    # Built before run_signal_tools (not after, as previously) so a real
    # reconfirm callback can be wired in — the same firer/seam every other
    # driver below uses, not a second execution path.
    # Opt-in only (never a silent default): some legitimate authorized targets
    # (an expired/self-signed cert on a legacy or intentionally-vulnerable demo
    # app) fail TLS verification entirely. An operator must explicitly set this
    # to acknowledge scanning past it — the same gating discipline as every
    # other REACHAGENT_* opt-in flag.
    _tls_kwargs: dict[str, Any] = (
        {"verify": False} if os.environ.get("REACHAGENT_TLS_INSECURE") == "1" else {}
    )
    firer = RequestFirer(
        httpx.Client(transport=transport, **_tls_kwargs)
        if transport is not None
        else httpx.Client(**_tls_kwargs),
        scope,
        audit,
        identity_stores=identities,
    )
    seam = _ValidatorSeam(graph)
    identity, auth_headers = _identity_for_scan(identities, events_out)

    run_signal_tools(
        tool_names=effective_signal_tools,
        graph=graph,
        scope=scope,
        audit=audit,
        target=base_url,
        emit=lambda phase, kind, message, **details: _emit(
            events_out, phase, kind, message, **details
        ),
        live_recon=live_recon,
        reconfirm=_make_signal_reconfirm(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            events=events_out,
            library=lib,
        ),
    )
    _adapt("verification", ("payloads", "report"))

    # Phase 3 — the classes the sink loop does not drive. Dispatch order is
    # LLM-ranked (rank_vuln_classes, above) when REACHAGENT_VULN_TUNING is
    # enabled — already the case for every GUI scan — falling back to the
    # order below otherwise. Every class still runs regardless; only
    # sequencing is LLM-influenced.
    _emit(events_out, "payloads", "info", "phase 3: structural + authz + advanced classes")

    from reachagent.scan.xss_dom import run_xss_dom

    def _run_authz_bola_if_identities() -> None:
        if identities is not None:
            run_authz_bola(
                graph=graph,
                base_url=base_url,
                identities=identities,
                events=events_out,
                transport=transport,
            )

    def _run_authz_idor_if_identities() -> None:
        if identities is not None:
            run_authz_idor(
                graph=graph,
                firer=firer,
                base_url=base_url,
                identities=identities,
                seam=seam,
                events=events_out,
                allow_cross_user_writes=allow_cross_user_writes,
            )

    phase3_drivers: dict[str, Callable[[], None]] = {
        "default_credentials": lambda: run_default_credentials(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events_out,
        ),
        "rate_limit_absence": lambda: run_rate_limit_absence(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events_out,
        ),
        "structural_headers": lambda: run_structural_headers(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            seam=seam,
            events=events_out,
        ),
        "file_upload": lambda: run_file_upload(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            seam=seam,
            events=events_out,
        ),
        "mass_assignment": lambda: run_mass_assignment(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            seam=seam,
            events=events_out,
        ),
        "xss_stored": lambda: run_xss_stored(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            seam=seam,
            events=events_out,
        ),
        "open_redirect": lambda: run_open_redirect(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            seam=seam,
            events=events_out,
        ),
        "cache_poisoning": lambda: run_cache_poisoning(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            seam=seam,
            events=events_out,
        ),
        "request_smuggling": lambda: run_request_smuggling(
            base_url=base_url,
            seam=seam,
            events=events_out,
        ),
        "subdomain_takeover": lambda: run_subdomain_takeover(
            graph=graph,
            seam=seam,
            events=events_out,
            transport=transport,
        ),
        "jwt_forgery": lambda: run_jwt_forgery(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            seam=seam,
            events=events_out,
        ),
        "sqli_blind": lambda: run_sqli_blind(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events_out,
            library=lib,
        ),
        "nosqli": lambda: run_nosqli(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events_out,
            library=lib,
        ),
        "ldap": lambda: run_ldap(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events_out,
            library=lib,
        ),
        "command_injection": lambda: run_command_injection(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events_out,
            library=lib,
        ),
        "authz_bola": _run_authz_bola_if_identities,
        "authz_idor": _run_authz_idor_if_identities,
        "graphql": lambda: run_graphql(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events_out,
            identities=identities,
        ),
        "business_logic": lambda: run_business_logic(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events_out,
        ),
        "race": lambda: run_race(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events_out,
        ),
        "xxe": lambda: run_xxe(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            seam=seam,
            events=events_out,
        ),
        "xss_dom": lambda: run_xss_dom(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events_out,
        ),
    }

    ranked_order, rank_reason = rank_vuln_classes(
        _PHASE3_CLASS_ORDER, graph, operator_prompt=operator_prompt
    )
    _emit(
        events_out,
        "payloads",
        "info",
        f"phase 3 class order: {rank_reason}",
        order=list(ranked_order),
    )
    current_specialist: str | None = None
    for class_name in ranked_order:
        check_cancel(cancel_check)
        specialist = _SPECIALIST_OF_CLASS.get(class_name, "general")
        if specialist != current_specialist:
            current_specialist = specialist
            _emit(
                events_out,
                "payloads",
                "info",
                f"{_SPECIALIST_LABELS.get(specialist, specialist)} — starting",
                specialist=specialist,
            )
        phase3_drivers[class_name]()

    findings = [fid for fid, _ in graph.findings()]
    _emit(events_out, "payloads", "info", "phase 3 done", findings=len(findings))

    # Findings now exist only if the deterministic oracle accepted them. The
    # model receives a final bounded snapshot and may only schedule/report a
    # follow-up; it cannot alter a finding already in the graph.
    _adapt("payloads", ("report",))

    driven_classes = {
        *_GENERIC_CLASSES,
        "clickjacking",
        "cors_misconfig",
        "csrf_missing_protection",
        "file_upload",
        "jwt_forgery",
        "bola",
        "bfla",
        "idor",
        "graphql",
        "business_logic",
        "race",
        "sqli_blind",
        "mass_assignment",
        "xss_stored",
        "open_redirect",
        "web_cache_poisoning",
        "request_smuggling",
        "subdomain_takeover",
        "xxe",
        # xss_dom IS driven (run_xss_dom above) — this set was stale, causing a
        # contradictory "no discovered precondition" event on every all-class
        # scan even when xss_dom just ran (and may have confirmed a finding).
        "xss_dom",
    }
    for vuln_class in ALL_CLASSES:
        if vuln_class not in driven_classes:
            _emit(
                events_out,
                "payloads",
                "not-applicable",
                f"{vuln_class}: no discovered precondition for a safe driver",
            )
    _emit(
        events_out,
        "report",
        "info",
        "phase 4 ready — confirmed findings handed to report generation",
        findings=len(findings),
    )
    _adapt("report", ())
    return {
        "graph": graph,
        "audit": audit,
        "findings": findings,
        "events": events_out,
    }
