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

import concurrent.futures
import contextvars
import copy
import logging
import os
import re
import threading
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import httpx

from reachagent.detection.oracle_gateway import OracleOutcome
from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import Endpoint, Finding, SinkType, SuspectedFinding
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
    "cloud_bucket_exposure",
    "known_vulnerable_version",
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
    "prototype_pollution",
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
    "prototype_pollution": "client_side",
    "file_upload": "injection",
    "sqli_blind": "injection",
    "nosqli": "injection",
    "ldap": "injection",
    "command_injection": "injection",
    "xxe": "injection",
    "request_smuggling": "protocol",
    "subdomain_takeover": "protocol",
    "cloud_bucket_exposure": "protocol",
    "known_vulnerable_version": "protocol",
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
    # Application-domain inference (v2 W18): a host-level advisory fact, order-only, exactly
    # like host_tech — hospital/ecommerce/banking steers WHICH classes to prioritize.
    domains = sorted({h.app_domain for _, h in graph.hosts() if h.app_domain})
    if domains:
        signals["app_domain"] = ",".join(domains)[:120]
    techs = sorted({h.technology for _, h in graph.hosts() if h.technology})
    if techs:
        signals["host_tech"] = ",".join(techs)[:200]
        # Cross-engagement pattern memory ("My additions"): a hunt-priority
        # hint only — every class in ALL_CLASSES still runs regardless, this
        # can only reorder. Values are our own fixed vuln_class vocabulary,
        # never target-controlled text, so this carries no prompt-injection
        # surface the way echoing response content would.
        from reachagent.memory.pattern_db import patterns_for_technology

        seen_classes: set[str] = set()
        past_classes: list[str] = []
        for tech in techs:
            for pattern in patterns_for_technology(tech, limit=5):
                if pattern.vuln_class not in seen_classes:
                    seen_classes.add(pattern.vuln_class)
                    past_classes.append(pattern.vuln_class)
        if past_classes:
            signals["past_confirmed_for_similar_stack"] = ",".join(past_classes[:8])
    # White-box mode (Build Order 7): SAST hits/known-vulnerable dependencies
    # STEER priority only — bounded, order-only, exactly like every other
    # signal in this dict. Values are our own static tools' rule ids / a
    # package+CVE pair, never raw target-controlled content.
    source_files = graph.source_files()
    if source_files:
        rule_ids = sorted({sf.rule_id for _fid, sf in source_files})
        signals["static_analysis_hits"] = ",".join(rule_ids[:10])[:300]
    advisories = graph.static_advisories()
    if advisories:
        cve_summaries = sorted({f"{a.package}:{a.cve_id}" for _aid, a in advisories})
        signals["known_vulnerable_dependencies"] = ",".join(cve_summaries[:10])[:300]
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

        tuner = client or build_openai_compatible_client(tier="grunt")
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
    "prototype_pollution",
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
# v3 V3: a second, independent attacker origin for CORS corroboration — a
# genuinely different Origin value must ALSO be reflected before trusting a
# single hit, ruling out a coincidental exact-match against one allowlist
# entry rather than true arbitrary-origin reflection.
_ATTACKER_ORIGIN_2 = "https://reachagent-second.evil.example"
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
    """One streamable event from the orchestrator → GUI (phase timeline).

    ``timestamp`` auto-populates via ``default_factory`` on every construction site
    (15+ across the codebase) with zero call-site changes — added so the GUI's live
    "terminal" feed can show real wall-clock time per line, not just message order.
    """

    phase: str  # plan | recon | endpoints | insertion-points | payloads | verification | report
    kind: str  # info | plan | step | verdict | finding | not-applicable | error
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


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

    def record_suspected(
        self,
        vuln_class: str,
        *,
        endpoint: str = "",
        location: str = "",
        source: str = "",
        reason: str = "",
        evidence: str = "",
        severity: str = "info",
        confidence: str = "",
    ) -> str:
        """Record a tried-but-unconfirmed lead into the Suspected tier (Build Order v2 W2).

        The honest counterpart to :meth:`write` — called when a candidate was genuinely probed
        but the oracle did NOT confirm it (or a signal-gated scanner claimed it and the oracle
        couldn't re-prove it). Writes a structurally-separate ``SuspectedFinding`` node, never a
        ``Finding`` — so the "no Finding without run_oracle" guarantee is untouched. Idempotent
        (dedups on class/endpoint/location/source), advisory-only, never counted as confirmed.
        """
        return self.graph.add_suspected_finding(
            SuspectedFinding(
                vuln_class=vuln_class,
                endpoint=endpoint,
                location=location,
                source=source or "oracle",
                reason=reason,
                evidence=evidence,
                severity=severity,
                confidence=confidence,
            )
        )

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
        # LLM-confidence annotation (Build Order 5): computed here, strictly
        # after verdict.is_violation is already True, so it can never
        # influence whether this finding gets written — an additional
        # signal on an already-confirmed finding, never a substitute for
        # the oracle. Kept on dedicated Finding fields, deliberately never
        # merged into `metadata` (that dict's documented contract is
        # deterministic provenance only — see Finding's own docstring).
        # Flag-gated, fails open to no annotation on any error.
        from reachagent.confirmation.confidence import annotate_confidence

        confidence, rationale = ("", "")
        annotation = annotate_confidence(vuln_class, severity, verdict.reason)
        if annotation:
            confidence = annotation.get("llm_confidence", "")
            rationale = annotation.get("llm_confidence_rationale", "")
        finding = Finding(
            vuln_class=vuln_class,
            severity=severity,
            oracle_used="",
            evidence_ref="",
            llm_confidence=confidence,
            llm_confidence_rationale=rationale,
        )
        finding_id = validator.write_finding(self.graph, finding, verdict, metadata=metadata)
        # Cross-engagement pattern memory ("My additions"): recorded ONLY here,
        # strictly after write_finding already committed a confirmed violation —
        # never from LLM narrative or an unconfirmed candidate (memory-poisoning
        # guard). Advisory-only; a write error never breaks the scan.
        from reachagent.memory.pattern_db import record_confirmed_pattern

        technology = ""
        for _node, host in self.graph.hosts():
            if getattr(host, "technology", None):
                technology = str(host.technology)
                break
        if technology:
            record_confirmed_pattern(vuln_class, technology, finding.oracle_used, severity)
        return finding_id


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
    from reachagent.confirmation.corroboration import corroborate_with_variant
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
        # Technique-diversity corroboration (v3 V3): a second, DIFFERENT
        # attacker origin must also be reflected before trusting a single
        # hit — rules out a coincidental exact-match against one allowlist
        # entry rather than true arbitrary-origin reflection.
        cors_confirmed = verdict.is_violation

        def _second_cors_attempt(_url: str = url, _label: str = label, _path: str = path) -> object:
            second_headers = dict(auth_headers)
            second_headers["Origin"] = _ATTACKER_ORIGIN_2
            second_result = _fire_readonly(
                firer,
                identity,
                "GET",
                _url,
                events=events,
                label=f"{_label}/cors/corroborate",
                headers=second_headers,
            )
            return seam.run(
                OracleMechanism.STRUCTURAL,
                StructuralEvidence(
                    check_type=StructuralCheckType.CORS_MISCONFIG,
                    acao=_hdr(second_result, "access-control-allow-origin"),
                    acac=_hdr(second_result, "access-control-allow-credentials"),
                    probe_origin=_ATTACKER_ORIGIN_2,
                    evidence_ref=f"orchestrator/cors{_path}",
                ),
            )

        if verdict.is_violation:
            cors_confirmed = corroborate_with_variant(verdict, _second_cors_attempt).corroborated
        if cors_confirmed and seam.last is not None:
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

    Canary first, same catch-all class ``recon/calibration.py`` already guards
    content-discovery against (§ D1-D4 there): many SPA backends (permissive CORS
    middleware answering every ``OPTIONS`` with 204, a catch-all route answering
    every unmatched ``POST`` with 200) make EVERY guessed path in ``_UPLOAD_PATHS``
    look like a confirmed bypass, since ``FILE_UPLOAD_BYPASS`` is a pure
    status-code check. Caught live: Juice Shop "confirmed" all 4 guessed paths at
    once — a completely made-up path (``/reachagent-cal-<uuid>``) got the exact
    same 204/200 preflight+baseline shape. One canary probe against such a
    guaranteed-nonexistent path, run the same way as a real candidate, detects
    this before any real path is even tried.
    """
    from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence

    canary_path = f"/reachagent-cal-{uuid.uuid4().hex}"
    canary_url = f"{base_url.rstrip('/')}{canary_path}"
    canary_preflight = _fire_readonly(
        firer,
        identity,
        "OPTIONS",
        canary_url,
        events=events,
        label=f"upload {canary_path}/preflight",
        headers=auth_headers,
    )
    if canary_preflight is not None and 200 <= canary_preflight.status_code < 300:
        try:
            canary_baseline = firer.fire(
                identity,
                "POST",
                canary_url,
                state_changing=True,
                headers=dict(auth_headers),
                files={"file": ("ok.txt", b"reachagent baseline", "text/plain")},
            )
        except Exception:  # noqa: BLE001 — a genuinely refused canary is not a catch-all
            canary_baseline = None
        if canary_baseline is not None and 200 <= canary_baseline.status_code < 300:
            _emit(
                events,
                "payloads",
                "not-applicable",
                "file_upload: target accepts OPTIONS/POST on an arbitrary "
                "nonexistent path — generic catch-all response, real upload "
                "endpoints cannot be distinguished this way",
            )
            return []

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
    from reachagent.confirmation.corroboration import corroborate_with_variant
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
        for index, (ref, name) in enumerate(_FORGED):
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
            if not verdict.is_violation:
                continue
            # Technique-diversity corroboration (v3 V3): when another forgery
            # technique remains, it must ALSO be accepted before trusting a
            # single hit — rules out a one-off accept (a proxy/cache oddity
            # on this one token) rather than a genuinely broken validator.
            # No new session/state/risk: one more read-only GET at the same,
            # already-scoped URL.
            forged_label = name
            confirmed = True
            remaining = [(r, n) for r, n in _FORGED[index + 1 :] if _TEMPLATES.get(r)]
            if remaining:
                ref2, name2 = remaining[0]

                def _second_attempt(
                    _ref2: str = ref2,
                    _name2: str = name2,
                    _url: str = url,
                    _label: str = label,
                    _baseline_status: int = baseline.status_code,
                    _path: str = path,
                ) -> object:
                    probe2 = _fire_readonly(
                        firer,
                        identity,
                        "GET",
                        _url,
                        events=events,
                        label=f"{_label}/{_name2}/corroborate",
                        headers={**auth_headers, "Authorization": f"Bearer {_TEMPLATES[_ref2]}"},
                    )
                    if probe2 is None:
                        return SimpleNamespace(is_violation=False)
                    return seam.run(
                        OracleMechanism.STRUCTURAL,
                        StructuralEvidence(
                            check_type=StructuralCheckType.JWT_FORGERY,
                            baseline_status=_baseline_status,
                            probe_status=probe2.status_code,
                            evidence_ref=f"orchestrator/jwt_forgery/{_name2}{_path}",
                        ),
                    )

                result = corroborate_with_variant(verdict, _second_attempt)
                confirmed = result.corroborated
                if confirmed:
                    forged_label = f"{name}+{name2}"
            if confirmed and seam.last is not None:
                nid = seam.write(
                    "jwt_forgery", seam.last, severity="high", metadata={"forged": forged_label}
                )
                if nid:
                    found.append(nid)
                    _emit(
                        events,
                        "payloads",
                        "finding",
                        f"jwt forgery accepted ({forged_label})",
                        path=path,
                    )
            break
        # Not recorded as Suspected: every variant rejected is the expected outcome for
        # correctly-implemented JWT validation, not a lead — see the note in run_nosqli.
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
#
# v2 W5 (widen candidate generation): several named operator-bypass variants are
# tried in sequence per parameter, mirroring run_jwt_forgery's already-established
# multi-variant pattern (_FORGED, above) — a WAF/input filter that strips one
# operator ($ne) may not catch another ($regex/$exists), and a filter that blocks
# one LDAP wildcard shape may miss another. Every variant still only ever produces
# an oracle-confirmed Finding or nothing; this widens what's ATTEMPTED, never what
# counts as proof.
_NOSQL_BYPASS_VALUES: tuple[tuple[str, str], ...] = (
    ('{"$ne": null}', "ne-null"),
    ('{"$ne": ""}', "ne-empty"),
    ('{"$gt": ""}', "gt-empty"),
    ('{"$regex": ".*"}', "regex-wildcard"),
    ('{"$exists": true}', "exists-true"),
)
_NOSQL_TIMING_VALUE = '{"$where": "sleep(5000)"}'
_LDAP_BYPASS_VALUES: tuple[tuple[str, str], ...] = (
    ("*)(uid=*))(|(uid=*", "wildcard-classic"),
    ("*)(|(objectClass=*))", "objectclass-wildcard"),
    ("admin)(&(password=*))", "admin-password-bypass"),
    ("*)(|(cn=*))", "cn-wildcard"),
)
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
    derived_identities: list[Any] | None = None,
) -> list[str]:
    """NoSQL injection via the dedicated detector — auth-bypass first, timing fallback.

    ``derived_identities`` (v2 W17, optional): when a confirmed auth-bypass's probe
    response carries real, reusable session material (not just a 2xx), a
    ``DerivedIdentityLead`` is appended for the caller to spawn + re-hunt at the
    Phase-3→4 boundary — never acted on here. ``bypass_identity_hint`` was previously
    computed by the detector and silently dropped by this driver; this is that gap closed.
    """
    from reachagent.nosql.detector import (
        AuthBypassProbe,
        NoSqliProber,
        TimingProbe,
        detect_nosqli,
    )
    from reachagent.oracles.differential import Observation
    from reachagent.scan.chaining import DerivedIdentityLead, capture_bypass_session
    from reachagent.tools.explorer_context import ExplorerContext

    ctx = ExplorerContext(
        graph=graph, firer=firer, library=library or _library(), base_url=base_url
    )
    found: list[str] = []

    def _probe(ep: Endpoint, param: Any) -> None:
        fire = _fire_value_fn(ctx, identity, base_url, ep, param)
        last_bypass_result: Any = None

        def _obs(value: str, label: str) -> Observation:
            nonlocal last_bypass_result
            result = fire(value)
            if label == "injected":
                last_bypass_result = result
            body = result.body.decode("utf-8", errors="replace") if result is not None else ""
            status = result.status_code if result is not None else 0
            return Observation(label=label, status_code=status, body=body)

        def _no_timing_signal() -> TimingProbe:
            # Identical latencies -> the statistical oracle can never confirm from
            # this call, with no live delay probe fired at all (v2 W5): only the
            # LAST bypass variant below actually exercises the real timing fallback,
            # so trying several bypass variants doesn't multiply timing-flakiness
            # risk or redundant network traffic.
            return TimingProbe((50.0,) * _TIMING_TRIALS, (50.0,) * _TIMING_TRIALS)

        def _real_timing() -> TimingProbe:
            probe_ms, baseline_ms = _paired_timing(fire, _NOSQL_TIMING_VALUE)
            return TimingProbe(probe_ms, baseline_ms)

        # v2 W5: try several named operator-bypass variants in sequence — a WAF/
        # input filter that strips one operator ($ne) may not catch another
        # ($regex/$exists). First confirmation wins; the real timing fallback runs
        # only once, on the final variant, if none of the bypasses confirmed.
        for index, (bypass_value, variant_name) in enumerate(_NOSQL_BYPASS_VALUES):
            is_last = index == len(_NOSQL_BYPASS_VALUES) - 1

            def fire_auth_bypass(bypass_value: str = bypass_value) -> AuthBypassProbe:
                return AuthBypassProbe(
                    baseline=_obs("baseline", "benign"),
                    probe=_obs(bypass_value, "injected"),
                )

            prober = NoSqliProber(
                fire_auth_bypass=fire_auth_bypass,
                fire_timing=_real_timing if is_last else _no_timing_signal,
                oracle_runner=seam.run,
            )
            result = detect_nosqli(
                prober, evidence_ref=f"orchestrator/nosqli {ep.path} {param.name}:{variant_name}"
            )
            if result.confirmed and seam.last is not None:
                mech = result.mechanism.value if result.mechanism is not None else "unknown"
                nid = seam.write(
                    "nosqli",
                    seam.last,
                    severity="high",
                    metadata={"mechanism": mech, "variant": variant_name},
                )
                if nid:
                    _emit(
                        events,
                        "payloads",
                        "finding",
                        f"nosqli via {mech} ({variant_name})",
                        path=ep.path,
                        param=param.name,
                    )
                    found.append(nid)
                    if (
                        derived_identities is not None
                        and result.bypass_identity_hint
                        and last_bypass_result is not None
                    ):
                        body_text = last_bypass_result.body.decode("utf-8", errors="replace")
                        captured = capture_bypass_session(last_bypass_result, body_text)
                        if captured is not None:
                            derived_identities.append(
                                DerivedIdentityLead(
                                    finding_id=nid,
                                    vuln_class="nosqli",
                                    role_hint=result.bypass_identity_hint,
                                    captured=captured,
                                )
                            )
                break
        # Note: a non-confirm here is the NORMAL, expected outcome for a properly-secured
        # parameter (every auth-bypass variant + timing all found nothing) — it is NOT a
        # "suspected lead" and must not be recorded as one (that would flood the Suspected
        # tier with every clean parameter on every scan). The Suspected tier is reserved
        # for a genuine external assertion (a signal-gated tool's claim) that couldn't be
        # reconfirmed — see `_make_signal_reconfirm`'s `_suspect` helper.

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
    derived_identities: list[Any] | None = None,
) -> list[str]:
    """LDAP injection via the dedicated detector — wildcard auth-bypass, timing fallback.

    No OOB path: LDAP has no out-of-band channel (§5) — the detector omits it.

    ``derived_identities`` (v2 W17, optional): same as ``run_nosqli`` — a confirmed
    auth-bypass whose probe response carries real session material queues a
    ``DerivedIdentityLead`` for the caller to spawn + re-hunt at the Phase-3→4 boundary.
    """
    from reachagent.ldap.detector import (
        AuthBypassProbe,
        LdapiProber,
        TimingProbe,
        detect_ldapi,
    )
    from reachagent.oracles.differential import Observation
    from reachagent.scan.chaining import DerivedIdentityLead, capture_bypass_session
    from reachagent.tools.explorer_context import ExplorerContext

    ctx = ExplorerContext(
        graph=graph, firer=firer, library=library or _library(), base_url=base_url
    )
    found: list[str] = []

    def _probe(ep: Endpoint, param: Any) -> None:
        fire = _fire_value_fn(ctx, identity, base_url, ep, param)
        last_bypass_result: Any = None

        def _obs(value: str, label: str) -> Observation:
            nonlocal last_bypass_result
            result = fire(value)
            if label == "wildcard-inject":
                last_bypass_result = result
            body = result.body.decode("utf-8", errors="replace") if result is not None else ""
            status = result.status_code if result is not None else 0
            return Observation(label=label, status_code=status, body=body)

        def _no_timing_signal() -> TimingProbe:
            # See run_nosqli's identical helper: identical latencies never confirm,
            # with no live delay probe fired — only the final variant below
            # exercises the real timing fallback (v2 W5).
            return TimingProbe((50.0,) * _TIMING_TRIALS, (50.0,) * _TIMING_TRIALS)

        def _real_timing() -> TimingProbe:
            probe_ms, baseline_ms = _paired_timing(fire, _LDAP_TIMING_VALUE)
            return TimingProbe(probe_ms, baseline_ms)

        # v2 W5: try several named wildcard/filter-injection variants in sequence —
        # a filter that blocks one LDAP wildcard shape may miss another.
        for index, (bypass_value, variant_name) in enumerate(_LDAP_BYPASS_VALUES):
            is_last = index == len(_LDAP_BYPASS_VALUES) - 1

            def fire_auth_bypass(bypass_value: str = bypass_value) -> AuthBypassProbe:
                return AuthBypassProbe(
                    baseline=_obs("baseline", "benign-bind"),
                    probe=_obs(bypass_value, "wildcard-inject"),
                )

            prober = LdapiProber(
                fire_auth_bypass=fire_auth_bypass,
                fire_timing=_real_timing if is_last else _no_timing_signal,
                oracle_runner=seam.run,
            )
            result = detect_ldapi(
                prober,
                evidence_ref=f"orchestrator/ldap_injection {ep.path} {param.name}:{variant_name}",
            )
            if result.confirmed and seam.last is not None:
                mech = result.mechanism.value if result.mechanism is not None else "unknown"
                nid = seam.write(
                    "ldap_injection",
                    seam.last,
                    severity="high",
                    metadata={"mechanism": mech, "variant": variant_name},
                )
                if nid:
                    _emit(
                        events,
                        "payloads",
                        "finding",
                        f"ldap injection via {mech} ({variant_name})",
                        path=ep.path,
                        param=param.name,
                    )
                    found.append(nid)
                    if (
                        derived_identities is not None
                        and result.bypass_identity_hint
                        and last_bypass_result is not None
                    ):
                        body_text = last_bypass_result.body.decode("utf-8", errors="replace")
                        captured = capture_bypass_session(last_bypass_result, body_text)
                        if captured is not None:
                            derived_identities.append(
                                DerivedIdentityLead(
                                    finding_id=nid,
                                    vuln_class="ldap_injection",
                                    role_hint=result.bypass_identity_hint,
                                    captured=captured,
                                )
                            )
                break
        # Not recorded as Suspected: a non-confirm here is the expected, common outcome for
        # a properly-secured parameter, not a lead — see the matching note in run_nosqli.

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
        # Not recorded as Suspected: a non-confirm here is the expected, common outcome for
        # a properly-secured parameter, not a lead — see the matching note in run_nosqli.

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

        # Technique-diversity corroboration (v3 V3): a second, DIFFERENT
        # redirect-shaped parameter on the SAME endpoint, only when one
        # exists — rules out one parameter's own quirk rather than a
        # systemic unsanitized-redirect issue. Endpoints with only one
        # redirect-shaped parameter stay single-probe (no second candidate
        # exists to corroborate against — an honest, disclosed limit, not a
        # fabricated one).
        fire_second_probe = None
        second_param_name = ""
        if len(redirect_params) > 1:
            second_param_name = redirect_params[1].name
            second_label = f"open_redirect {ep.path}?{second_param_name}"
            second_probe_url = f"{base_url.rstrip('/')}{ep.path}?{second_param_name}={target}"

            def _fire_second_probe(
                _url: str = second_probe_url, _label: str = second_label
            ) -> RedirectProbe:
                response = _fire_readonly(
                    firer, identity, "GET", _url, events=events, label=_label, headers=auth_headers
                )
                if response is None:
                    return RedirectProbe()
                return RedirectProbe(
                    status=response.status_code,
                    location=str(response.headers.get("location", "")),
                )

            fire_second_probe = _fire_second_probe

        prober = OpenRedirectProber(
            fire_probe=_fire_probe,
            probe_target=target,
            oracle_runner=seam.run,
            fire_second_probe=fire_second_probe,
            second_param_name=second_param_name,
        )
        result = detect_open_redirect(prober, evidence_ref=f"orchestrator/open_redirect{ep.path}")
        if result.confirmed and seam.last is not None:
            metadata = {"param": param_name}
            if result.corroborated:
                metadata["corroborated_param"] = second_param_name
            nid = seam.write("open_redirect", seam.last, severity="medium", metadata=metadata)
            if nid:
                found.append(nid)
                message = f"open redirect — {param_name} echoed into Location"
                if result.corroborated:
                    message += f" (corroborated via {second_param_name})"
                _emit(events, "payloads", "finding", message, path=ep.path)

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

    Corroborated (Build Order 5): TIMING_STATISTICAL is this session's own
    confirmed weak spot (a live hermetic run produced a false positive here
    under heavy concurrent system load, then passed cleanly in isolation —
    exactly the network/system-jitter noise the precision review flagged).
    A first confirmed attempt triggers up to 2 more independent full timing
    runs (fresh trials each time, not a reuse of the first), requiring 2-of-3
    agreement before writing the finding — a one-off skewed measurement no
    longer writes a finding by itself. Each attempt is still independently
    oracle-gated; corroboration only decides whether to trust the aggregate.
    """
    from reachagent.confirmation.corroboration import corroborate
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
    evidence_ref = f"orchestrator/request_smuggling/{target.host}:{target.port}"

    def _fire_timing() -> SmugglingTimingProbe:
        probe_ms, baseline_ms = fire_timing_trials(target)
        return SmugglingTimingProbe(probe_latencies_ms=probe_ms, baseline_latencies_ms=baseline_ms)

    def _one_attempt() -> bool:
        prober = SmugglingProber(fire_timing=_fire_timing, oracle_runner=seam.run)
        return detect_request_smuggling(prober, evidence_ref=evidence_ref).confirmed

    if not _one_attempt():
        _emit(events, "payloads", "not-applicable", "request_smuggling: no CL.TE timing signal")
        return found
    # The first attempt already confirmed once; corroborate() runs up to 2
    # MORE fresh attempts (max_attempts=3 total including this one already
    # counted as the first agreement) and only proceeds on 2-of-3 agreement.
    corroboration = corroborate(_one_attempt, required_agreements=1, max_attempts=2)
    total_attempts = 1 + corroboration.attempts
    total_agreements = 1 + corroboration.agreements
    if corroboration.corroborated and seam.last is not None:
        nid = seam.write("request_smuggling", seam.last, severity="high")
        if nid:
            found.append(nid)
            _emit(
                events,
                "payloads",
                "finding",
                f"request smuggling — CL.TE desync confirmed via timing "
                f"({total_agreements}/{total_attempts} independent runs agreed)",
                path="/",
            )
    else:
        _emit(
            events,
            "payloads",
            "not-applicable",
            "request_smuggling: initial timing signal did not reproduce on corroboration",
        )
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


def run_cloud_bucket_exposure(
    *,
    graph: ReachabilityGraph,
    seam: _ValidatorSeam,
    events: list[ScanEvent],
    transport: httpx.BaseTransport | None = None,
) -> list[str]:
    """Probe generated cloud-bucket-name candidates for public listing (§7, §10).

    Mirrors ``run_subdomain_takeover``: every candidate bucket host is a
    third-party cloud-storage domain (S3/GCS/Azure) derived from the
    target's own hostname, never the target itself, so this deliberately
    does not go through ``RequestFirer`` — the same reasoning that gives
    this class its own dedicated transport outside the firer. Never
    state-changing (GET only); every probe URL and outcome is narrated into
    the live event feed since it bypasses the firer's own audit.
    """
    from reachagent.cloud_bucket.detector import (
        BucketProbe,
        BucketProber,
        candidate_bucket_probes,
        detect_cloud_bucket_exposure,
    )

    found: list[str] = []
    seen_hostnames: set[str] = set()
    for _node, host in graph.hosts():
        hostname = host.hostname or host.address
        if not hostname or hostname in seen_hostnames:
            continue
        seen_hostnames.add(hostname)
        probes = candidate_bucket_probes(hostname)
        if not probes:
            continue
        _emit(
            events,
            "payloads",
            "step",
            f"cloud_bucket_exposure: trying {len(probes)} generated bucket names for {hostname}",
        )

        def _fire_probe(url: str) -> BucketProbe:
            try:
                with httpx.Client(
                    transport=transport, timeout=10.0, follow_redirects=True
                ) as client:
                    response = client.get(url)
                return BucketProbe(status=response.status_code, body=response.text)
            except httpx.HTTPError:
                return BucketProbe(status=0, body="")

        prober = BucketProber(fire_probe=_fire_probe, oracle_runner=seam.run)
        result = detect_cloud_bucket_exposure(
            prober, probes=probes, evidence_ref=f"orchestrator/cloud_bucket_exposure/{hostname}"
        )
        if result.confirmed and seam.last is not None:
            nid = seam.write("cloud_bucket_exposure", seam.last, severity="high")
            if nid:
                found.append(nid)
                _emit(
                    events,
                    "payloads",
                    "finding",
                    f"cloud bucket publicly listable — {result.exposed_url}",
                    path=hostname,
                )
                break  # one confirmed exposure per scan is enough
    if not found:
        _emit(
            events,
            "payloads",
            "not-applicable" if seen_hostnames else "info",
            "cloud_bucket_exposure: no generated bucket name was publicly listable",
        )
    return found


def run_known_vulnerable_version(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    seam: _ValidatorSeam,
    events: list[ScanEvent],
) -> list[str]:
    """Fingerprinted version + live NVD lookup -> known-CVE structural check
    (§7 Build Order 4, hexstrike-ai audit refinement).

    Reads the graph's own already-fingerprinted ``Host.technology``/
    ``detected_version`` (a whatweb/recon fact — no new probing here) and
    asks NVD whether that exact product/version has known CVEs. A version
    with no known CVEs is not applicable, not worth an oracle call — same
    "generate/look up candidates, ask the oracle only about ones already
    worth it" shape as ``run_cloud_bucket_exposure``. When matches exist,
    one live re-probe confirms the RAW fingerprinted version substring
    (never the full reconstructed "product/version" banner, which the
    live text may not format identically) is genuinely present right now,
    not stale graph data from an earlier recon pass, before writing a
    finding.
    """
    from reachagent.cve_intel.detector import (
        VersionProbe,
        VersionProber,
        detect_known_vulnerable_version,
    )
    from reachagent.cve_intel.nvd_client import enrich_with_epss, lookup_cves

    found: list[str] = []
    technology = ""
    version = ""
    for _node, host in graph.hosts():
        if host.technology and host.detected_version:
            technology, version = host.technology, host.detected_version
            break
    if not technology or not version:
        _emit(
            events,
            "payloads",
            "not-applicable",
            "known_vulnerable_version: no fingerprinted product+version in the graph",
        )
        return found

    matches = tuple(lookup_cves(technology, version))
    if not matches:
        _emit(
            events,
            "payloads",
            "not-applicable",
            f"known_vulnerable_version: no known CVEs for {technology} {version}",
        )
        return found
    matches = tuple(enrich_with_epss(list(matches)))

    def _fire_probe() -> VersionProbe:
        result = firer.fire(identity, "GET", base_url)
        haystack = f"{dict(result.headers)}\n{result.body.decode('utf-8', errors='replace')}"
        return VersionProbe(status=result.status_code, haystack=haystack)

    prober = VersionProber(fire_probe=_fire_probe, oracle_runner=seam.run)
    result = detect_known_vulnerable_version(
        prober,
        version_string=version,
        cve_matches=matches,
        evidence_ref=f"orchestrator/known_vulnerable_version/{base_url}",
    )
    if result.confirmed and seam.last is not None:
        worst = max((match.cvss_score or 0.0 for match in result.matches), default=0.0)
        severity = "critical" if worst >= 9.0 else "high" if worst >= 7.0 else "medium"
        metadata = {
            "cve_ids": ",".join(match.cve_id for match in result.matches),
            "worst_cvss": str(worst),
            "epss_scores": ",".join(
                f"{match.cve_id}={match.epss_score:.3f}"
                for match in result.matches
                if match.epss_score is not None
            ),
        }
        nid = seam.write(
            "known_vulnerable_version", seam.last, severity=severity, metadata=metadata
        )
        if nid:
            found.append(nid)
            _emit(
                events,
                "payloads",
                "finding",
                f"known-vulnerable version {technology} {version} — "
                f"{len(result.matches)} CVE match(es)",
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
        # Technique-diversity corroboration (v3 V3): a THIRD identity, when
        # configured, corroborates a confirmed write against a second,
        # independent non-owner session — ruling out the first non-owner
        # having its own unrelated delegated access to this one object.
        # Fired lazily inside detect_idor, only if the primary already
        # confirms — most scans only configure 2 identities, so this stays
        # None (single-probe, unchanged) in the common case.
        second_non_owner = next((nid for nid in auth_ok if nid not in (owner, non_owner)), None)
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

            fire_second_probe = None
            if second_non_owner is not None:

                def _fire_second_probe(
                    _identity: str = second_non_owner,
                    _method: str = ep.method,
                    _url: str = url,
                    _kwargs: dict[str, object] = fire_kwargs,
                    _sub_label: str = f"{label}/second-non-owner",
                ) -> IdorProbe:
                    try:
                        second_result = firer.fire(_identity, _method, _url, **_kwargs)
                    except Exception as exc:  # noqa: BLE001, S112 — a refused probe is not a violation
                        _emit(
                            events,
                            "payloads",
                            "error",
                            f"{_sub_label} refused ({type(exc).__name__})",
                        )
                        return IdorProbe(non_owner_status=0)
                    return IdorProbe(non_owner_status=second_result.status_code)

                fire_second_probe = _fire_second_probe

            prober = IdorProber(
                fire_probe=_fire_probe, oracle_runner=seam.run, fire_second_probe=fire_second_probe
            )
            result = detect_idor(prober, evidence_ref=f"orchestrator/{label}")
            if result.confirmed and seam.last is not None:
                metadata = {"path": concrete_path}
                if result.corroborated and second_non_owner is not None:
                    metadata["corroborated_identity"] = second_non_owner
                nid = seam.write("idor", seam.last, severity="critical", metadata=metadata)
                if nid:
                    found.append(nid)
                    message = f"idor — cross-user write succeeded at {concrete_path}"
                    if result.corroborated:
                        message += f" (corroborated via {second_non_owner})"
                    _emit(events, "payloads", "finding", message, path=concrete_path)

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

    def _suspect(candidate: Any, reason: str) -> None:
        # W2: a signal-gated tool (nuclei/sqlmap/dalfox) CLAIMED this, but the oracle did not
        # (or could not) independently confirm it. Never a Finding — surface it as a suspected
        # lead for manual review instead of silently dropping the tool's claim on the floor.
        try:
            graph.add_suspected_finding(
                SuspectedFinding(
                    vuln_class=str(candidate.vuln_class),
                    endpoint=str(getattr(candidate, "endpoint_node", "")),
                    location=str(getattr(candidate, "param_node", "") or ""),
                    source="signal-gated-tool",
                    reason=reason,
                    severity="info",
                )
            )
        except Exception as exc:  # noqa: BLE001 — a suspected-tier write must never break the scan
            _emit(
                events,
                "verification",
                "error",
                f"suspected-tier write skipped: {type(exc).__name__}",
            )

    def _reconfirm(candidate: Any) -> object:
        builder = _RECONFIRM_BUILDERS.get((candidate.vuln_class, candidate.suggested_oracle))
        if builder is None:
            # The tool flagged a class/oracle pair we have no deterministic re-check for.
            _suspect(candidate, "no_oracle_for_class")
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
            _suspect(candidate, "reconfirm_probe_failed")
            return None
        if evidence is None:
            _suspect(candidate, "reconfirm_probe_unavailable")
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
        else:
            # Oracle ran on the tool's claim and did NOT confirm — the classic
            # "scanner says vuln, proof says no" case → suspected, not dropped.
            _suspect(candidate, "scanner_claim_unverified")
        return node_id

    return _reconfirm


# ---------------------------------------------------------------------------
# Phase 3 dispatch — driver factory + concurrent specialist spawning (2c)
# ---------------------------------------------------------------------------

# Bounded, not unbounded (plan §2c): a fixed cap on how many specialist
# children can run at once. Four is exactly the number of non-"auth"
# specialist groups in _SPECIALIST_OF_CLASS today (client_side/injection/
# protocol/api_logic) — if the taxonomy ever grows past four, extra groups
# simply queue for a free worker slot, which is the correct bounded
# behavior, not a limitation to raise reactively.
_MAX_CONCURRENT_SPECIALISTS = 4


def _build_phase3_drivers(
    *,
    graph: ReachabilityGraph,
    seam: _ValidatorSeam,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    auth_headers: Mapping[str, str],
    identities: IdentityStore | None,
    transport: httpx.BaseTransport | None,
    library: Any,
    allow_cross_user_writes: bool,
    events: list[ScanEvent],
    derived_identities: list[Any] | None = None,
) -> dict[str, Callable[[], None]]:
    """Build the class_name -> driver-call dict, bound to one (graph, seam) pair.

    Extracted from the sequential dispatch loop (Build Order 2c) so it can be
    called once for the parent graph (unchanged sequential path) and once
    per specialist child with a child-scoped graph/seam — the only two
    things that ever differ between an invocation; every other argument
    (firer/identity/auth_headers/identities/transport/library) is shared
    read-mostly state, safe across concurrent children (see the Build Order
    2c prerequisite fix to TokenStore/IdentityStore locking).

    ``derived_identities`` (v2 W17, optional): threaded only into nosqli/ldap — the
    two classes whose detectors already document an auth-bypass-derives-credentials
    intent. Deliberately left unwired in the concurrent-specialist path (each
    `_run_phase3_concurrent` child omits it): the sequential dispatch already covers
    the single scan-wide re-hunt this increment supports, and NOT sharing a mutable
    list across concurrently-running child threads keeps this new capability from
    touching Build Order 2c's already-adversarially-reviewed thread-safety guarantees.
    """
    from reachagent.scan.prototype_pollution import run_prototype_pollution
    from reachagent.scan.xss_dom import run_xss_dom

    def _run_authz_bola_if_identities() -> None:
        if identities is not None:
            run_authz_bola(
                graph=graph,
                base_url=base_url,
                identities=identities,
                events=events,
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
                events=events,
                allow_cross_user_writes=allow_cross_user_writes,
            )

    return {
        "default_credentials": lambda: run_default_credentials(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events,
        ),
        "rate_limit_absence": lambda: run_rate_limit_absence(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events,
        ),
        "structural_headers": lambda: run_structural_headers(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            seam=seam,
            events=events,
        ),
        "file_upload": lambda: run_file_upload(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            seam=seam,
            events=events,
        ),
        "mass_assignment": lambda: run_mass_assignment(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            seam=seam,
            events=events,
        ),
        "xss_stored": lambda: run_xss_stored(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            seam=seam,
            events=events,
        ),
        "open_redirect": lambda: run_open_redirect(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            seam=seam,
            events=events,
        ),
        "cache_poisoning": lambda: run_cache_poisoning(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            seam=seam,
            events=events,
        ),
        "request_smuggling": lambda: run_request_smuggling(
            base_url=base_url,
            seam=seam,
            events=events,
        ),
        "subdomain_takeover": lambda: run_subdomain_takeover(
            graph=graph,
            seam=seam,
            events=events,
            transport=transport,
        ),
        "cloud_bucket_exposure": lambda: run_cloud_bucket_exposure(
            graph=graph,
            seam=seam,
            events=events,
            transport=transport,
        ),
        "known_vulnerable_version": lambda: run_known_vulnerable_version(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events,
        ),
        "jwt_forgery": lambda: run_jwt_forgery(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            seam=seam,
            events=events,
        ),
        "sqli_blind": lambda: run_sqli_blind(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events,
            library=library,
        ),
        "nosqli": lambda: run_nosqli(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events,
            library=library,
            derived_identities=derived_identities,
        ),
        "ldap": lambda: run_ldap(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events,
            library=library,
            derived_identities=derived_identities,
        ),
        "command_injection": lambda: run_command_injection(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events,
            library=library,
        ),
        "authz_bola": _run_authz_bola_if_identities,
        "authz_idor": _run_authz_idor_if_identities,
        "graphql": lambda: run_graphql(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events,
            identities=identities,
        ),
        "business_logic": lambda: run_business_logic(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events,
        ),
        "race": lambda: run_race(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events,
        ),
        "xxe": lambda: run_xxe(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            seam=seam,
            events=events,
        ),
        "xss_dom": lambda: run_xss_dom(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events,
        ),
        "prototype_pollution": lambda: run_prototype_pollution(
            graph=graph,
            firer=firer,
            base_url=base_url,
            identity=identity,
            seam=seam,
            events=events,
        ),
    }


def _dispatch_classes(
    classes: tuple[str, ...],
    *,
    graph: ReachabilityGraph,
    drivers: dict[str, Callable[[], None]],
    events: list[ScanEvent],
    operator_prompt: str | None,
    cancel_check: object | None,
    check_cancel: Callable[[object | None], None],
    touch: Callable[[], None],
    label: str = "",
) -> None:
    """Continuous re-rank-then-dispatch loop (Build Order 2), scoped to
    exactly ``classes`` and one (graph, drivers) pair. Shared by the
    sequential Phase-3 path and each Build Order 2c specialist child so
    both use identical dispatch semantics — a child is just this same loop
    running against a narrower class list and its own graph snapshot.

    ``touch`` is called once per dispatched class (real, visible work just
    happened — an LLM call, HTTP probes — so the idle-timeout clock must
    refresh here, not only at the end of the whole class list; that was a
    real bug, fixed earlier). ``AdaptiveControlState`` itself is confirmed
    unsynchronized (Build Order 2c prerequisite research), so a caller
    running several of these concurrently MUST pass a lock-wrapped
    ``touch`` — never ``control_state.touch`` directly — see
    ``_run_phase3_concurrent``.

    Termination is guaranteed regardless of what the LLM proposes: exactly
    one class is consumed from ``remaining`` per iteration, so this cannot
    loop or stall the way an open-ended tool-selection loop could — no
    loop-guard needed.
    """
    from reachagent.scan.agentic_loop import ControlError

    remaining = list(classes)
    current_specialist: str | None = None
    prefix = f"[{label}] " if label else ""
    while remaining:
        check_cancel(cancel_check)
        ranked_order, rank_reason = rank_vuln_classes(
            tuple(remaining), graph, operator_prompt=operator_prompt
        )
        class_name = ranked_order[0]
        # rank_vuln_classes never drops/invents a class — ranked_order is
        # exactly `remaining`, reordered — so the tail is already the next
        # remaining set with no further filtering needed.
        remaining = list(ranked_order[1:])
        _emit(
            events,
            "payloads",
            "info",
            f"{prefix}next: {class_name} — {rank_reason}",
            remaining=len(remaining),
        )
        specialist = _SPECIALIST_OF_CLASS.get(class_name, "general")
        if specialist != current_specialist:
            current_specialist = specialist
            _emit(
                events,
                "payloads",
                "info",
                f"{prefix}{_SPECIALIST_LABELS.get(specialist, specialist)} — starting",
                specialist=specialist,
            )
        try:
            drivers[class_name]()
        except ControlError:
            raise
        except Exception as exc:  # noqa: BLE001 — one class's driver crashing (a
            # malformed/oversized live response, an unexpected edge case) must
            # never cost every OTHER vuln class its chance to run — caught live:
            # crAPI's cache_poisoning driver hit an oversized response body and
            # took the entire remaining Phase 3 pipeline down with it.
            _log.warning("class driver %r failed: %s", class_name, exc)
            _emit(
                events,
                "payloads",
                "error",
                f"{prefix}{class_name}: driver failed ({exc}) — continuing with remaining classes",
            )
        touch()


def _run_attack_path_chain(
    *,
    lead: Any,
    graph: ReachabilityGraph,
    seam: _ValidatorSeam,
    firer: RequestFirer,
    base_url: str,
    auth_headers: Mapping[str, str],
    identities: IdentityStore,
    transport: httpx.BaseTransport | None,
    library: Any,
    allow_cross_user_writes: bool,
    events: list[ScanEvent],
    cancel_check: object | None,
    check_cancel: Callable[[object | None], None],
    control_state: Any,
) -> list[str]:
    """Spawn ``lead``'s derived identity, run browser recon under it (v2 Phase 6 Stage
    C — surfaces any admin-only rendered link/form the new privilege unlocks), then
    re-hunt ALL Phase-3 classes — exactly ONE pass, never recursive (v2 W17). Returns
    the new finding ids, each already linked back to ``lead.finding_id`` via an
    ``enables`` edge so the report's existing chain rendering (``chain_paths``) shows
    the causal path.
    """
    from reachagent.scan.chaining import spawn_derived_identity

    spawned = spawn_derived_identity(
        identities, firer, graph, role_hint=lead.role_hint, captured=lead.captured
    )
    if spawned is None:
        _emit(
            events,
            "payloads",
            "info",
            f"attack-path chaining: {lead.vuln_class} yielded credentials but the "
            "spawn/registration failed — no re-hunt",
        )
        return []
    new_identity, session_node = spawned
    graph.add_derived_credential(lead.finding_id, session_node)
    _emit(
        events,
        "payloads",
        "finding",
        f"attack-path chain: confirmed {lead.vuln_class} yielded new credentials — "
        f"re-hunting as {new_identity}",
        finding=lead.finding_id,
        derived_identity=new_identity,
    )
    before = {fid for fid, _ in graph.findings()}
    new_auth_headers = identities.auth_headers(new_identity)

    # v2 Phase 6 Stage C: re-run browser recon (W11) under the NEW identity, before
    # re-hunting — narrows (doesn't fully close) the disclosed "re-hunts only
    # already-discovered endpoints" limit. An admin-only nav link a SPA only renders
    # for an elevated session becomes a real Endpoint fact here (drivers read
    # graph.endpoints() fresh at call time, so endpoint-level STRUCTURAL checks below
    # can test it this same pass); its parameters are NOT auto-fingerprinted, so
    # per-parameter injection classes still won't test it until a separate
    # fingerprinting pass runs — same disclosed limit run_browser_recon's form path
    # already has. Not a general crawler/brute-force replacement — an endpoint
    # nothing on any rendered page links to is still invisible. Fail-open, same
    # discipline as every other browser_recon call site.
    try:
        from reachagent.scan.browser_recon import run_browser_recon

        new_endpoints = run_browser_recon(
            graph=graph, firer=firer, base_url=base_url, identity=new_identity, events=events
        )
        if new_endpoints:
            _emit(
                events,
                "payloads",
                "info",
                f"attack-path chain: browser recon as {new_identity} surfaced "
                f"{new_endpoints} new endpoint(s)",
            )
    except Exception as exc:  # noqa: BLE001 — browser recon must never abort the chain
        _emit(
            events,
            "payloads",
            "error",
            f"attack-path chain browser recon failed: {type(exc).__name__}",
            error_category="browser_recon",
        )

    rehunt_drivers = _build_phase3_drivers(
        graph=graph,
        seam=seam,
        firer=firer,
        base_url=base_url,
        identity=new_identity,
        auth_headers=new_auth_headers,
        identities=identities,
        transport=transport,
        library=library,
        allow_cross_user_writes=allow_cross_user_writes,
        events=events,
        # Deliberately no derived_identities here — bounded to ONE re-hunt pass,
        # never a chain-of-chains, per the plan's explicit "bounded depth" line.
    )
    _dispatch_classes(
        _PHASE3_CLASS_ORDER,
        graph=graph,
        drivers=rehunt_drivers,
        events=events,
        operator_prompt=None,
        cancel_check=cancel_check,
        check_cancel=check_cancel,
        touch=control_state.touch,
        label=f"chain:{new_identity}",
    )
    new_ids = [fid for fid, _ in graph.findings() if fid not in before]
    for new_id in new_ids:
        graph.add_enables(lead.finding_id, new_id)
    return new_ids


def _run_phase3_concurrent(
    *,
    graph: ReachabilityGraph,
    seam: _ValidatorSeam,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    auth_headers: Mapping[str, str],
    identities: IdentityStore | None,
    transport: httpx.BaseTransport | None,
    library: Any,
    allow_cross_user_writes: bool,
    events: list[ScanEvent],
    operator_prompt: str | None,
    cancel_check: object | None,
    check_cancel: Callable[[object | None], None],
    control_state: Any,
) -> None:
    """Build Order 2c: run Phase 3's specialist groups concurrently.

    Dependency-aware scheduling (plan §2c), kept deliberately simple rather
    than a generic per-endpoint dependency graph: "auth" (default_credentials,
    rate_limit_absence, jwt_forgery, authz_bola, authz_idor, mass_assignment)
    runs first, sequentially, on the PARENT graph directly (identical to the
    pre-2c dispatch loop, just scoped to auth's classes) — a defensive,
    forward-looking precaution, not a fix for a dependency that exists in
    the code TODAY: verified by reading every Phase-3 driver, none of them
    (auth included) currently calls the Chain Solver or writes a
    ``derived_credential`` edge mid-Phase-3 — that machinery today runs
    only in Phase 1/2 recon (``scan/entrypoint.py``). ``jwt_forgery``,
    ``nosql/detector.py``, and ``ldap/detector.py`` all separately DOCUMENT
    an intent to spawn one once wired up — and ``nosqli``/``ldap`` currently
    live in the "injection" group, which runs CONCURRENTLY, not
    sequentially-first (an adversarial-review finding, disclosed here
    rather than silently left). If that wiring is completed for any driver
    outside "auth", this grouping must be revisited then — moving the newly
    credential-deriving class into "auth" (or introducing an equivalent
    first-run bucket) — rather than assuming today's split already accounts
    for it.

    The remaining specialists (client_side/injection/protocol/api_logic)
    have no CURRENT dependency on each other, so once auth finishes they run
    concurrently, each against its own deep-copied graph snapshot (the
    plan's chosen default: per-child graph + merge at defined sync points,
    not a lock around every graph mutation — ``ReachabilityGraph``/
    ``AdaptiveControlState`` are confirmed unsynchronized) — bounded to
    ``_MAX_CONCURRENT_SPECIALISTS`` threads, no spawn depth to guard since a
    child never spawns its own children.

    A confirmed finding only becomes visible to a sibling specialist (or the
    parent) once that specialist's thread finishes and merges — a
    disclosed, accepted staleness cost for the simpler, safer default,
    exactly as the plan calls for. A cancelled or crashed specialist still
    merges whatever it found before stopping — cancellation must never lose
    an already-confirmed finding — and one specialist crashing never aborts
    its siblings.
    """
    from reachagent.graph.merge import merge_new_findings
    from reachagent.scan.agentic_loop import ScanCancelled

    auth_classes = tuple(
        class_name
        for class_name in _PHASE3_CLASS_ORDER
        if _SPECIALIST_OF_CLASS.get(class_name) == "auth"
    )
    other_by_specialist: dict[str, list[str]] = {}
    for class_name in _PHASE3_CLASS_ORDER:
        specialist = _SPECIALIST_OF_CLASS.get(class_name, "general")
        if specialist != "auth":
            other_by_specialist.setdefault(specialist, []).append(class_name)

    parent_drivers = _build_phase3_drivers(
        graph=graph,
        seam=seam,
        firer=firer,
        base_url=base_url,
        identity=identity,
        auth_headers=auth_headers,
        identities=identities,
        transport=transport,
        library=library,
        allow_cross_user_writes=allow_cross_user_writes,
        events=events,
    )
    if auth_classes:
        _emit(
            events,
            "payloads",
            "info",
            f"{_SPECIALIST_LABELS.get('auth', 'auth')} — starting (sequential, runs first)",
            specialist="auth",
        )
        _dispatch_classes(
            auth_classes,
            graph=graph,
            drivers=parent_drivers,
            events=events,
            operator_prompt=operator_prompt,
            cancel_check=cancel_check,
            check_cancel=check_cancel,
            touch=control_state.touch,
        )

    if not other_by_specialist:
        return

    _emit(
        events,
        "payloads",
        "info",
        f"fanning out {len(other_by_specialist)} specialist(s) concurrently: "
        + ", ".join(sorted(other_by_specialist)),
    )

    # AdaptiveControlState.touch() is a single unguarded attribute write —
    # confirmed unsynchronized like the rest of the class (Build Order 2c
    # prerequisite research) — so every concurrent specialist thread calls
    # THIS lock-wrapped wrapper instead of control_state.touch directly.
    touch_lock = threading.Lock()

    def _safe_touch() -> None:
        with touch_lock:
            control_state.touch()

    def _run_one(
        specialist: str, classes: tuple[str, ...]
    ) -> tuple[str, ReachabilityGraph, list[ScanEvent], str]:
        """Never raises — whatever a child found before stopping (cleanly,
        cancelled, or crashed) is always returned for the parent to merge."""
        child_events: list[ScanEvent] = []
        child_graph = ReachabilityGraph()
        try:
            child_graph = copy.deepcopy(graph)
            child_seam = _ValidatorSeam(child_graph)
            child_drivers = _build_phase3_drivers(
                graph=child_graph,
                seam=child_seam,
                firer=firer,
                base_url=base_url,
                identity=identity,
                auth_headers=auth_headers,
                identities=identities,
                transport=transport,
                library=library,
                allow_cross_user_writes=allow_cross_user_writes,
                events=child_events,
            )
            _dispatch_classes(
                classes,
                graph=child_graph,
                drivers=child_drivers,
                events=child_events,
                operator_prompt=operator_prompt,
                cancel_check=cancel_check,
                check_cancel=check_cancel,
                touch=_safe_touch,
                label=specialist,
            )
            return specialist, child_graph, child_events, "done"
        except ScanCancelled:
            return specialist, child_graph, child_events, "cancelled"
        except Exception as exc:  # noqa: BLE001 — one specialist crashing must not abort its siblings
            _emit(
                child_events,
                "payloads",
                "error",
                f"[{specialist}] specialist crashed: {type(exc).__name__}: {exc}",
                error_category="specialist",
            )
            return specialist, child_graph, child_events, f"error:{type(exc).__name__}"

    max_workers = min(_MAX_CONCURRENT_SPECIALISTS, len(other_by_specialist))
    saw_cancel = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        # ThreadPoolExecutor.submit() does NOT propagate the calling thread's
        # contextvars.Context to the worker thread (confirmed by adversarial
        # review + direct repro) — the GUI's LLM-tuning flags (REACHAGENT_
        # VULN_TUNING and friends) are set via llm.runtime.override()'s
        # ContextVar, never os.environ, so without this every concurrent
        # specialist would silently run with tuning disabled while the
        # sequential auth phase (same thread as the caller) kept it enabled.
        # copy_context() is called ONCE PER SPECIALIST, in this (parent)
        # thread, before submission — a single Context object cannot be
        # .run() from more than one thread at a time, so each specialist
        # needs its own independent snapshot, not one shared across all four.
        futures = {
            pool.submit(contextvars.copy_context().run, _run_one, specialist, tuple(classes)): (
                specialist
            )
            for specialist, classes in other_by_specialist.items()
        }
        for future in concurrent.futures.as_completed(futures):
            _specialist, child_graph, child_events, status = future.result()
            # Relay via .append() (never .extend()) — the GUI's own event
            # buffer overrides only .append() with bounds/heartbeat logic;
            # this runs on the parent thread only, so no lock is needed.
            for event in child_events:
                events.append(event)
            new_ids = merge_new_findings(child_graph, graph)
            _emit(
                events,
                "payloads",
                "info",
                f"[{_specialist}] specialist {status} — {len(new_ids)} new finding(s) merged",
                new_findings=len(new_ids),
            )
            control_state.touch()
            if status == "cancelled":
                saw_cancel = True
    if saw_cancel:
        raise ScanCancelled("scan cancelled by operator")


def _run_llm_vuln_review_pass(
    *, graph: ReachabilityGraph, events_out: list[ScanEvent], label: str
) -> None:
    """One bounded LLM vulnerability-review pass (operator-requested): a Shannon/
    Strix-style pass where the LLM reasons over the discovered surface (structure
    only, not response content — the audit trail never persists bodies) and flags
    what IT independently suspects, the same judgment call those reference tools
    make. The one difference from those tools (the whole point of keeping this
    addition safe): its output can only ever land in the structurally-separate
    Suspected/Unconfirmed tier, never `write_finding`/`run_oracle` — see
    scan/llm_vuln_review.py's module docstring.

    Called twice by `scan_all_classes` (``label`` is "early"/"final", narration
    only) rather than once at the very end: an operator reported LLM-suspected
    leads reading as "dumped all at once" right before the report phase, with
    zero visibility while the scan was still running. The early pass reviews the
    surface once recon completes (before Phase 3 even starts); the final pass
    reviews the fuller surface plus Phase 3's own now-populated confirmed list.
    `run_llm_vulnerability_review` itself reads the OTHER pass's already-written
    leads via "already SUSPECTED" so the two passes don't repeat each other.
    Fail-open — an LLM failure here must never abort the scan.
    """
    try:
        from reachagent.scan.llm_vuln_review import run_llm_vulnerability_review

        new_leads = run_llm_vulnerability_review(graph=graph, events=events_out)
        if new_leads:
            _emit(
                events_out,
                "payloads",
                "info",
                f"LLM vulnerability review ({label}): {new_leads} suspected lead(s) "
                "flagged for manual review (not oracle-verified)",
            )
    except Exception as exc:  # noqa: BLE001 — advisory only, must never abort the scan
        _emit(
            events_out,
            "payloads",
            "error",
            f"LLM vulnerability review ({label}) failed: {type(exc).__name__}",
            error_category="llm_vuln_review",
        )


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
    operator_checkpoint: Callable[[str, str, str], None] | None = None,
    concurrent_specialists: bool = False,
    repo_path: str | None = None,
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

    ``operator_checkpoint``, when given, is called exactly once — right before the
    scan's very first state-changing (non-read-only, non-authentication) request —
    as ``(method, target, identity)``. Intended to block until an operator resumes
    or cancels (the GUI wires this to its existing pause/resume machinery); a scan
    with no operator attached (e.g. a hermetic test) simply omits it.

    ``concurrent_specialists`` (default False, Build Order 2c): when set, Phase 3's
    specialist groups fan out concurrently instead of running one linear sequence —
    "auth" first and sequentially (it can derive credentials/sessions other
    specialists may depend on), then client_side/injection/protocol/api_logic
    concurrently, each against its own graph snapshot, merged back as each
    finishes. Default False preserves the exact prior sequential behavior
    unchanged; see ``_run_phase3_concurrent`` for the full design rationale.

    ``repo_path`` (default None, Build Order 7 — white-box mode): when given,
    an optional local source-repo path, additive to the live black-box scan
    above, never a replacement for it. Runs semgrep/TruffleHog/manifest+NVD
    SCA once, right after recon, writing ``SourceFile``/``Secret``/
    ``PackageDependency``/``StaticAdvisory`` facts into the same graph. A
    ``StaticAdvisory`` (a known-CVE dependency match) is the plan's one
    narrow, explicit exception to "no Finding without a confirmed run_oracle
    result" — it is structurally never a ``Finding`` (see ``graph/nodes.py``)
    and the report keeps it in a visibly separate, "static/unconfirmed-
    reachability" section, never blended with oracle-confirmed findings.
    Every white-box fact also folds into Phase 3's class-priority steering
    signal as an additional hint — order-only, exactly like every other
    tuning signal already there; it never gates or substitutes for oracle
    confirmation of anything.
    """
    from reachagent.scan.agentic_loop import (
        AdaptiveControlLoop,
        AdaptiveControlState,
        DefaultLoopAdvisor,
        IdleTimeout,
        LoopDetected,
        ModelControlError,
        PhaseDecision,
        ScanCancelled,
        check_cancel,
        validate_decision,
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
                # W1: surface the agent's own reasoning into the chat panel, not just the
                # terminal feed, so the conversation reflects what it decided and why. The
                # GUI routes kind="assistant-note" into the chat log; other consumers ignore it.
                if decision.rationale.strip():
                    _emit(
                        events_out,
                        phase,
                        "assistant-note",
                        decision.rationale.strip(),
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
        except (LoopDetected, IdleTimeout) as exc:
            # Graceful termination ("My additions" / PentAGI-style watchdog):
            # a stuck or looping ADAPTIVE decision loop stops adapting, but
            # the deterministic scan underneath is unaffected — every
            # remaining phase/class still runs, just in its default order
            # rather than a further LLM-reordered one. This is deliberately
            # never re-raised, even under require_llm: unlike ModelControlError
            # (the advisor itself is unreachable), the advisor here answered
            # fine — it just kept repeating itself or went idle — so there is
            # nothing to retry, only adaptation left to stop.
            #
            # Auto-prompter refinement (D-CIPHER-style, "My additions"): before
            # falling back to the plain default order, offer the SAME advisor
            # one bounded, best-effort call describing the failure, asking for
            # a revised strategy hint (e.g. "stop reordering the recon phase,
            # move straight to payloads"). Reuses the existing
            # LoopAdvisorClient/validate_decision machinery — no new client
            # protocol, no new flag. Still allowlist-validated by
            # validate_decision, still fails open to no hint on any error.
            hint = ""
            try:
                advisor = control.advisor or DefaultLoopAdvisor()
                raw = advisor.advise(
                    phase,
                    f"Adaptive control loop stopped: {type(exc).__name__}: {exc}",
                    remaining,
                    control.operator_prompt,
                )
                recovery = validate_decision(raw)
                if recovery is not None and recovery.hint:
                    hint = recovery.hint
            except Exception:  # noqa: BLE001 — recovery hint is best-effort, never required
                hint = ""
            if hint:
                control.operator_prompt = (
                    f"{control.operator_prompt[:1_000]}\nRecovery focus: {hint}"
                ).strip()
            _emit(
                events_out,
                phase,
                "control-stopped",
                f"adaptive control loop stopped ({type(exc).__name__}: {exc}) — "
                "continuing with the deterministic default order"
                + (f"; recovery hint applied: {hint}" if hint else ""),
                error_category="control",
            )
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

    # White-box mode (Build Order 7) — additive, never a replacement for the
    # live black-box scan above (§1, §9). Off unless the operator supplied a
    # repo path. Runs once, here, so its facts are available to Phase 3's
    # class-priority steering signal (below) before any payload work starts.
    if repo_path:
        from reachagent.whitebox.analysis import run_whitebox_analysis

        try:
            whitebox_summary = run_whitebox_analysis(repo_path=repo_path, graph=graph, audit=audit)
        except Exception as exc:  # noqa: BLE001 — white-box analysis must never abort the scan
            _emit(
                events_out,
                "endpoints",
                "error",
                f"white-box analysis failed: {type(exc).__name__}: {exc}",
                error_category="whitebox",
            )
        else:
            _emit(
                events_out,
                "endpoints",
                "info",
                "white-box analysis complete — "
                f"{whitebox_summary['source_files']} SAST hit(s), "
                f"{whitebox_summary['secrets']} secret(s), "
                f"{whitebox_summary['package_dependencies']} dependencies, "
                f"{whitebox_summary['static_advisories']} known-CVE match(es)",
                **whitebox_summary,
            )

    # Application-domain inference (v2 W18): one bounded LLM call classifies WHAT the app is
    # (hospital/ecommerce/banking/...) from the observed surface, stored as a host-level
    # advisory fact that steers Phase-3 class priority (order-only, never a gate). Only when
    # LLM is active; fails open to no profile. Set on every host so the signal is stable.
    if require_llm:
        from reachagent.scan.app_domain import classify_app_domain

        app_domain = classify_app_domain(graph)
        if app_domain:
            from dataclasses import replace as _dc_replace

            for _host_node, host in graph.hosts():
                graph.add_host(_dc_replace(host, app_domain=app_domain))  # merge-enrich, order-only
            _emit(
                events_out,
                "endpoints",
                "assistant-note",
                f"This looks like a {app_domain}; I'll prioritize the vuln classes that matter "
                f"most for that kind of app.",
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
        first_state_change_checkpoint=operator_checkpoint,
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

    # General Explorer browser recon (v2 W11) — additive SPA route/form discovery,
    # runs once here (firer/identity now exist), before Phase 3 dispatch, so anything
    # it materializes is part of the graph for the rest of the scan. A SPA's real form
    # surface is invisible to the static HTML parser used earlier (which only sees the
    # empty `<div id="root">` shell a JS framework renders into) — this extends the
    # SAME browser tool already used for XSS taint discovery to general recon. Never a
    # finding; a browser/Playwright failure degrades to a logged event, never aborts
    # the scan (same fail-open discipline as xss_dom/prototype_pollution).
    try:
        from reachagent.scan.browser_recon import run_browser_recon

        new_endpoints = run_browser_recon(
            graph=graph, firer=firer, base_url=base_url, identity=identity, events=events_out
        )
        if new_endpoints:
            _emit(
                events_out,
                "endpoints",
                "info",
                f"browser recon complete — {new_endpoints} SPA-rendered endpoint(s) added",
            )
    except Exception as exc:  # noqa: BLE001 — browser recon must never abort the scan
        _emit(
            events_out,
            "endpoints",
            "error",
            f"browser recon failed: {type(exc).__name__}",
            error_category="browser_recon",
        )

    # LLM-driven vulnerability review, early pass — the surface is fully mapped
    # (recon + browser recon done) but Phase 3 hasn't started, so these leads become
    # visible live well before any confirmed finding does, rather than only ever
    # appearing in one silent batch right before the report phase.
    if require_llm:
        _run_llm_vuln_review_pass(graph=graph, events_out=events_out, label="early")

    # Phase 3 — the classes the sink loop does not drive. Dispatch order is
    # LLM-ranked (rank_vuln_classes, above) when REACHAGENT_VULN_TUNING is
    # enabled — already the case for every GUI scan — falling back to the
    # order below otherwise. Every class still runs regardless; only
    # sequencing is LLM-influenced.
    _emit(events_out, "payloads", "info", "phase 3: structural + authz + advanced classes")

    if concurrent_specialists:
        # Build Order 2c: specialist groups fan out concurrently (auth first
        # and sequentially, then the rest concurrently) — see
        # _run_phase3_concurrent for the full design rationale.
        _run_phase3_concurrent(
            graph=graph,
            seam=seam,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            identities=identities,
            transport=transport,
            library=lib,
            allow_cross_user_writes=allow_cross_user_writes,
            events=events_out,
            operator_prompt=operator_prompt,
            cancel_check=cancel_check,
            check_cancel=check_cancel,
            control_state=control_state,
        )
    else:
        # Default sequential path, byte-for-byte the same dispatch order and
        # semantics as before Build Order 2c — _dispatch_classes is the same
        # continuous re-rank-then-dispatch loop (Build Order 2) extracted so
        # a specialist child can reuse it unchanged.
        derived_identities: list[Any] = []
        phase3_drivers = _build_phase3_drivers(
            graph=graph,
            seam=seam,
            firer=firer,
            base_url=base_url,
            identity=identity,
            auth_headers=auth_headers,
            identities=identities,
            transport=transport,
            library=lib,
            allow_cross_user_writes=allow_cross_user_writes,
            events=events_out,
            derived_identities=derived_identities,
        )
        _dispatch_classes(
            _PHASE3_CLASS_ORDER,
            graph=graph,
            drivers=phase3_drivers,
            events=events_out,
            operator_prompt=operator_prompt,
            cancel_check=cancel_check,
            check_cancel=check_cancel,
            touch=control_state.touch,
        )

        # Attack-path chaining (v2 W17): a confirmed nosqli/ldap auth-bypass that
        # captured REAL session material spawns a fresh synthetic identity and
        # re-hunts under it once — bounded to exactly one re-hunt pass per scan
        # (never a chain-of-chains), and only the FIRST such lead (if several
        # fired) is acted on. Disclosed limit: this re-tests the SAME
        # already-discovered endpoint set under the new identity's privilege — it
        # does not trigger new content discovery, so an admin-only route never
        # crawled unauthenticated stays invisible. Sequential path only (see
        # _build_phase3_drivers's docstring for why the concurrent path omits it).
        if identities is not None and derived_identities:
            _run_attack_path_chain(
                lead=derived_identities[0],
                graph=graph,
                seam=seam,
                firer=firer,
                base_url=base_url,
                auth_headers=auth_headers,
                identities=identities,
                transport=transport,
                library=lib,
                allow_cross_user_writes=allow_cross_user_writes,
                events=events_out,
                cancel_check=cancel_check,
                check_cancel=check_cancel,
                control_state=control_state,
            )

    # Cross-host credential reuse (v3 V4): a credential captured from ANY
    # confirmed finding's evidence this scan tries, once, against every OTHER
    # in-scope host's login form — a genuine gap even the reference projects
    # researched this session don't cover. See cross_host_reuse.py's own
    # docstring for the exact reused-machinery/extraction-scope discipline.
    from reachagent.scan.cross_host_reuse import run_cross_host_credential_reuse

    run_cross_host_credential_reuse(
        graph=graph,
        firer=firer,
        base_url=base_url,
        identity=identity,
        seam=seam,
        events=events_out,
    )

    findings = [fid for fid, _ in graph.findings()]
    _emit(events_out, "payloads", "info", "phase 3 done", findings=len(findings))

    # Findings now exist only if the deterministic oracle accepted them. The
    # model receives a final bounded snapshot and may only schedule/report a
    # follow-up; it cannot alter a finding already in the graph.
    _adapt("payloads", ("report",))

    # LLM-driven vulnerability review, final pass — see _run_llm_vuln_review_pass's
    # own docstring for the full design (operator-requested; two bounded passes, not
    # one, so leads appear live across the scan instead of dumped in a single batch
    # at the end).
    if require_llm:
        _run_llm_vuln_review_pass(graph=graph, events_out=events_out, label="final")

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
        "prototype_pollution",
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
