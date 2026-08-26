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
caller** — the same documented seam as ``eval/portswigger_blind_sqli.py``: it injects
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
from collections.abc import Mapping
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

_log = logging.getLogger(__name__)

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
    "csrf_missing_protection",
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
    """Validator-side seam (portswigger precedent): real run_oracle / write_finding.

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
        token = identities.token_store(name).get_token()
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return name, headers
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
    probe = each precomputed forged token (none-alg / HS256-key-confusion / weak-secret)
    from the tagged library. A forged token accepted (2xx) is the violation.
    """
    from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence
    from reachagent.payloads.payload_resolver import _TEMPLATES

    _FORGED = (
        ("jwt_forgery/none-alg", "none-alg"),
        ("jwt_forgery/hs256-key-confusion", "hs256-key-confusion"),
        ("jwt_forgery/weak-secret", "weak-secret"),
    )
    found: list[str] = []
    valid_token = next((v for v in auth_headers.values() if v), "")  # e.g. "Bearer x"
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
    for name in names:
        token = identities.token_store(name).get_token()
        if not token:
            continue
        id_ = identity_id(name)
        if id_ in owners:
            owner_tokens[id_] = token
        else:
            non_owner_tokens[id_] = token
    if not owner_tokens or not non_owner_tokens:
        _emit(events, "payloads", "not-applicable", "bola/bfla: no owner+non-owner token pair")
        return []
    result = bola_detector.detect(
        graph,
        base_url,
        owner_tokens=owner_tokens,
        non_owner_tokens=non_owner_tokens,
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

    tokens: list[tuple[str, str]] = []
    if identities is not None:
        tokens = [
            (name, identities.token_store(name).get_token() or "")
            for name in identities.names()
            if identities.token_store(name).get_token()
        ]
    if len(tokens) < 2:
        _emit(events, "payloads", "not-applicable", "graphql: resolver-BOLA needs ≥2 identities")
        return []
    owner_id = tokens[0][0]
    non_owner_id = tokens[1][0]
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
    """
    from reachagent.business_logic.runner import SequentialReplayRunner
    from reachagent.business_logic.templates import instantiate_all

    instantiated = instantiate_all(graph)
    if not instantiated.checks:
        _emit(
            events,
            "payloads",
            "not-applicable",
            "business_logic: no coupon/quantity/price/flow resources in the graph",
        )
        return []
    runner = SequentialReplayRunner(firer, base_url)
    found: list[str] = []
    for check in instantiated.checks:
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
) -> dict[str, Any]:
    """Run the validated multi-phase LLM-driven loop over ALL attack classes.

    Phase 1+2+3-sink reuse ``scan_target`` (cold-start recon, api_discovery, the generic
    sink-matched payload chain). The remaining classes run through their deterministic
    drivers above. Every finding is ``run_oracle → is_violation → write_finding``.
    ``library`` is built once and shared by ``scan_target`` and the blind-SQLi driver.
    ``graph``/``audit`` may be injected so the caller holds live references to the state
    the scan is writing (the GUI streams them while the scan runs).
    """
    from reachagent.scan.entrypoint import detect_target_type, scan_target

    events_out = events if events is not None else []
    execution_plan = None
    planned_recon_tools: tuple[str, ...] | None = None
    planned_signal_tools: tuple[str, ...] = ()
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
        )

        lib_for_plan = library if library is not None else _library()
        entries = getattr(lib_for_plan, "all_entries", lambda: ())()
        payload_refs = tuple(
            str(getattr(entry, "payload_ref", ""))
            for entry in entries[:100]
            if getattr(entry, "payload_ref", "")
        )
        target_type = detect_target_type(base_url)
        context = PlanningContext(
            target=base_url,
            target_type=target_type,
            in_scope=tuple(part.strip() for part in in_scope.split(",") if part.strip()),
            graph_facts={"phase": "recon", "target": base_url},
            operator_prompt=operator_prompt or "",
            payload_refs=payload_refs,
            max_request_budget=max(1, max_attempts),
            max_tool_budget=16,
        )
        own_client = planner_client is None
        plan_client = planner_client or build_planner_client()
        try:
            execution_plan = plan_execution(context, plan_client)
        finally:
            if own_client and hasattr(plan_client, "close"):
                plan_client.close()
        catalog_by_name = {entry.name: entry for entry in build_tool_catalog()}
        recon_names: list[str] = []
        signal_names: list[str] = []
        for phase in execution_plan.phases:
            for tool_name in phase.tools:
                if catalog_by_name[tool_name].signal_gated:
                    signal_names.append(tool_name)
                else:
                    recon_names.append(tool_name)
        planned_recon_tools = tuple(dict.fromkeys(recon_names))
        planned_signal_tools = tuple(dict.fromkeys(signal_names))
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
                    "profile": phase.profile,
                    "vuln_classes": list(phase.vuln_classes),
                    "payload_refs": list(phase.payload_refs),
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
                vuln_classes=list(phase.vuln_classes),
                payload_refs=list(phase.payload_refs),
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
        live_recon=live_recon,
        events=events_out,
        transport=transport,
        library=lib,
        graph=graph,
        audit=audit,
    )
    graph = result["graph"] if graph is None else graph
    audit = result["audit"] if audit is None else audit
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
        operator_prompt=operator_prompt,
    )
    if priority is not None:
        from reachagent.tools.coordinator_support import set_surface_priority
        set_surface_priority(priority.ranked_ids)
        _emit(
            events_out,
            "endpoints",
            "step",
            f"LLM surface prioritization: {priority.rationale}",
            ranked_count=len(priority.ranked_ids),
            ranked_ids=list(priority.ranked_ids[:10]),
        )

    scope = ScopeGuard.from_raw(in_scope, out_of_scope)
    from reachagent.recon.signal_dispatch import run_signal_tools

    run_signal_tools(
        tool_names=planned_signal_tools,
        graph=graph,
        scope=scope,
        audit=audit,
        target=base_url,
        emit=lambda phase, kind, message, **details: _emit(
            events_out, phase, kind, message, **details
        ),
        live_recon=live_recon,
    )
    identity_headers: dict[str, dict[str, str]] = {}
    if identities is not None:
        for name in identities.names():
            token = identities.token_store(name).get_token()
            if token:
                identity_headers[name] = {"Authorization": f"Bearer {token}"}
    firer = RequestFirer(
        httpx.Client(transport=transport) if transport is not None else httpx.Client(),
        scope,
        audit,
        identity_headers=identity_headers,
    )
    seam = _ValidatorSeam(graph)
    identity, auth_headers = _identity_for_scan(identities, events_out)

    # Phase 3 — the classes the sink loop does not drive.
    _emit(events_out, "payloads", "info", "phase 3: structural + authz + advanced classes")
    run_structural_headers(
        graph=graph,
        firer=firer,
        base_url=base_url,
        identity=identity,
        auth_headers=auth_headers,
        seam=seam,
        events=events_out,
    )
    run_file_upload(
        graph=graph,
        firer=firer,
        base_url=base_url,
        identity=identity,
        auth_headers=auth_headers,
        seam=seam,
        events=events_out,
    )
    run_jwt_forgery(
        graph=graph,
        firer=firer,
        base_url=base_url,
        identity=identity,
        auth_headers=auth_headers,
        seam=seam,
        events=events_out,
    )
    run_sqli_blind(
        graph=graph,
        firer=firer,
        base_url=base_url,
        identity=identity,
        seam=seam,
        events=events_out,
        library=lib,
    )
    if identities is not None:
        run_authz_bola(
            graph=graph,
            base_url=base_url,
            identities=identities,
            events=events_out,
            transport=transport,
        )
    run_graphql(
        graph=graph,
        firer=firer,
        base_url=base_url,
        identity=identity,
        seam=seam,
        events=events_out,
        identities=identities,
    )
    run_business_logic(
        graph=graph,
        firer=firer,
        base_url=base_url,
        identity=identity,
        seam=seam,
        events=events_out,
    )

    from reachagent.scan.xss_dom import run_xss_dom

    run_xss_dom(
        graph=graph,
        firer=firer,
        base_url=base_url,
        identity=identity,
        seam=seam,
        events=events_out,
    )

    findings = [fid for fid, _ in graph.findings()]
    _emit(events_out, "payloads", "info", "phase 3 done", findings=len(findings))
    driven_classes = {
        *_GENERIC_CLASSES,
        "clickjacking",
        "cors_misconfig",
        "csrf_missing_protection",
        "file_upload",
        "jwt_forgery",
        "bola",
        "bfla",
        "graphql",
        "business_logic",
        "sqli_blind",
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
    return {
        "graph": graph,
        "audit": audit,
        "findings": findings,
        "events": events_out,
    }
