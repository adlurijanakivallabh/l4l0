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
from dataclasses import dataclass, field
from itertools import count
from typing import TYPE_CHECKING

import httpx

from reachagent.eval.juiceshop_harness import ChallengeResult, JuiceshopRun, in_scope_class
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


def _fire_post_json(
    mcp: object,
    sess: server._Session,
    identity: str,
    path: str,
    param_name: str,
    payload: str,
) -> str:
    ep = sess.graph.add_endpoint(Endpoint(method="POST", path=path))
    param = sess.graph.add_parameter(ep, Parameter(name=param_name, location="body"))
    fired = _call(
        mcp,
        "fire_request",
        identity=identity,
        endpoint_node=ep,
        param_node=param,
        payload=payload,
        method="POST",
        state_changing=False,
    )
    return str(fired["fire_ref"])


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
) -> bool:
    """Confirm a header-derived structural class (clickjacking / CORS).

    The four framing/CORS response headers are resolved server-side from
    ``probe_fire_ref`` (§10/§13) — only the opaque fire handle and the attacker
    ``probe_origin`` we sent cross the wire, never the headers themselves. On an
    ``is_violation`` verdict, commits the finding via the Validator.
    """
    verdict = _call(
        mcp,
        "run_oracle",
        mechanism="structural",
        evidence={
            "check_type": check_type,
            "probe_fire_ref": probe_fire_ref,
            "probe_origin": probe_origin,
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


def _detect_sqli(target: JuiceshopTarget, token: str | None) -> bool:
    """SQLi: product search q= reflects SQL error on injection — responses_invariant."""
    shared = _SharedState()
    sess = _session_as(target, token, shared)
    mcp = _mcp_for(sess)
    ep = sess.graph.add_endpoint(Endpoint(method="GET", path="/rest/products/search"))
    param = sess.graph.add_parameter(ep, Parameter(name="q", location="query"))
    _call(mcp, "fingerprint_parameter", identity="anon", endpoint_node=ep, param_node=param)
    baseline = _call(
        mcp,
        "fire_request",
        identity="anon",
        endpoint_node=ep,
        param_node=param,
        payload="apple",
        method="GET",
    )
    probe = _call(
        mcp,
        "fire_request",
        identity="anon",
        endpoint_node=ep,
        param_node=param,
        payload="'",
        method="GET",
    )
    return _confirm_differential(
        mcp,
        vuln_class="sqli",
        axis="cross_condition",
        expectation="responses_invariant",
        baseline_ref=str(baseline["fire_ref"]),
        probe_ref=str(probe["fire_ref"]),
        evidence_ref="sqli/search-q",
    )


def _detect_path_traversal(target: JuiceshopTarget, token: str | None) -> bool:
    """Path traversal: /ftp/<filename> — structural sentinel check via fire_ref."""
    shared = _SharedState()
    sess = _session_as(target, token, shared)
    mcp = _mcp_for(sess)
    ep = sess.graph.add_endpoint(Endpoint(method="GET", path="/ftp/{filename}"))
    param = sess.graph.add_parameter(ep, Parameter(name="filename", location="path"))
    _call(mcp, "fingerprint_parameter", identity="anon", endpoint_node=ep, param_node=param)
    baseline = _call(
        mcp,
        "fire_request",
        identity="anon",
        endpoint_node=ep,
        param_node=param,
        payload="legal.md",
        method="GET",
    )
    probe = _call(
        mcp,
        "fire_request",
        identity="anon",
        endpoint_node=ep,
        param_node=param,
        payload="../../etc/passwd",
        method="GET",
    )
    return _confirm_structural(
        mcp,
        vuln_class="path_traversal",
        check_type="path_traversal",
        baseline_status=int(str(baseline.get("status_code", 0))),
        probe_status=int(str(probe.get("status_code", 0))),
        sentinel="root:",
        probe_fire_ref=str(probe["fire_ref"]),
        evidence_ref="path_traversal/ftp",
    )


def _detect_file_upload(target: JuiceshopTarget, token: str | None) -> bool:
    """File upload bypass: /file-upload — multipart probe, structural status check."""
    shared = _SharedState()
    sess = _session_as(target, token, shared)
    mcp = _mcp_for(sess)
    ep = sess.graph.add_endpoint(Endpoint(method="POST", path="/file-upload"))
    param = sess.graph.add_parameter(ep, Parameter(name="file", location="body"))
    _call(mcp, "fingerprint_parameter", identity="user", endpoint_node=ep, param_node=param)
    baseline = _call(
        mcp,
        "fire_request",
        identity="user",
        endpoint_node=ep,
        param_node=param,
        payload="test.jpg",
        method="POST",
        state_changing=True,
        upload={"filename": "test.jpg", "content": "GIF89a", "content_type": "image/jpeg"},
    )
    probe = _call(
        mcp,
        "fire_request",
        identity="user",
        endpoint_node=ep,
        param_node=param,
        payload="evil.exe",
        method="POST",
        state_changing=True,
        upload={
            "filename": "evil.exe",
            "content": "MZ\x90\x00",
            "content_type": "application/octet-stream",
        },
    )
    return _confirm_structural(
        mcp,
        vuln_class="file_upload",
        check_type="file_upload_bypass",
        baseline_status=int(str(baseline.get("status_code", 0))),
        probe_status=int(str(probe.get("status_code", 0))),
        sentinel="",
        probe_fire_ref=str(probe["fire_ref"]),
        evidence_ref="file_upload/upload",
    )


def _detect_xss_stored(target: JuiceshopTarget, token: str | None) -> bool:
    """Stored XSS: POST feedback comment, GET read-back — execution_confirmation via fire_ref."""
    shared = _SharedState()
    sess = _session_as(target, token, shared)
    mcp = _mcp_for(sess)
    tag = "XSSREACH42"
    ep_w = sess.graph.add_endpoint(Endpoint(method="POST", path="/api/Feedbacks"))
    param_w = sess.graph.add_parameter(ep_w, Parameter(name="comment", location="body"))
    _call(mcp, "fingerprint_parameter", identity="anon", endpoint_node=ep_w, param_node=param_w)
    _call(
        mcp,
        "fire_request",
        identity="anon",
        endpoint_node=ep_w,
        param_node=param_w,
        payload=f"<script>{tag}</script>",
        method="POST",
        state_changing=True,
        extra_fields={"rating": 1},
    )
    ep_r = sess.graph.add_endpoint(Endpoint(method="GET", path="/api/Feedbacks"))
    param_r = sess.graph.add_parameter(ep_r, Parameter(name="probe", location="query"))
    _call(mcp, "fingerprint_parameter", identity="anon", endpoint_node=ep_r, param_node=param_r)
    readback = _call(
        mcp,
        "fire_request",
        identity="anon",
        endpoint_node=ep_r,
        param_node=param_r,
        payload="",
        method="GET",
    )
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
        return False
    _call(mcp, "write_finding", verdict_ref=str(verdict["verdict_ref"]), vuln_class="xss")
    return True


def _detect_clickjacking(target: JuiceshopTarget, token: str | None) -> bool:
    """Clickjacking: GET the app root, confirm no effective framing defense.

    ``X-Frame-Options`` / CSP ``frame-ancestors`` are read from the captured
    response server-side (resolved from the fire_ref); both absent → framable.
    Read-only GET.
    """
    shared = _SharedState()
    sess = _session_as(target, token, shared)
    mcp = _mcp_for(sess)
    fire_ref = _fire_get(mcp, sess, "anon", "/")
    return _confirm_structural_headers(
        mcp,
        vuln_class="clickjacking",
        check_type="clickjacking",
        probe_fire_ref=fire_ref,
        evidence_ref="clickjacking/root",
    )


def _detect_cors(target: JuiceshopTarget, token: str | None) -> bool:
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
    return _confirm_structural_headers(
        mcp,
        vuln_class="cors_misconfig",
        check_type="cors_misconfig",
        probe_fire_ref=fire_ref,
        evidence_ref="cors/root",
        probe_origin=attacker_origin,
    )


# ---------------------------------------------------------------------------
# Scoring — per-challenge via a tracker before/after delta.
# ---------------------------------------------------------------------------


def _detection_oracle_fired(detections: dict[str, bool], scope_class: str) -> bool:
    """Whether ReachAgent's class-level oracle confirmed a finding for this class.

    A per-class signal (one detector runs per class), kept only to distinguish
    "we ran and confirmed the class exists" from "we never exercised it". It is
    deliberately NOT used to mark individual challenges confirmed — that is what
    the old class-to-all mapping did, and it inflated false positives.
    """
    return detections.get(scope_class, False)


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
    §14/§15). Consequence of delta attribution: a confirmed challenge is by
    construction also solved, so the false-positive rate is 0 until per-challenge
    exploit claims exist — the binding metric here is coverage, which now reports
    the genuine fraction of in-scope challenges ReachAgent actually caused to solve.
    """
    before = fetch_tracker(target)

    detections: dict[str, bool] = {
        "injection": _detect_sqli(target, token),
        "path_traversal": _detect_path_traversal(target, token),
        "file_upload": _detect_file_upload(target, token),
        "xss": _detect_xss_stored(target, token),
        "clickjacking": _detect_clickjacking(target, token),
        "cors": _detect_cors(target, token),
    }
    # Silence the unused-variable check while keeping the class-level signal
    # available for future per-challenge attribution work.
    _ = detections

    after = fetch_tracker(target)
    run = JuiceshopRun()
    for ch_key, ch_info in after.items():
        category = str(ch_info["category"])
        scope_class = in_scope_class(category)
        if scope_class is None:
            continue
        solved_after = bool(ch_info["solved"])
        solved_before = bool(before.get(ch_key, {}).get("solved", False))
        newly_solved = solved_after and not solved_before
        run.results.append(
            ChallengeResult(
                vuln_class=scope_class,
                challenge_key=ch_key,
                confirmed=newly_solved,
                tracker_solved=solved_after,
            )
        )
    return run
