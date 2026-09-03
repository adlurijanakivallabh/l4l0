"""Hermetic E2E for the stored-XSS driver: write + independent reread.

Mirrors test_mass_assignment_driver.py's harness. Proves: (1) the write only
fires after its own read-only-first clearance, and (2) confirmation reads an
INDEPENDENT re-fetch of the resource — the tag must appear there, not merely
in the write's own response body.
"""

from __future__ import annotations

import json

import httpx

from reachagent.detection.oracle_gateway import OracleOutcome
from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.identity.store import Credential, IdentityStore
from reachagent.oracles.base import OracleVerdict
from reachagent.scan.orchestrator import _ValidatorSeam, run_xss_stored
from tests._oracle_test_support import CONFIRMS, INCONCLUSIVE, FixedJudgmentClient

_BASE = "http://xs.test"


def _real_stored_evidence_run(
    self: _ValidatorSeam, mechanism: object, evidence: object
) -> OracleOutcome:
    """v3 V3: judges on the real payload_tag-in-response_body content (DOM
    flows are always empty in this driver, so DOM never confirms) instead of
    a blanket fixed verdict — needed to reach the STORED corroboration path
    at all, since a flat confirm would let the DOM leg (tried first in
    detect_xss) confirm before the stored path is ever exercised."""
    tag = getattr(evidence, "payload_tag", "") or ""
    body = getattr(evidence, "response_body", "") or ""
    status = CONFIRMS if tag and tag in body else INCONCLUSIVE
    ref = str(getattr(evidence, "evidence_ref", "") or "")
    verdict = OracleVerdict(
        mechanism=mechanism, status=status, evidence_ref=ref, reason="test-fixed-verdict"
    )
    self._last = verdict
    return OracleOutcome(verdict)


def _graph() -> ReachabilityGraph:
    graph = ReachabilityGraph()
    write_ep = graph.add_endpoint(Endpoint(method="POST", path="/comments"))
    graph.add_parameter(write_ep, Parameter(name="username", location="json"))
    graph.add_parameter(write_ep, Parameter(name="body", location="json"))
    graph.add_endpoint(Endpoint(method="GET", path="/comments/{id}"))
    return graph


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["xs.test"]))


def _run(handler: object) -> list:
    graph = _graph()
    seam = _ValidatorSeam(graph)
    run_xss_stored(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        auth_headers={},
        seam=seam,
        events=[],
    )
    return graph.findings()


def test_confirms_when_tag_reflects_in_independent_reread(monkeypatch) -> None:  # noqa: ANN001
    # v3 (CLAUDE.md): confirmation is now an LLM judgment, not the removed
    # decide() logic. seam.run -> validator.run_oracle has no client= seam to
    # inject through here, so fix the LLM provider factory that
    # llm_judgment.judge() falls back to — this test then asserts WIRING
    # (a confirmed verdict flows through to graph.findings()), not judgment
    # itself.
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )
    captured: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method in ("OPTIONS", "GET") and request.url.path == "/comments":
            return httpx.Response(200, text="ok")
        if request.method == "POST":
            captured.append(json.loads(request.content))
            return httpx.Response(200, json={"status": "created"})
        if request.method == "GET":
            # Independent reread: the injected script tag reflects unencoded.
            injected = captured[0]["body"]
            return httpx.Response(200, text=f"<p>{injected}</p>")
        return httpx.Response(404)

    findings = _run(handler)
    classes = {f.vuln_class for _fid, f in findings}
    assert "xss_stored" in classes
    assert all(f.status.value == "confirmed_violation" for _fid, f in findings)


def test_second_identity_wires_corroboration_through(monkeypatch) -> None:  # noqa: ANN001
    """v3 V3 wiring test: when a SECOND identity with a session exists, it is
    threaded through as the corroborating independent reader and the written
    finding's metadata records the corroboration. The corroboration DECISION
    logic itself (a contradicted second read fails closed) is already covered
    at the detector level in tests/phase3/test_xss_detector.py — this only
    proves the orchestrator wires a second identity through at all."""
    monkeypatch.setattr(_ValidatorSeam, "run", _real_stored_evidence_run)

    identities = IdentityStore()
    identities.add(Credential("anon", "anon", "pw", "user"))
    identities.add(Credential("second_reader", "second_reader", "pw", "user"))
    identities.open_session("anon", "anon-token")
    identities.open_session("second_reader", "second-token")

    captured: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method in ("OPTIONS", "GET") and request.url.path == "/comments":
            return httpx.Response(200, text="ok")
        if request.method == "POST":
            captured.append(json.loads(request.content))
            return httpx.Response(200, json={"status": "created"})
        if request.method == "GET":
            injected = captured[0]["body"]
            return httpx.Response(200, text=f"<p>{injected}</p>")
        return httpx.Response(404)

    graph = _graph()
    seam = _ValidatorSeam(graph)
    run_xss_stored(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        auth_headers={},
        seam=seam,
        events=[],
        identities=identities,
    )
    findings = graph.findings()
    assert findings
    _fid, finding = findings[0]
    assert finding.vuln_class == "xss_stored"
    assert finding.metadata.get("corroborated") == "1"


def test_secure_target_encodes_payload_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method in ("OPTIONS", "GET") and request.url.path == "/comments":
            return httpx.Response(200, text="ok")
        if request.method == "POST":
            return httpx.Response(200, json={"status": "created"})
        if request.method == "GET":
            # The server HTML-encoded the payload before persisting/rendering.
            return httpx.Response(200, text="<p>&lt;script&gt;safe&lt;/script&gt;</p>")
        return httpx.Response(404)

    assert _run(handler) == []


def test_no_read_only_clearance_never_fires_the_write() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        if request.method in ("OPTIONS", "GET"):
            return httpx.Response(404, text="not found")  # no clearance
        return httpx.Response(200, json={"status": "created"})

    assert _run(handler) == []
    assert "POST" not in seen  # the write genuinely never fired


def test_no_sibling_read_endpoint_skips_without_firing() -> None:
    graph = ReachabilityGraph()
    write_ep = graph.add_endpoint(Endpoint(method="POST", path="/comments"))
    graph.add_parameter(write_ep, Parameter(name="body", location="json"))
    # No sibling GET endpoint anywhere in the graph.

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, text="ok")

    seam = _ValidatorSeam(graph)
    run_xss_stored(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        auth_headers={},
        seam=seam,
        events=[],
    )
    assert graph.findings() == []
    assert seen == []  # never even reached the preflight


def test_sequencing_is_preflight_then_write_then_independent_reread() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.method in ("OPTIONS", "GET") and request.url.path == "/comments":
            return httpx.Response(200, text="ok")
        if request.method == "POST":
            return httpx.Response(200, json={"status": "created"})
        return httpx.Response(200, text="<script>reflected</script>")

    _run(handler)
    methods = [m for m, _p in seen]
    assert methods[0] in ("OPTIONS", "GET")  # preflight first
    assert "POST" in methods
    write_index = methods.index("POST")
    assert write_index < len(methods) - 1  # a reread follows the write
    # The reread is a genuinely separate GET, not the write's own response.
    assert methods[write_index + 1] == "GET"
    assert seen[write_index + 1][1] != "/comments"


def test_json_body_carries_the_resolved_canary_payload() -> None:
    captured: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method in ("OPTIONS", "GET") and request.url.path == "/comments":
            return httpx.Response(200, text="ok")
        if request.method == "POST":
            captured.append(json.loads(request.content))
            return httpx.Response(200, json={"status": "created"})
        return httpx.Response(200, text="<p>safe</p>")

    _run(handler)
    assert captured
    payload_body = captured[0]
    # The non-identifier field (body) carries the <script>{canary}</script> payload;
    # username stays legit — it's what the reread URL is resolved from.
    assert payload_body["body"].startswith("<script>") and payload_body["body"].endswith(
        "</script>"
    )
    assert "username" in payload_body  # the identifier field is untouched
