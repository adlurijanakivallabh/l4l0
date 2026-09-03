"""Hermetic E2E for the IDOR driver: opt-in cross-user write confirmation.

Mirrors the mass_assignment/xss_stored driver harness. Proves: (1) the driver
is a complete no-op without allow_cross_user_writes=True, (2) the owner's own
write must succeed before the non-owner's probe ever fires, (3) confirmation
requires the non-owner's write to actually succeed (not merely execute), and
(4) a correctly-refused non-owner write produces no finding.
"""

from __future__ import annotations

import httpx

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Object, Parameter
from reachagent.graph.store import ReachabilityGraph, identity_id
from reachagent.identity.store import Credential, IdentityStore
from reachagent.scan.orchestrator import _ValidatorSeam, run_authz_idor
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient

_BASE = "http://idor.test"


def _identities() -> IdentityStore:
    store = IdentityStore()
    store.add(Credential("owner", "alice", "pw", "user"))
    store.add(Credential("attacker", "mallory", "pw", "user"))
    store.open_session("owner", "owner-token")
    store.open_session("attacker", "attacker-token")
    return store


def _graph() -> ReachabilityGraph:
    graph = ReachabilityGraph()
    obj = graph.add_object(Object(type="order", sensitivity_tier=2, instance_key="order-42"))
    graph.set_owns(identity_id("owner"), obj)
    ep = graph.add_endpoint(Endpoint(method="PATCH", path="/api/orders/{id}"))
    graph.add_parameter(ep, Parameter(name="status", location="json"))
    return graph


def _firer(handler: object, identities: IdentityStore) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["idor.test"]), identity_stores=identities)


def _run(handler: object, *, allow: bool, graph: ReachabilityGraph | None = None) -> list:
    identities = _identities()
    graph = graph or _graph()
    seam = _ValidatorSeam(graph)
    run_authz_idor(
        graph=graph,
        firer=_firer(handler, identities),
        base_url=_BASE,
        identities=identities,
        seam=seam,
        events=[],
        allow_cross_user_writes=allow,
    )
    return graph.findings()


def _by_bearer(request: httpx.Request) -> str:
    return request.headers.get("authorization", "")


def test_disabled_by_default_never_fires_a_single_request() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, text="ok")

    assert _run(handler, allow=False) == []
    assert seen == []


def test_confirms_when_non_owner_write_succeeds(monkeypatch) -> None:  # noqa: ANN001
    """Confirmation is now an LLM judgment (v3, CLAUDE.md) rather than a fixed
    decide(); _ValidatorSeam.run calls tools.validator.run_oracle with no
    client= passthrough, so pin the verdict by monkeypatching the client
    builder it constructs internally.
    """
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method in ("OPTIONS", "GET"):
            return httpx.Response(200, text="ok")
        return httpx.Response(200, json={"status": "updated"})

    findings = _run(handler, allow=True)
    classes = {f.vuln_class for _fid, f in findings}
    assert "idor" in classes
    assert all(f.status.value == "confirmed_violation" for _fid, f in findings)


def test_non_owner_write_refused_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method in ("OPTIONS", "GET"):
            return httpx.Response(200, text="ok")
        if request.method == "PATCH" and "attacker-token" in _by_bearer(request):
            return httpx.Response(403, json={"error": "forbidden"})
        return httpx.Response(200, json={"status": "updated"})

    assert _run(handler, allow=True) == []


def test_owner_write_failing_skips_without_ever_probing_non_owner() -> None:
    # Both identities' read-only preflights fire eagerly (harmless GETs), but
    # the risky part -- the attacker's actual PATCH -- must never fire.
    writes: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method in ("OPTIONS", "GET"):
            return httpx.Response(200, text="ok")
        writes.append(_by_bearer(request))
        if "owner-token" in _by_bearer(request):
            return httpx.Response(500, text="server error")
        return httpx.Response(200, json={"status": "updated"})

    assert _run(handler, allow=True) == []
    assert not any("attacker-token" in bearer for bearer in writes)


def test_no_read_only_clearance_never_fires_either_write() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        if request.method in ("OPTIONS", "GET"):
            return httpx.Response(404, text="not found")
        return httpx.Response(200, json={"status": "updated"})

    assert _run(handler, allow=True) == []
    assert "PATCH" not in seen


def test_third_identity_wires_corroboration_through(monkeypatch) -> None:  # noqa: ANN001
    """v3 V3 wiring test: when a THIRD identity with a session exists, it is
    threaded through as the corroborating probe and the written finding's
    metadata records which identity corroborated. The corroboration DECISION
    logic itself (a contradicted second probe fails closed) is already
    covered at the detector level in tests/phase2/test_idor_detector.py —
    this only proves the orchestrator wires a third identity through at all.
    """
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )

    identities = _identities()
    identities.add(Credential("second_attacker", "eve", "pw", "user"))
    identities.open_session("second_attacker", "second-attacker-token")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method in ("OPTIONS", "GET"):
            return httpx.Response(200, text="ok")
        return httpx.Response(200, json={"status": "updated"})

    graph = _graph()
    seam = _ValidatorSeam(graph)
    run_authz_idor(
        graph=graph,
        firer=_firer(handler, identities),
        base_url=_BASE,
        identities=identities,
        seam=seam,
        events=[],
        allow_cross_user_writes=True,
    )
    findings = graph.findings()
    assert findings
    _fid, finding = findings[0]
    assert finding.vuln_class == "idor"
    # Which of the two non-owner identities ends up "first" vs. "corroborating"
    # depends on set iteration order (auth_ok is a set, not an ordered list) —
    # not something this wiring test should hardcode. Just prove a THIRD
    # identity's write genuinely corroborated the finding.
    assert finding.metadata.get("corroborated_identity") in {
        identity_id("attacker"),
        identity_id("second_attacker"),
    }


def test_no_second_identity_with_a_session_never_fires() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, text="ok")

    identities = IdentityStore()
    identities.add(Credential("owner", "alice", "pw", "user"))
    identities.open_session("owner", "owner-token")
    graph = _graph()
    seam = _ValidatorSeam(graph)
    run_authz_idor(
        graph=graph,
        firer=_firer(handler, identities),
        base_url=_BASE,
        identities=identities,
        seam=seam,
        events=[],
        allow_cross_user_writes=True,
    )
    assert graph.findings() == []
    assert seen == []
