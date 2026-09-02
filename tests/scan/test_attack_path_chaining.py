"""End-to-end attack-path chaining (v2 W17): confirmed nosqli auth-bypass ->
real session captured -> synthetic identity spawned -> re-hunt -> new finding
linked back via an `enables` edge.

Confirmation itself is deterministic (auth-bypass differential), but `detect_nosqli`
always tries the TIMING fallback too when auth-bypass doesn't confirm — against
/admin/secret under the "anon" identity (no token, so auth-bypass correctly fails),
that fallback runs against a near-zero-latency MockTransport, whose tiny variance can
spuriously cross the timing oracle's significance threshold from pure scheduler jitter
alone. `_TIMING_TRIALS` is bumped exactly like `test_blind_injection_drivers.py`'s own
documented remedy for this — diluting one stray outlier's weight on the mean — not a
workaround for anything wrong in the production code.
"""

from __future__ import annotations

import types

import httpx
import pytest

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter, SinkType
from reachagent.graph.store import ReachabilityGraph, finding_id
from reachagent.identity.store import IdentityStore
from reachagent.scan import orchestrator as _orchestrator
from reachagent.scan.orchestrator import _run_attack_path_chain, _ValidatorSeam, run_nosqli

_BASE = "http://t.test"
_ADMIN_TOKEN = "admin-tok-xyz"
_DENOISED_TRIALS = 40


def _two_endpoint_graph() -> tuple[ReachabilityGraph, str, str]:
    graph = ReachabilityGraph()
    login_ep = graph.add_endpoint(Endpoint(method="GET", path="/login"))
    login_param = graph.add_parameter(login_ep, Parameter(name="user", location="query"))
    graph.set_parameter_sink_type(login_param, SinkType.NOSQL)

    admin_ep = graph.add_endpoint(Endpoint(method="GET", path="/admin/secret"))
    admin_param = graph.add_parameter(admin_ep, Parameter(name="user", location="query"))
    graph.set_parameter_sink_type(admin_param, SinkType.NOSQL)
    return graph, login_ep, admin_ep


def _handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    value = request.url.params.get("user", "")
    injected = ("$ne" in value) or (value.startswith("$") and value != "$")
    auth = request.headers.get("authorization", "")

    if path == "/login":
        # Anyone can bypass /login's auth check; a real session token is granted.
        if value == "baseline" or value.startswith("reachagent-canary"):
            return httpx.Response(401, text="invalid credentials")
        if injected:
            return httpx.Response(200, json={"token": _ADMIN_TOKEN})
        return httpx.Response(401, text="invalid credentials")

    if path == "/admin/secret":
        # Only reachable at all with the admin bearer token (anon always gets a
        # flat 401, so baseline and injected are IDENTICAL for "anon" — no
        # differential, correctly not-confirmable pre-chain). ONCE authenticated
        # as admin, this endpoint has its OWN second nosqli injection point that
        # a plain baseline value can't unlock — the two-layer "SQLi -> admin
        # creds -> a DEEPER bug only reachable as admin" scenario this feature
        # exists for. Genuinely deterministic (403->200 via injection), no
        # timing fallback ever needed.
        if auth != f"Bearer {_ADMIN_TOKEN}":
            return httpx.Response(401)
        if value == "baseline" or value.startswith("reachagent-canary"):
            return httpx.Response(403)
        if injected:
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(403)

    return httpx.Response(404)


def test_confirmed_nosqli_bypass_spawns_identity_and_confirms_a_new_finding_via_chaining(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_orchestrator, "_TIMING_TRIALS", _DENOISED_TRIALS)
    graph, _login_ep, _admin_ep = _two_endpoint_graph()
    identities = IdentityStore()
    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(_handler)),
        ScopeGuard.from_hosts(["t.test"]),
        identity_stores=identities,
    )
    seam = _ValidatorSeam(graph)
    events: list = []
    leads: list = []

    # Phase 3, pass 1: only /login confirms (as "anon" — no auth header at all).
    run_nosqli(
        graph=graph,
        firer=firer,
        base_url=_BASE,
        identity="anon",
        seam=seam,
        events=events,
        derived_identities=leads,
    )
    before_ids = {fid for fid, _ in graph.findings()}
    assert len(before_ids) == 1
    login_finding_id = next(iter(before_ids))
    assert len(leads) == 1

    control_state = types.SimpleNamespace(touch=lambda: None)
    new_ids = _run_attack_path_chain(
        lead=leads[0],
        graph=graph,
        seam=seam,
        firer=firer,
        base_url=_BASE,
        auth_headers={},
        identities=identities,
        transport=None,
        library=None,
        allow_cross_user_writes=False,
        events=events,
        cancel_check=None,
        check_cancel=lambda _c: None,
        control_state=control_state,
    )

    # The admin-only endpoint is now confirmed too — a genuinely NEW finding. The
    # re-hunt dispatches the FULL 24-class order against a near-zero-latency
    # MockTransport, so an unrelated timing-based class (e.g. request_smuggling)
    # can occasionally also fire from pure scheduler jitter — that's a property of
    # exercising every class hermetically, not something this test asserts against;
    # what matters is that the SPECIFIC admin/secret nosqli finding is among the new
    # ones and is correctly linked back. The mock's `injected` check matches the
    # very first bypass variant tried ("$ne": null / "ne-null"), so that's the
    # variant suffix on the confirming evidence_ref (v2 W5 multi-variant probing).
    admin_finding_id = finding_id("nosqli", "orchestrator/nosqli /admin/secret user:ne-null")
    assert admin_finding_id in new_ids
    assert admin_finding_id != login_finding_id

    after = dict(graph.findings())
    assert after[admin_finding_id].vuln_class == "nosqli"

    # Chain edges: derived_credential from the original finding, enables to the new one.
    assert (login_finding_id, admin_finding_id) in graph.enables_edges()
    derived_targets = [
        spawned for fid, spawned in graph.derived_credential_edges() if fid == login_finding_id
    ]
    assert len(derived_targets) == 1
    assert graph.has_node(derived_targets[0])

    # A new synthetic identity genuinely exists in the IdentityStore, not just the graph.
    derived_names = [n for n in identities.names() if n.startswith("derived-")]
    assert len(derived_names) == 1

    # Real chat/report visibility: an event announced the chain.
    assert any("attack-path chain" in e.message for e in events)


def test_chaining_is_a_no_op_when_no_lead_captured_real_session_material() -> None:
    """If /login's bypass never returns real session material, nothing to chain into."""

    def clean_handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("user", "")
        if value == "baseline" or value.startswith("reachagent-canary"):
            return httpx.Response(401)
        if "$ne" in value:
            return httpx.Response(200, json={"ok": True})  # no token, no cookie
        return httpx.Response(401)

    graph, _login_ep, _admin_ep = _two_endpoint_graph()
    identities = IdentityStore()
    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(clean_handler)),
        ScopeGuard.from_hosts(["t.test"]),
        identity_stores=identities,
    )
    seam = _ValidatorSeam(graph)
    leads: list = []
    run_nosqli(
        graph=graph,
        firer=firer,
        base_url=_BASE,
        identity="anon",
        seam=seam,
        events=[],
        derived_identities=leads,
    )
    assert leads == []  # confirmed nosqli, but nothing to spawn from
