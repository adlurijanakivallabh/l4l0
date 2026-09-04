"""End-to-end attack-path chaining (v2 W17): confirmed nosqli auth-bypass ->
real session captured -> synthetic identity spawned -> re-hunt -> new finding
linked back via an `enables` edge.

Confirmation itself used to be deterministic (auth-bypass differential); v3
(CLAUDE.md) replaced that with LLM judgment (`oracles/llm_judgment.py`). This
file's own tests need MULTIPLE distinct verdicts within a single run (e.g.
/login's real bypass must confirm, while "anon" hitting /admin/secret — both
baseline and probe correctly 401 with no admin token — must NOT) — a single
flat fixed-verdict fake would spuriously confirm everything, so
`_DifferentialJudge` below reproduces the OLD deterministic differential
semantics (probe reached 2xx, baseline did not => confirmed_violation) by
parsing the real evidence JSON handed to the judgment prompt, not a
model call. `detect_nosqli` always tries the TIMING fallback too when
auth-bypass doesn't confirm; `_DifferentialJudge` also sees that evidence
shape and correctly returns inconclusive for it (it never carries a
baseline/probe status pair), matching the desired "never spuriously confirm
from timing noise" behavior `_TIMING_TRIALS` was already bumped for.
"""

from __future__ import annotations

import json
import re
import types

import httpx
import pytest

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Finding, FindingStatus, Parameter, SinkType
from reachagent.graph.store import ReachabilityGraph, finding_id
from reachagent.identity.store import IdentityStore
from reachagent.scan import orchestrator as _orchestrator
from reachagent.scan.chaining import DerivedIdentityLead
from reachagent.scan.orchestrator import (
    _run_attack_path_chain,
    _run_attack_path_chains_concurrent,
    _ValidatorSeam,
    run_nosqli,
)

_BASE = "http://t.test"
_ADMIN_TOKEN = "admin-tok-xyz"
_DENOISED_TRIALS = 40

_EVIDENCE_JSON_RE = re.compile(r"Evidence \(JSON.*?\):\n(\{.*\})\n\n", re.DOTALL)


class _DifferentialJudge:
    """Fake LLM client reproducing differential decide()'s exact semantics.

    confirmed_violation only when the probe reached a 2xx status and the
    baseline did not — the same rule the removed decide() applied. Any other
    evidence shape (e.g. PairedTrialEvidence's timing fields, which have no
    baseline/probe status pair) safely falls through to inconclusive.
    """

    def propose_json(self, prompt: str, *, max_tokens: int = 500) -> dict:
        match = _EVIDENCE_JSON_RE.search(prompt)
        if not match:
            return {"status": "inconclusive", "reason": "no evidence parsed"}
        evidence = json.loads(match.group(1))
        baseline_status = (evidence.get("baseline") or {}).get("status_code", 0)
        probe_status = (evidence.get("probe") or {}).get("status_code", 0)
        if 200 <= probe_status < 300 and not (200 <= baseline_status < 300):
            return {"status": "confirmed_violation", "reason": "probe 2xx, baseline was not"}
        return {"status": "inconclusive", "reason": "no differential observed"}


def _patch_judgment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "reachagent.oracles.llm_judgment.build_openai_compatible_client",
        lambda: _DifferentialJudge(),
    )


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
    _patch_judgment(monkeypatch)
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


def _lead_from_first_pass(monkeypatch: pytest.MonkeyPatch) -> tuple:
    """Shared setup: run pass 1 to get a real DerivedIdentityLead, everything else
    the caller needs to drive _run_attack_path_chain directly."""
    _patch_judgment(monkeypatch)
    monkeypatch.setattr(_orchestrator, "_TIMING_TRIALS", _DENOISED_TRIALS)
    graph, _login_ep, _admin_ep = _two_endpoint_graph()
    identities = IdentityStore()
    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(_handler)),
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
    assert len(leads) == 1
    return graph, identities, firer, seam, leads[0]


def test_attack_path_chain_runs_browser_recon_under_the_new_derived_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v2 Phase 6 Stage C: the chain re-runs browser recon under the FRESHLY
    DERIVED identity (not the original anon one) before re-hunting."""
    graph, identities, firer, seam, lead = _lead_from_first_pass(monkeypatch)
    calls: list[str] = []

    def fake_browser_recon(*, graph, firer, base_url, identity, events):  # noqa: ANN001
        calls.append(identity)
        return 0

    monkeypatch.setattr("reachagent.scan.browser_recon.run_browser_recon", fake_browser_recon)

    control_state = types.SimpleNamespace(touch=lambda: None)
    _run_attack_path_chain(
        lead=lead,
        graph=graph,
        seam=seam,
        firer=firer,
        base_url=_BASE,
        auth_headers={},
        identities=identities,
        transport=None,
        library=None,
        allow_cross_user_writes=False,
        events=[],
        cancel_check=None,
        check_cancel=lambda _c: None,
        control_state=control_state,
    )

    assert len(calls) == 1
    assert calls[0].startswith("derived-")
    assert calls[0] in identities.names()


def test_attack_path_chain_browser_recon_failure_does_not_abort_the_rehunt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph, identities, firer, seam, lead = _lead_from_first_pass(monkeypatch)

    def boom(**_kwargs: object) -> int:
        raise RuntimeError("playwright crashed")

    monkeypatch.setattr("reachagent.scan.browser_recon.run_browser_recon", boom)

    control_state = types.SimpleNamespace(touch=lambda: None)
    events: list = []
    new_ids = _run_attack_path_chain(
        lead=lead,
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

    # The re-hunt still ran and confirmed the admin finding despite the browser
    # recon crash — a browser/Playwright failure never aborts the chain.
    admin_finding_id = finding_id("nosqli", "orchestrator/nosqli /admin/secret user:ne-null")
    assert admin_finding_id in new_ids
    assert any("attack-path chain browser recon failed" in e.message for e in events)


def test_concurrent_chaining_spawns_one_agent_per_lead_and_merges_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v4 R3b: genuine dynamic agent spawning — TWO leads get TWO concurrent
    re-hunt agents (not just the first, the old behavior), each merged back
    into the parent graph."""
    graph, identities, firer, seam, lead = _lead_from_first_pass(monkeypatch)
    # A second, distinct lead sharing the same real captured session material
    # (this test's own fixture only produces one genuine bypass point) --
    # what's under test is the concurrent-spawn/merge machinery itself, not
    # re-deriving a second realistic bypass scenario already covered above.
    second_finding_id = graph.add_finding(
        Finding(
            vuln_class="nosqli",
            severity="high",
            oracle_used="differential",
            evidence_ref="ref-2",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    second_lead = DerivedIdentityLead(
        finding_id=second_finding_id,
        vuln_class=lead.vuln_class,
        role_hint="second-admin",
        captured=lead.captured,
    )

    events: list = []
    control_state = types.SimpleNamespace(touch=lambda: None)
    _run_attack_path_chains_concurrent(
        leads=[lead, second_lead],
        graph=graph,
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

    # Two genuinely distinct synthetic identities were spawned (one per lead)
    # -- both agents genuinely ran, not just the first.
    derived_names = [n for n in identities.names() if n.startswith("derived-")]
    assert len(derived_names) == 2
    admin_finding_id = finding_id("nosqli", "orchestrator/nosqli /admin/secret user:ne-null")
    assert admin_finding_id in dict(graph.findings())
    # The re-hunt-agent completion events for BOTH agents landed in the
    # parent's own event list -- not lost in an isolated child.
    assert sum(1 for e in events if e.message.startswith("re-hunt agent (")) == 2
    # Both leads re-hunt the SAME underlying admin/secret nosqli via the same
    # captured material (this test's own simplification -- see comment
    # above), producing the IDENTICAL evidence_ref and thus the IDENTICAL
    # deterministic finding id -- exactly ONE agent's confirmation becomes
    # the genuinely new finding (an enables edge from its own lead); the
    # OTHER agent's identical re-confirmation is caught by
    # merge_new_findings's pre-existing exact-id check (graph/merge.py),
    # not a new mechanism. WHICH of the two wins is a genuine race (both run
    # truly concurrently; whichever's merge lands first keeps its edge) --
    # assert exactly one, not a specific one, so this test isn't flaky on
    # completion order.
    enabling_leads = {
        fid for fid, _ in graph.enables_edges() if fid in {lead.finding_id, second_finding_id}
    }
    assert len(enabling_leads) == 1


def test_concurrent_chaining_one_agent_crashing_does_not_abort_the_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph, identities, firer, seam, lead = _lead_from_first_pass(monkeypatch)

    second_finding_id = graph.add_finding(
        Finding(
            vuln_class="nosqli",
            severity="high",
            oracle_used="differential",
            evidence_ref="ref-2",
            status=FindingStatus.CONFIRMED_VIOLATION,
        )
    )
    second_lead = DerivedIdentityLead(
        finding_id=second_finding_id,
        vuln_class=lead.vuln_class,
        role_hint="crash-me",
        captured=lead.captured,
    )

    from reachagent.scan import chaining as _chaining

    real_spawn = _chaining.spawn_derived_identity

    def spawn_or_crash(identities, firer, graph, *, role_hint, captured):  # noqa: ANN001
        if role_hint == "crash-me":
            raise RuntimeError("simulated spawn crash")
        return real_spawn(identities, firer, graph, role_hint=role_hint, captured=captured)

    monkeypatch.setattr("reachagent.scan.chaining.spawn_derived_identity", spawn_or_crash)

    events: list = []
    control_state = types.SimpleNamespace(touch=lambda: None)
    _run_attack_path_chains_concurrent(
        leads=[lead, second_lead],
        graph=graph,
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

    # The crashing agent's failure is visible...
    assert any("crashed" in e.message for e in events)
    # ...but the healthy sibling's own confirmed finding still made it through.
    admin_finding_id = finding_id("nosqli", "orchestrator/nosqli /admin/secret user:ne-null")
    assert admin_finding_id in dict(graph.findings())


def test_chaining_is_a_no_op_when_no_lead_captured_real_session_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If /login's bypass never returns real session material, nothing to chain into.

    Confirmation is injected here too so this genuinely tests "confirmed but no
    session material" — without it, an unconfigured judgment would return
    inconclusive and `leads == []` would hold for the wrong reason (never
    confirmed at all), not the one this test's name and docstring claim.
    """
    _patch_judgment(monkeypatch)

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
