"""Hermetic E2E for the Phase-B dedicated blind/auth-bypass drivers.

nosqli/ldap confirm via the differential AUTH_BYPASS oracle (refused baseline ->
granted probe); command_injection confirms via the statistical timing oracle
(a small injected latency on the sleep payload). A clean target confirms nothing
(the oracle fail-closed contract), and every probe is a read-only GET.

The timing-fallback tests bump ``_TIMING_TRIALS`` well above the production
default. A near-zero-latency MockTransport call has a MUCH tighter baseline std
than a real HTTP round trip (real network jitter is milliseconds; an in-process
mock call's jitter is scheduler noise, sub-millisecond) — so a single stray GC
pause among only 10 trials can shift the mean enough to cross the oracle's
3-sigma threshold purely by chance, exactly the flakiness the codebase's own
convention avoids by testing oracle DECISION math with fabricated latencies,
never real wall-clock measurement. These are deliberately real-wall-clock E2E
tests (proving the driver actually wires _paired_timing through a live firer),
so the fix is to dilute a single outlier's weight on the mean with more trials —
the same "repeat-to-denoise before trusting" rule the timing oracle itself
documents — not to weaken the production oracle's threshold.
"""

from __future__ import annotations

import time

import httpx

import reachagent.oracles.llm_judgment as _llm_judgment
from reachagent.detection.oracle_gateway import OracleOutcome
from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import OracleVerdict
from reachagent.scan import orchestrator as _orchestrator
from reachagent.scan.orchestrator import (
    _ValidatorSeam,
    run_command_injection,
    run_ldap,
    run_nosqli,
)
from tests._oracle_test_support import CONFIRMS, INCONCLUSIVE, FixedJudgmentClient

_DENOISED_TRIALS = 40

_BASE = "http://t.test"


def _confirm_everything(monkeypatch) -> None:  # noqa: ANN001
    """v3 (CLAUDE.md): confirmation is now an LLM judgment, not the removed
    decide() logic, and these driver-level tests have no client= seam to
    inject through (only tools.validator.run_oracle's direct callers do) —
    same situation as tests/phase1/test_confirm_error_based_e2e.py. Fixing the
    provider factory that judge() falls back to makes every oracle call in the
    test CONFIRM, which is only safe for tests where a real, single bypass/
    timing signal is what actually earns the confirmation (asserted via the
    handler's real HTTP responses) — not a stand-in for that content."""
    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )


def _real_evidence_run(
    self: _ValidatorSeam, mechanism: OracleMechanism, evidence: object
) -> OracleOutcome:
    """A ``_ValidatorSeam.run`` stand-in that still looks at the REAL evidence.

    Unlike a blanket fixed verdict, this confirms a DIFFERENTIAL (auth-bypass)
    call only when the real probe response actually got granted (status 200) —
    needed for the "tries later variants" tests, where the whole point is that
    an early, still-blocked variant must NOT be the one that confirms. A
    TIMING_STATISTICAL call confirms only when the probe latencies actually ran
    slower than baseline — every non-final bypass variant drives the fixed,
    identical-latency ``_no_timing_signal`` fake (must stay inconclusive so it
    can't masquerade as a real timing hit), while the real paired-timing round
    on the final variant carries a genuine injected delay.
    Mirrors the real ``run()``'s ``self._last`` bookkeeping — the driver reads
    ``seam.last`` (not the OracleOutcome) to decide whether to write a Finding.
    """
    if mechanism is OracleMechanism.DIFFERENTIAL:
        status = CONFIRMS if evidence.probe.status_code == 200 else INCONCLUSIVE  # type: ignore[attr-defined]
    else:
        probe_mean = sum(evidence.probe_latencies_ms) / len(evidence.probe_latencies_ms)  # type: ignore[attr-defined]
        baseline_mean = sum(evidence.baseline_latencies_ms) / len(evidence.baseline_latencies_ms)  # type: ignore[attr-defined]
        status = CONFIRMS if probe_mean > baseline_mean else INCONCLUSIVE
    ref = str(getattr(evidence, "evidence_ref", "") or "")
    verdict = OracleVerdict(
        mechanism=mechanism, status=status, evidence_ref=ref, reason="test-fixed-verdict"
    )
    self._last = verdict
    return OracleOutcome(verdict)


def _use_real_evidence_runner(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(_ValidatorSeam, "run", _real_evidence_run)


def _graph(sink: SinkType | None) -> tuple[ReachabilityGraph, str]:
    graph = ReachabilityGraph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/login"))
    param = graph.add_parameter(ep, Parameter(name="user", location="query"))
    if sink is not None:
        graph.set_parameter_sink_type(param, sink)
    return graph, ep


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["t.test"]))


def _run(driver: object, graph: ReachabilityGraph, firer: RequestFirer) -> list:
    seam = _ValidatorSeam(graph)
    driver(  # type: ignore[operator]
        graph=graph, firer=firer, base_url=_BASE, identity="anon", seam=seam, events=[]
    )
    return graph.findings()


def _bypass_handler(injected_markers: tuple[str, ...]) -> object:
    """401 for benign/canary; 200 for a request whose value carries an operator."""

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("user", "")
        if value == "baseline" or value.startswith("reachagent-canary"):
            return httpx.Response(401, text="invalid credentials")
        if any(m in value for m in injected_markers):
            return httpx.Response(200, json={"token": "granted"})
        return httpx.Response(401, text="invalid credentials")

    return handler


def test_nosqli_authbypass_confirms(monkeypatch) -> None:  # noqa: ANN001
    _confirm_everything(monkeypatch)
    graph, _ep = _graph(SinkType.NOSQL)
    findings = _run(run_nosqli, graph, _firer(_bypass_handler(("$ne", "$"))))
    classes = {f.vuln_class for _fid, f in findings}
    assert "nosqli" in classes
    assert all(f.status.value == "confirmed_violation" and f.oracle_used for _fid, f in findings)


def test_ldap_authbypass_confirms(monkeypatch) -> None:  # noqa: ANN001
    _confirm_everything(monkeypatch)
    graph, _ep = _graph(SinkType.LDAP)
    findings = _run(run_ldap, graph, _firer(_bypass_handler(("*)(", "*"))))
    assert "ldap_injection" in {f.vuln_class for _fid, f in findings}


def test_command_injection_timing_confirms(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(_orchestrator, "_TIMING_TRIALS", _DENOISED_TRIALS)
    _confirm_everything(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("user", "")
        if "sleep" in value:  # the injected time-delay payload
            time.sleep(0.02)
        return httpx.Response(200, text="pong")

    graph, _ep = _graph(SinkType.SHELL)
    findings = _run(run_command_injection, graph, _firer(handler))
    assert "command_injection" in {f.vuln_class for _fid, f in findings}


def test_clean_target_confirms_nothing(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(_orchestrator, "_TIMING_TRIALS", _DENOISED_TRIALS)

    # Benign target: never refuses, never delays -> no auth-bypass, no timing signal.
    def clean(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    for driver, sink in (
        (run_nosqli, SinkType.NOSQL),
        (run_ldap, SinkType.LDAP),
        (run_command_injection, SinkType.SHELL),
    ):
        graph, _ep = _graph(sink)
        assert _run(driver, graph, _firer(clean)) == []


def test_untyped_param_is_skipped_outright_not_merely_unconfirmed() -> None:
    # sink=None (never observed/hinted for this class): the plausibility gate
    # skips the param BEFORE any request fires — proven deterministically by a
    # request count, not by relying on a noisy oracle staying quiet. Spraying the
    # statistical timing fallback across every untyped param is exactly the
    # false-positive mode this test locks closed (see _drives_param docstring).
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, text="ok")

    graph, _ep = _graph(None)
    assert _run(run_nosqli, graph, _firer(handler)) == []
    assert seen == []


def test_drivers_fire_only_get_requests() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, json={"ok": True})

    graph, _ep = _graph(SinkType.NOSQL)
    _run(run_nosqli, graph, _firer(handler))
    assert seen and all(method == "GET" for method in seen)


def test_nosqli_authbypass_with_real_token_queues_a_derived_identity_lead(monkeypatch) -> None:  # noqa: ANN001
    """v2 W17: a confirmed auth-bypass whose probe response carries REAL session
    material (here, {"token": "granted"}) queues a DerivedIdentityLead for the
    caller to spawn + re-hunt — bypass_identity_hint is no longer dropped."""
    from reachagent.scan.chaining import DerivedIdentityLead

    _confirm_everything(monkeypatch)
    graph, _ep = _graph(SinkType.NOSQL)
    seam = _ValidatorSeam(graph)
    leads: list = []
    run_nosqli(
        graph=graph,
        firer=_firer(_bypass_handler(("$ne", "$"))),
        base_url=_BASE,
        identity="anon",
        seam=seam,
        events=[],
        derived_identities=leads,
    )
    assert len(leads) == 1
    lead = leads[0]
    assert isinstance(lead, DerivedIdentityLead)
    assert lead.vuln_class == "nosqli"
    assert lead.role_hint == "nosqli-bypass-principal"
    assert lead.captured.token == "granted"


def test_nosqli_authbypass_with_no_real_session_material_queues_nothing() -> None:
    """A bypass that returns a bare 2xx with no token/cookie grants nothing to
    chain into — no lead should be queued."""

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("user", "")
        if value == "baseline" or value.startswith("reachagent-canary"):
            return httpx.Response(401, text="invalid credentials")
        if "$ne" in value or "$" in value:
            return httpx.Response(200, json={"ok": True})  # no token, no cookie
        return httpx.Response(401, text="invalid credentials")

    graph, _ep = _graph(SinkType.NOSQL)
    seam = _ValidatorSeam(graph)
    leads: list = []
    run_nosqli(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        seam=seam,
        events=[],
        derived_identities=leads,
    )
    assert leads == []


def test_nosqli_omits_chaining_entirely_when_derived_identities_not_passed(monkeypatch) -> None:  # noqa: ANN001
    """Backward-compatible default: callers that don't opt in (derived_identities
    left as None) get identical behavior to before W17 — no crash, no side effect."""
    _confirm_everything(monkeypatch)
    graph, _ep = _graph(SinkType.NOSQL)
    findings = _run(run_nosqli, graph, _firer(_bypass_handler(("$ne", "$"))))
    assert "nosqli" in {f.vuln_class for _fid, f in findings}


def test_nosqli_tries_later_variants_when_earlier_ones_are_blocked(monkeypatch) -> None:  # noqa: ANN001
    """v2 W5: a WAF-like filter that strips '$ne' but is blind to '$gt' — the loop
    must not give up after the first (blocked) variant."""
    _use_real_evidence_runner(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("user", "")
        if value == "baseline" or value.startswith("reachagent-canary"):
            return httpx.Response(401, text="invalid credentials")
        if "$gt" in value:
            return httpx.Response(200, json={"token": "granted"})
        return httpx.Response(401, text="blocked by waf")  # $ne variants filtered

    graph, _ep = _graph(SinkType.NOSQL)
    findings = _run(run_nosqli, graph, _firer(handler))
    [(fid, finding)] = findings
    assert finding.vuln_class == "nosqli"
    assert fid.endswith(":gt-empty")  # the 3rd variant tried, not the 1st


def test_ldap_tries_later_variants_when_earlier_ones_are_blocked(monkeypatch) -> None:  # noqa: ANN001
    """Same proof as above, for the LDAP wildcard variants."""
    _use_real_evidence_runner(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("user", "")
        if value == "baseline" or value.startswith("reachagent-canary"):
            return httpx.Response(401)
        if "password=*" in value:
            return httpx.Response(200, json={"token": "granted"})
        return httpx.Response(401)  # wildcard variants filtered by a stricter filter

    graph, _ep = _graph(SinkType.LDAP)
    findings = _run(run_ldap, graph, _firer(handler))
    [(fid, finding)] = findings
    assert finding.vuln_class == "ldap_injection"
    assert fid.endswith(":admin-password-bypass")  # the 3rd variant tried, not the 1st


def test_nosqli_does_not_spray_real_timing_probes_across_every_variant(monkeypatch) -> None:  # noqa: ANN001
    """Only the LAST bypass variant may trigger the real timing fallback — the
    other variants use a fake always-clean TimingProbe, so a WAF that blocks
    every auth-bypass shape causes exactly one round of real timing, not five."""
    monkeypatch.setattr(_orchestrator, "_TIMING_TRIALS", _DENOISED_TRIALS)
    _use_real_evidence_runner(monkeypatch)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("user", "")
        calls.append(value)
        if "$where" in value and "sleep" in value:
            time.sleep(0.02)
            return httpx.Response(200, text="pong")
        return httpx.Response(401, text="nope")

    graph, _ep = _graph(SinkType.NOSQL)
    findings = _run(run_nosqli, graph, _firer(handler))
    assert "nosqli" in {f.vuln_class for _fid, f in findings}
    variant_count = len(_orchestrator._NOSQL_BYPASS_VALUES)
    # Each variant fires 2 bypass requests (baseline + probe); only the final
    # variant additionally runs a real paired-timing round (2 x _TIMING_TRIALS).
    assert len(calls) == variant_count * 2 + 2 * _DENOISED_TRIALS
