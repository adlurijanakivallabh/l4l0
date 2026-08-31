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

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan import orchestrator as _orchestrator
from reachagent.scan.orchestrator import (
    _ValidatorSeam,
    run_command_injection,
    run_ldap,
    run_nosqli,
)

_DENOISED_TRIALS = 40

_BASE = "http://t.test"


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


def test_nosqli_authbypass_confirms() -> None:
    graph, _ep = _graph(SinkType.NOSQL)
    findings = _run(run_nosqli, graph, _firer(_bypass_handler(("$ne", "$"))))
    classes = {f.vuln_class for _fid, f in findings}
    assert "nosqli" in classes
    assert all(f.status.value == "confirmed_violation" and f.oracle_used for _fid, f in findings)


def test_ldap_authbypass_confirms() -> None:
    graph, _ep = _graph(SinkType.LDAP)
    findings = _run(run_ldap, graph, _firer(_bypass_handler(("*)(", "*"))))
    assert "ldap_injection" in {f.vuln_class for _fid, f in findings}


def test_command_injection_timing_confirms(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(_orchestrator, "_TIMING_TRIALS", _DENOISED_TRIALS)

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
