"""Hermetic E2E for the race driver: sequential-first single-use/reuse replay.

Mirrors the mass_assignment/xss_stored driver harness. Proves: (1) only
SINGLE_USE_REUSE resources are targeted (business_logic's other three
templates are untouched here), (2) a second-redemption rejected by the
target denies the finding, and (3) a second-redemption accepted confirms it.
"""

from __future__ import annotations

import httpx

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.orchestrator import _ValidatorSeam, run_business_logic, run_race

_BASE = "http://race.test"


def _graph() -> ReachabilityGraph:
    graph = ReachabilityGraph()
    endpoint = graph.add_endpoint(Endpoint(method="POST", path="/coupon/redeem"))
    graph.add_parameter(endpoint, Parameter(name="coupon_code", location="json"))
    return graph


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["race.test"]))


def _run(handler: object, graph: ReachabilityGraph | None = None) -> list:
    graph = graph or _graph()
    seam = _ValidatorSeam(graph)
    run_race(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        seam=seam,
        events=[],
    )
    return graph.findings()


def test_confirms_when_second_redemption_is_accepted() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "redeemed"})

    findings = _run(handler)
    classes = {f.vuln_class for _fid, f in findings}
    assert "race" in classes
    assert all(f.status.value == "confirmed_violation" for _fid, f in findings)


def test_second_redemption_refused_no_finding() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json={"status": "redeemed"})
        return httpx.Response(409, json={"error": "already redeemed"})

    assert _run(handler) == []


def test_no_single_use_resource_never_fires() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, json={"status": "redeemed"})

    graph = ReachabilityGraph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/search"))
    graph.add_parameter(ep, Parameter(name="q", location="query"))

    assert _run(handler, graph=graph) == []
    assert seen == []  # no single-use/reuse resource in the graph — never probed


def test_business_logic_excludes_single_use_reuse_race_owns_it_exclusively() -> None:
    """The one-line fix run_business_logic needs before run_race can be trusted:
    without it, both drivers would fire the SAME limited coupon, and whichever
    runs second sees an already-consumed resource instead of a fresh baseline.
    """
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(200, json={"status": "redeemed"})

    graph = _graph()
    seam = _ValidatorSeam(graph)
    run_business_logic(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        seam=seam,
        events=[],
    )
    assert seen == []  # run_business_logic never touched the single-use coupon
    assert graph.findings() == []
