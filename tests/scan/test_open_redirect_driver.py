"""Hermetic E2E for the open-redirect driver: query-param injection + Location check.

Mirrors test_mass_assignment_driver.py's harness. Proves: (1) only endpoints
declaring a redirect-shaped query parameter are probed, and (2) confirmation
requires the injected attacker URL to appear verbatim in the response's
``Location`` header, not merely a 3xx status.
"""

from __future__ import annotations

import httpx

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.orchestrator import _ValidatorSeam, run_open_redirect

_BASE = "http://or.test"


def _graph(param_name: str = "next") -> ReachabilityGraph:
    graph = ReachabilityGraph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/login"))
    graph.add_parameter(ep, Parameter(name=param_name, location="query"))
    return graph


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["or.test"]))


def _run(handler: object, graph: ReachabilityGraph | None = None) -> list:
    graph = graph or _graph()
    seam = _ValidatorSeam(graph)
    run_open_redirect(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        auth_headers={},
        seam=seam,
        events=[],
    )
    return graph.findings()


def test_confirms_when_attacker_url_echoed_into_location() -> None:
    captured: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(str(request.url))
        target = request.url.params.get("next", "")
        return httpx.Response(302, headers={"Location": target})

    findings = _run(handler)
    classes = {f.vuln_class for _fid, f in findings}
    assert "open_redirect" in classes
    assert all(f.status.value == "confirmed_violation" for _fid, f in findings)
    assert captured and "next=" in captured[0]


def test_rewritten_location_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "/login-ok"})

    assert _run(handler) == []


def test_no_redirect_shaped_param_never_fires() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, text="ok")

    graph = ReachabilityGraph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/search"))
    graph.add_parameter(ep, Parameter(name="q", location="query"))

    assert _run(handler, graph=graph) == []
    assert seen == []  # no redirect-shaped param — never probed


def test_non_redirect_status_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    assert _run(handler) == []


def test_post_endpoints_are_never_probed() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(302, headers={"Location": "https://evil.example/x"})

    graph = ReachabilityGraph()
    ep = graph.add_endpoint(Endpoint(method="POST", path="/logout"))
    graph.add_parameter(ep, Parameter(name="redirect", location="query"))

    assert _run(handler, graph=graph) == []
    assert seen == []


def test_recognizes_multiple_redirect_param_name_variants() -> None:
    for name in ("redirect", "returnUrl", "dest", "url"):
        graph = _graph(param_name=name)

        def handler(request: httpx.Request, _name: str = name) -> httpx.Response:
            target = request.url.params.get(_name, "")
            return httpx.Response(302, headers={"Location": target})

        findings = _run(handler, graph=graph)
        assert findings, f"expected a finding for param name {name!r}"
