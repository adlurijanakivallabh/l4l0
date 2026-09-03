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
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient

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


def test_confirms_when_attacker_url_echoed_into_location(monkeypatch) -> None:  # noqa: ANN001
    """Confirmation is now an LLM judgment (v3, CLAUDE.md) rather than a fixed
    decide(); _ValidatorSeam.run calls tools.validator.run_oracle with no
    client= passthrough, so pin the verdict by monkeypatching the client
    builder it constructs internally.
    """
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )

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


def test_two_redirect_params_wire_corroboration_through(monkeypatch) -> None:  # noqa: ANN001
    """v3 V3 wiring test: when an endpoint has TWO redirect-shaped params, the
    second one is threaded through as the corroborating probe and the written
    finding's metadata records which param corroborated. The corroboration
    DECISION logic itself (contradicted second probe -> fails closed) is
    already covered at the detector level in tests/phase3/test_open_redirect.py
    — this only proves the orchestrator wires the second param through at all."""
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )

    graph = ReachabilityGraph()
    ep = graph.add_endpoint(Endpoint(method="GET", path="/login"))
    graph.add_parameter(ep, Parameter(name="next", location="query"))
    graph.add_parameter(ep, Parameter(name="returnUrl", location="query"))

    def handler(request: httpx.Request) -> httpx.Response:
        target = request.url.params.get("next") or request.url.params.get("returnUrl") or ""
        return httpx.Response(302, headers={"Location": target})

    findings = _run(handler, graph=graph)
    assert findings
    _fid, finding = findings[0]
    assert finding.vuln_class == "open_redirect"
    assert finding.metadata.get("corroborated_param") == "returnUrl"


def test_recognizes_multiple_redirect_param_name_variants(monkeypatch) -> None:  # noqa: ANN001
    """Same LLM-judgment pinning as above — verdict is now beyond fixture control."""
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )

    for name in ("redirect", "returnUrl", "dest", "url"):
        graph = _graph(param_name=name)

        def handler(request: httpx.Request, _name: str = name) -> httpx.Response:
            target = request.url.params.get(_name, "")
            return httpx.Response(302, headers={"Location": target})

        findings = _run(handler, graph=graph)
        assert findings, f"expected a finding for param name {name!r}"
