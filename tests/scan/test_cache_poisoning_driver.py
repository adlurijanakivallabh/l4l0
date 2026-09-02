"""Hermetic E2E for the cache-poisoning driver: unkeyed-header injection +
independent, header-free re-read of the same cache-busted URL.

Mirrors test_open_redirect_driver.py's harness. Proves: (1) confirmation
requires the injected marker to survive into a SECOND, unrelated request that
never sent the poisoning header — a simulated shared cache; (2) per-request
reflection with no cache behind it (the marker vanishes on the clean re-read)
never produces a finding.
"""

from __future__ import annotations

import httpx

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.nodes import Endpoint
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.orchestrator import _UNKEYED_HEADER, _ValidatorSeam, run_cache_poisoning
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient

_BASE = "http://cp.test"


def _graph() -> ReachabilityGraph:
    graph = ReachabilityGraph()
    graph.add_endpoint(Endpoint(method="GET", path="/"))
    return graph


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["cp.test"]))


def _run(handler: object, graph: ReachabilityGraph | None = None) -> list:
    graph = graph or _graph()
    seam = _ValidatorSeam(graph)
    run_cache_poisoning(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        auth_headers={},
        seam=seam,
        events=[],
    )
    return graph.findings()


def test_confirms_when_marker_replayed_from_simulated_cache(monkeypatch) -> None:  # noqa: ANN001
    """A real cache stores the first response and serves it back unchanged —
    the re-read carries no poisoning header but still sees the marker.

    Confirmation is now an LLM judgment (v3, CLAUDE.md) rather than a fixed
    decide(); _ValidatorSeam.run calls tools.validator.run_oracle with no
    client= passthrough, so pin the verdict by monkeypatching the client
    builder it constructs internally.
    """
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )

    cache: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url not in cache:
            marker = request.headers.get(_UNKEYED_HEADER, "")
            cache[url] = f'<link rel="canonical" href="https://{marker}/">'
        return httpx.Response(200, text=cache[url])

    findings = _run(handler)
    classes = {f.vuln_class for _fid, f in findings}
    assert "web_cache_poisoning" in classes
    assert all(f.status.value == "confirmed_violation" for _fid, f in findings)


def test_per_request_reflection_with_no_cache_is_not_confirmed() -> None:
    """No caching at all: each request reflects only its own header — the
    clean re-read never sees the marker. Not exploitable."""

    def handler(request: httpx.Request) -> httpx.Response:
        marker = request.headers.get(_UNKEYED_HEADER, "")
        return httpx.Response(200, text=f'<link rel="canonical" href="https://{marker}/">')

    assert _run(handler) == []


def test_header_ignored_entirely_no_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>static</html>")

    assert _run(handler) == []


def test_each_candidate_gets_its_own_cache_buster() -> None:
    """Every candidate URL must carry a distinct, run-unique cache-buster —
    the technique never touches a URL a real visitor could ever hit."""
    seen_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return httpx.Response(200, text="ok")

    graph = ReachabilityGraph()
    graph.add_endpoint(Endpoint(method="GET", path="/"))
    graph.add_endpoint(Endpoint(method="GET", path="/products"))
    _run(handler, graph=graph)

    cache_busters = [httpx.URL(u).params.get("_rachk") for u in seen_urls]
    assert all(cache_busters)
    # Two requests (poison + reread) per candidate share one buster; distinct
    # candidates never do.
    assert len(set(cache_busters)) == len(seen_urls) // 2
