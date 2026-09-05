"""Tests for the recon agent tool (fetch_openapi/parse_graphql/mine_js dispatch)."""

from __future__ import annotations

import httpx

from lalo.execution.firer import HttpFirer
from lalo.execution.scope import ScopeGuard
from lalo.execution.target import Engagement
from lalo.graph.model import NodeKind, ReachabilityGraph
from lalo.recon.tool import build_recon_tool

_OPENAPI_DOC = {
    "openapi": "3.0.0",
    "paths": {"/users": {"get": {}}, "/users/{id}": {"get": {}, "delete": {}}},
}


def _firer(handler: object) -> HttpFirer:
    eng = Engagement.from_specs(["app.example.com"])
    scope = ScopeGuard(engagement=eng, resolver=lambda h: frozenset({"93.184.216.34"}))
    return HttpFirer(scope, client=httpx.Client(transport=httpx.MockTransport(handler)))  # type: ignore[arg-type]


def _scope() -> ScopeGuard:
    eng = Engagement.from_specs(["app.example.com"])
    return ScopeGuard(engagement=eng, resolver=lambda h: frozenset({"93.184.216.34"}))


def test_fetch_openapi_merges_in_scope_endpoints_into_the_graph() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_OPENAPI_DOC)

    graph = ReachabilityGraph()
    tool = build_recon_tool(_firer(handler), graph, _scope())
    result = tool.run(
        {"action": "fetch_openapi", "spec_url": "https://app.example.com/openapi.json"}
    )
    assert result.ok is True
    assert len(graph.nodes_of_kind(NodeKind.ENDPOINT)) == 2


def test_fetch_openapi_requires_spec_url() -> None:
    tool = build_recon_tool(_firer(lambda r: httpx.Response(200)), ReachabilityGraph(), _scope())
    result = tool.run({"action": "fetch_openapi"})
    assert result.ok is False


def test_fetch_openapi_with_no_facts_extracted_is_a_failed_result() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    tool = build_recon_tool(_firer(handler), ReachabilityGraph(), _scope())
    result = tool.run(
        {"action": "fetch_openapi", "spec_url": "https://app.example.com/openapi.json"}
    )
    assert result.ok is False


def test_parse_graphql_merges_the_endpoint_fact() -> None:
    graph = ReachabilityGraph()
    tool = build_recon_tool(_firer(lambda r: httpx.Response(200)), graph, _scope())
    introspection = {"data": {"__schema": {"types": [{"name": "User"}]}}}
    result = tool.run(
        {
            "action": "parse_graphql",
            "endpoint_url": "https://app.example.com/graphql",
            "introspection": introspection,
        }
    )
    assert result.ok is True
    assert graph.has_node("https://app.example.com/graphql")


def test_parse_graphql_requires_an_introspection_dict() -> None:
    tool = build_recon_tool(_firer(lambda r: httpx.Response(200)), ReachabilityGraph(), _scope())
    result = tool.run(
        {"action": "parse_graphql", "endpoint_url": "https://app.example.com/graphql"}
    )
    assert result.ok is False


def test_mine_js_merges_discovered_paths_as_endpoint_facts() -> None:
    graph = ReachabilityGraph()
    tool = build_recon_tool(_firer(lambda r: httpx.Response(200)), graph, _scope())
    js = 'fetch("/api/users/{id}"); const x = "/api/orders";'
    result = tool.run(
        {"action": "mine_js", "js_source": js, "base_url": "https://app.example.com/"}
    )
    assert result.ok is True
    assert graph.has_node("https://app.example.com/api/users/{id}")
    assert graph.has_node("https://app.example.com/api/orders")


def test_mine_js_surfaces_a_sourcemap_hint() -> None:
    tool = build_recon_tool(_firer(lambda r: httpx.Response(200)), ReachabilityGraph(), _scope())
    js = '"/api/users"; //# sourceMappingURL=app.js.map'
    result = tool.run(
        {"action": "mine_js", "js_source": js, "base_url": "https://app.example.com/"}
    )
    assert "app.js.map" in result.observation


def test_mine_js_out_of_scope_url_is_rejected_not_silently_dropped() -> None:
    graph = ReachabilityGraph()
    tool = build_recon_tool(_firer(lambda r: httpx.Response(200)), graph, _scope())
    js = '"/evil"'
    result = tool.run(
        {"action": "mine_js", "js_source": js, "base_url": "https://evil.example.org/"}
    )
    assert "rejected" in result.observation


def test_unknown_action_is_a_failed_result() -> None:
    tool = build_recon_tool(_firer(lambda r: httpx.Response(200)), ReachabilityGraph(), _scope())
    result = tool.run({"action": "nope"})
    assert result.ok is False
