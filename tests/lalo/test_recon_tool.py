"""Tests for the recon agent tool (fetch_openapi/parse_graphql/mine_js dispatch)."""

from __future__ import annotations

from dataclasses import dataclass

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


def test_parse_postman_merges_in_scope_endpoints_into_the_graph() -> None:
    graph = ReachabilityGraph()
    tool = build_recon_tool(_firer(lambda r: httpx.Response(200)), graph, _scope())
    collection = {
        "item": [
            {"request": {"method": "GET", "url": "https://app.example.com/users"}},
            {
                "name": "Auth",
                "item": [{"request": {"method": "POST", "url": "https://app.example.com/login"}}],
            },
        ]
    }
    result = tool.run({"action": "parse_postman", "collection": collection})
    assert result.ok is True
    assert len(graph.nodes_of_kind(NodeKind.ENDPOINT)) == 2


def test_parse_postman_requires_a_collection_dict() -> None:
    tool = build_recon_tool(_firer(lambda r: httpx.Response(200)), ReachabilityGraph(), _scope())
    result = tool.run({"action": "parse_postman"})
    assert result.ok is False


def test_parse_postman_out_of_scope_url_is_rejected_not_silently_dropped() -> None:
    graph = ReachabilityGraph()
    tool = build_recon_tool(_firer(lambda r: httpx.Response(200)), graph, _scope())
    collection = {"item": [{"request": {"method": "GET", "url": "https://evil.example.org/steal"}}]}
    result = tool.run({"action": "parse_postman", "collection": collection})
    assert "rejected" in result.observation
    assert graph.nodes_of_kind(NodeKind.ENDPOINT) == []


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


# --- scan_ports: the nmap ReconRunner, dispatched through the same tool -----

_OPEN_PORT_XML = (
    '<?xml version="1.0"?><nmaprun><host><ports>'
    '<port protocol="tcp" portid="443">'
    '<state state="open"/><service name="https"/></port>'
    "</ports></host></nmaprun>"
)


@dataclass
class _FakeExecResult:
    ok: bool = True
    stdout: str = ""


class _FakeContainer:
    def exec(self, command: str, *, timeout: float = 120.0) -> _FakeExecResult:
        if command.startswith("command -v"):
            return _FakeExecResult(ok=True)
        return _FakeExecResult(ok=True, stdout=_OPEN_PORT_XML)


def test_scan_ports_without_a_container_is_a_failed_result() -> None:
    tool = build_recon_tool(_firer(lambda r: httpx.Response(200)), ReachabilityGraph(), _scope())
    result = tool.run({"action": "scan_ports", "host": "app.example.com"})
    assert result.ok is False
    assert "container" in result.observation


def test_scan_ports_requires_a_host() -> None:
    tool = build_recon_tool(
        _firer(lambda r: httpx.Response(200)),
        ReachabilityGraph(),
        _scope(),
        container=_FakeContainer(),
    )
    result = tool.run({"action": "scan_ports"})
    assert result.ok is False


def test_scan_ports_refuses_an_out_of_engagement_host() -> None:
    tool = build_recon_tool(
        _firer(lambda r: httpx.Response(200)),
        ReachabilityGraph(),
        _scope(),
        container=_FakeContainer(),
    )
    result = tool.run({"action": "scan_ports", "host": "10.0.0.9"})
    assert result.ok is False
    assert "not in engagement" in result.observation


def test_scan_ports_refuses_a_flag_shaped_host() -> None:
    """The agent's own 'host' arg reaching a real nmap command line - a
    value like "--script=vulners" must never be quoted-and-passed-through."""
    tool = build_recon_tool(
        _firer(lambda r: httpx.Response(200)),
        ReachabilityGraph(),
        _scope(),
        container=_FakeContainer(),
    )
    result = tool.run({"action": "scan_ports", "host": "--script=vulners"})
    assert result.ok is False
    assert "UnsafeNmapArgumentError" in result.observation


def test_scan_ports_merges_open_ports_into_the_graph() -> None:
    graph = ReachabilityGraph()
    tool = build_recon_tool(
        _firer(lambda r: httpx.Response(200)), graph, _scope(), container=_FakeContainer()
    )
    result = tool.run({"action": "scan_ports", "host": "app.example.com"})
    assert result.ok is True
    assert graph.has_node("tcp://app.example.com:443")
