"""Spec-first API discovery (Task 27 Component 3) + optional --surface seeding (Component 2)."""

from __future__ import annotations

import ast
from pathlib import Path

import httpx

from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import Protocol
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.recon.api_discovery import discover_api
from reachagent.scan.entrypoint import scan_target

_TARGET = "target.test"


def _firer(handler: object) -> tuple[RequestFirer, AuditLog]:
    a = AuditLog()
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts([_TARGET]), a), a


_OPENAPI = {
    "openapi": "3.0.0",
    "paths": {
        "/users/v1/{username}": {
            "get": {"parameters": [{"name": "username", "in": "path"}]},
        },
        "/books/v1": {
            "get": {"parameters": [{"name": "Authorization", "in": "header"}]},
            "post": {"parameters": [{"name": "book_title", "in": "body"}]},
        },
    },
}


def _openapi_handler(spec_path: str = "/openapi.json") -> object:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == spec_path:
            return httpx.Response(200, json=_OPENAPI)
        return httpx.Response(404, text="not found")

    return handler


# -- D1 spec-first OpenAPI --------------------------------------------------------


def test_openapi_json_materializes_endpoints_and_params() -> None:
    g = ReachabilityGraph()
    firer, a = _firer(_openapi_handler())
    result = discover_api(g, firer, f"https://{_TARGET}")
    assert result.spec_found is True
    assert result.spec_kind == "openapi"
    endpoints = {ep.path: ep for _, ep in g.endpoints()}
    assert "/users/v1/{username}" in endpoints
    assert "/books/v1" in endpoints
    # Method-level endpoints: GET /books/v1 and POST /books/v1 both materialize.
    methods = {ep.method for _, ep in g.endpoints() if ep.path == "/books/v1"}
    assert methods == {"GET", "POST"}
    # Parameters with correct locations.
    params = {
        (ep.path, p.name, p.location)
        for ep_node, ep in g.endpoints()
        for _pn, p in g.parameters_of(ep_node)
    }
    assert ("/users/v1/{username}", "username", "path") in params
    assert ("/books/v1", "Authorization", "header") in params
    assert ("/books/v1", "book_title", "body") in params
    # Facts only — zero findings/candidates/can_call.
    assert g.findings() == [] and g.can_call_edges() == []


def test_swagger_and_v3_variants_parsed_identically() -> None:
    for spec_path in ("/swagger.json", "/v3/api-docs", "/api/openapi.json"):
        g = ReachabilityGraph()
        firer, _a = _firer(_openapi_handler(spec_path))
        result = discover_api(g, firer, f"https://{_TARGET}")
        assert result.spec_found is True, f"{spec_path} not found"
        assert any(ep.path == "/users/v1/{username}" for _, ep in g.endpoints())


# -- D1 GraphQL introspection ------------------------------------------------------


_GRAPHQL_SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [
                {
                    "name": "Query",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "publicProducts", "type": {"name": "Product"}, "args": []},
                        {
                            "name": "userSecret",
                            "type": {"name": "String"},
                            "args": [{"name": "id"}],
                        },
                    ],
                }
            ],
        }
    }
}


def test_graphql_introspection_fields_as_parameters() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "graphql" in request.url.path and "query" in request.url.params:
            return httpx.Response(200, json=_GRAPHQL_SCHEMA)
        return httpx.Response(404, text="not found")

    g = ReachabilityGraph()
    firer, _a = _firer(handler)
    result = discover_api(g, firer, f"https://{_TARGET}")
    assert result.spec_found is True
    assert result.spec_kind == "graphql"
    # GraphQL endpoint materialized as a POST /graphql with fields as parameters.
    gql_ep = next((ep for _, ep in g.endpoints() if ep.path == "/graphql"), None)
    assert gql_ep is not None and gql_ep.protocol is Protocol.GRAPHQL
    ep_node = next(n for n, ep in g.endpoints() if ep.path == "/graphql")
    param_names = {p.name for _, p in g.parameters_of(ep_node)}
    assert "publicProducts" in param_names and "userSecret" in param_names


# -- D2 combinatorial fallback -----------------------------------------------------


def test_no_spec_falls_back_to_bounded_combinatorial() -> None:
    hits: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/api/v1/users", "/v1/books"):
            hits.append(request.url.path)
            return httpx.Response(200, text="ok")
        return httpx.Response(404, text="not found")

    g = ReachabilityGraph()
    firer, a = _firer(handler)
    result = discover_api(g, firer, f"https://{_TARGET}")
    assert result.spec_found is False
    assert result.fallback_probes <= 50
    paths = {ep.path for _, ep in g.endpoints()}
    assert "/api/v1/users" in paths and "/v1/books" in paths
    # Non-2xx skipped.
    assert "/api/v1/orders" not in paths
    assert g.findings() == [] and g.can_call_edges() == []


# -- scope + audit + read-only -----------------------------------------------------


def test_probes_are_read_only_and_scope_held() -> None:
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        return httpx.Response(404, text="nope")

    g = ReachabilityGraph()
    firer, a = _firer(handler)
    discover_api(g, firer, f"https://{_TARGET}")
    assert all(m == "GET" for m in methods)
    assert len(methods) >= 1  # at least the spec probes fired

    # Out-of-scope target: the firer refuses every probe (scope held, no packet),
    # discover_api swallows the refusal and reports an honest no-spec result.
    out_audit = AuditLog()
    out_scope_firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(handler)),  # type: ignore[arg-type]
        ScopeGuard.from_hosts(["in-scope.test"]),
        out_audit,
    )
    g2 = ReachabilityGraph()
    result = discover_api(g2, out_scope_firer, f"https://{_TARGET}")
    assert result.spec_found is False
    assert g2.endpoints() == []
    assert any(e.outcome == "refused_out_of_scope" for e in out_audit.entries)


# -- Component 2: --surface seeding ------------------------------------------------


def test_surface_seeds_endpoints_before_recon(tmp_path: Path) -> None:
    surface = tmp_path / "surface.yaml"
    surface.write_text(
        "endpoints:\n"
        "  - method: GET\n"
        "    path: /users/v1/{username}\n"
        "    parameters:\n"
        "      - name: username\n"
        "        location: path\n"
        "  - method: GET\n"
        "    path: /createdb\n"
        "    state_changing: true\n"
    )
    g = ReachabilityGraph()
    a = AuditLog()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    result = scan_target(
        base_url=f"https://{_TARGET}",
        in_scope="target.test",
        dry_run=True,
        transport=httpx.MockTransport(handler),
        graph=g,
        audit=a,
        surface_path=str(surface),
    )
    paths = {ep.path for _, ep in g.endpoints()}
    assert "/users/v1/{username}" in paths
    assert "/createdb" in paths  # state-changing materialized, not fired
    assert result["dry_run"] is True
    # Zero state-changing fires (read-only-first held; dry-run fires nothing anyway).
    assert not any(e.outcome.startswith("fired:") for e in a.entries)


def test_no_surface_unchanged_cold_start() -> None:
    g = ReachabilityGraph()
    a = AuditLog()
    scan_target(
        base_url=f"https://{_TARGET}",
        in_scope="target.test",
        dry_run=True,
        graph=g,
        audit=a,
        fixtures={"gobuster": "/items (Status: 200)\n"},
    )
    paths = {ep.path for _, ep in g.endpoints()}
    assert "/items" in paths
    assert "/users/v1/{username}" not in paths


# Surface pass-through is exercised by tests/scan/test_orchestrator.py (the orchestrator
# calls scan_target with surface_path and the seeded endpoints materialize in the graph).


# -- AST: six families + no validator -------------------------------------------------


def test_api_discovery_imports_no_validator() -> None:
    import reachagent.recon.api_discovery as mod

    tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
    forbidden = (
        "reachagent.tools.validator",
        "reachagent.tools.candidate",
        "run_oracle",
        "write_finding",
        "Candidate",
    )
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if any(f in node.module for f in forbidden):
                offenders.append(f"from {node.module}")
            for alias in node.names:
                if any(f in alias.name for f in forbidden):
                    offenders.append(f"import {alias.name}")
        if isinstance(node, ast.Name) and node.id == "Candidate":
            offenders.append("bare Candidate symbol")
    assert offenders == []


def test_six_oracle_families_unchanged() -> None:
    assert set(OracleMechanism) == {
        OracleMechanism.DIFFERENTIAL,
        OracleMechanism.STRUCTURAL,
        OracleMechanism.TIMING_STATISTICAL,
        OracleMechanism.OOB_CALLBACK,
        OracleMechanism.EXECUTION_CONFIRMATION,
        OracleMechanism.BUSINESS_RULE_INVARIANT,
    }
