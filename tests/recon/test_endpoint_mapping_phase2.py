"""Focused Phase 2 tests: forms, schemas, browser/API calls, and ranking."""

from __future__ import annotations

import httpx

from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import Endpoint, Host, Parameter
from reachagent.graph.store import ReachabilityGraph, endpoint_id
from reachagent.identity.store import Credential, IdentityStore
from reachagent.recon.api_discovery import discover_api
from reachagent.recon.mapper import SurfaceMapper, SurfaceSpec
from reachagent.recon.surface import parse_html_surface, parse_javascript_surface
from reachagent.recon.surface_tuning import (
    build_insertion_summaries,
    propose_surface_priority,
)
from reachagent.recon.tools.arjun import ArjunRunner
from reachagent.recon.tools.x8 import X8Runner


def test_html_forms_preserve_method_csrf_and_serialization() -> None:
    surface = parse_html_surface(
        """
        <a href='/search?q=books'>search</a>
        <form action='/account/update' method='POST' enctype='application/x-www-form-urlencoded'>
          <input type='hidden' name='csrf_token' value='token-example' required>
          <input name='display_name' required>
        </form>
        <form action='/upload' method='post' enctype='multipart/form-data'>
          <input type='file' name='avatar'>
          <textarea name='caption'></textarea>
        </form>
        <script src='/assets/app.js'></script>
        """,
        "https://target.test/",
    )
    forms = {endpoint.path: endpoint for endpoint in surface.endpoints}
    update = forms["/account/update"]
    assert update.method == "POST" and update.state_changing
    assert {(p.name, p.location, p.serialization) for p in update.parameters} == {
        ("csrf_token", "form", "application/x-www-form-urlencoded"),
        ("display_name", "form", "application/x-www-form-urlencoded"),
    }
    upload = forms["/upload"]
    assert {p.location for p in upload.parameters} == {"multipart"}
    search = forms["/search"]
    assert search.parameters[0].name == "q" and search.parameters[0].location == "query"
    assert surface.scripts == ("https://target.test/assets/app.js",)


def test_html_links_to_a_different_host_are_not_materialized_as_same_site_paths() -> None:
    surface = parse_html_surface(
        """
        <a href='/search?q=books'>search</a>
        <a href='https://github.com/digininja/DVWA'>project home</a>
        <form action='https://accounts.google.com/o/oauth2/auth' method='GET'>
          <input name='client_id'>
        </form>
        """,
        "https://target.test/",
    )
    paths = {endpoint.path for endpoint in surface.endpoints}
    assert paths == {"/search"}
    assert "/digininja/DVWA" not in paths
    assert "/o/oauth2/auth" not in paths


def test_javascript_calls_capture_methods_body_fields_and_graphql() -> None:
    surface = parse_javascript_surface(
        """
        fetch('/api/users?id=7', {method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({email: userEmail, role: 'user'})});
        const xhr = new XMLHttpRequest(); xhr.open('GET', '/api/profile?view=full');
        axios.get('/graphql', {params: {query: 'query Q { userSecret(id: 1) }'}});
        """,
        "https://target.test/assets/app.js",
    )
    endpoints = {(e.method, e.path, e.protocol.value): e for e in surface.endpoints}
    api = endpoints[("POST", "/api/users", "rest")]
    assert {p.name for p in api.parameters} >= {"id", "email", "role"}
    assert all(p.location in {"query", "json"} for p in api.parameters)
    gql = endpoints[("GET", "/graphql", "graphql")]
    assert any(p.location == "graphql" for p in gql.parameters)
    assert any(p.name == "userSecret.id" for p in gql.parameters)


def test_openapi_request_body_refs_and_cookie_header_locations() -> None:
    document = {
        "openapi": "3.0.3",
        "components": {
            "schemas": {
                "Create": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": {"type": "string", "example": "alice"},
                        "age": {"type": "integer", "default": 2},
                    },
                }
            }
        },
        "paths": {
            "/users/{id}": {
                "parameters": [{"name": "id", "in": "path", "example": "u-1"}],
                "get": {
                    "parameters": [
                        {"name": "X-Tenant", "in": "header", "required": True},
                        {"name": "sid", "in": "cookie"},
                    ]
                },
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Create"}}
                        },
                    }
                },
            }
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=document)
        return httpx.Response(404)

    graph = ReachabilityGraph()
    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(handler)),
        ScopeGuard.from_hosts(["target.test"]),
        AuditLog(),
    )
    result = discover_api(graph, firer, "https://target.test")
    assert result.spec_found and len(result.endpoints) == 2
    get_ep = endpoint_id("GET", "/users/{id}")
    post_ep = endpoint_id("POST", "/users/{id}")
    get_params = {(p.name, p.location) for _, p in graph.parameters_of(get_ep)}
    assert get_params == {("id", "path"), ("X-Tenant", "header"), ("sid", "cookie")}
    post_params = {(p.name, p.location, p.required) for _, p in graph.parameters_of(post_ep)}
    assert {name for name, _location, _required in post_params} == {"id", "name", "age"}
    assert any(p.required for _, p in graph.parameters_of(post_ep))
    assert graph.endpoint(post_ep).request_body == '{"age": 2, "name": "alice"}'


def test_live_html_discovery_is_scoped_and_never_submits_forms() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/":
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="<form action='/login' method='POST'><input name='user'></form>"
                "<a href='/catalog?id=2'>catalog</a><a href='https://evil.test/x'>off</a>"
                "<script src='/app.js'></script>",
            )
        if request.url.path == "/app.js":
            return httpx.Response(
                200,
                headers={"content-type": "application/javascript"},
                text="fetch('/api/items?sort=asc')",
            )
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<p>ok</p>")

    graph = ReachabilityGraph()
    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(handler)),
        ScopeGuard.from_hosts(["target.test"]),
        AuditLog(),
    )
    result = discover_api(graph, firer, "https://target.test")
    paths = {endpoint.path for _, endpoint in graph.endpoints()}
    assert result.pages_crawled >= 1
    assert {"/login", "/catalog", "/api/items"} <= paths
    assert not any(request.method != "GET" for request in requests)
    assert not any(
        endpoint.source and "evil.test" in endpoint.source for _, endpoint in graph.endpoints()
    )


def test_mapper_builds_benign_location_specific_probe() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    spec = SurfaceSpec.from_mapping(
        {
            "endpoints": [
                {
                    "method": "GET",
                    "path": "/search",
                    "parameters": [
                        {"name": "q", "location": "query", "example": "books"},
                        {"name": "sid", "location": "cookie", "example": "session"},
                    ],
                }
            ]
        }
    )
    graph = ReachabilityGraph()
    identities = IdentityStore()
    identities.add(Credential(identity="probe", username="probe", password="secret", role="user"))
    mapper = SurfaceMapper(
        graph,
        RequestFirer(
            httpx.Client(transport=httpx.MockTransport(handler)),
            ScopeGuard.from_hosts(["target.test"]),
            AuditLog(),
        ),
        identities,
        "https://target.test",
    )
    mapper.run(spec)
    endpoint = endpoint_id("GET", "/search")
    assert {p.location for _, p in graph.parameters_of(endpoint)} == {"query", "cookie"}
    assert seen and seen[0].url.params.get("q") == "books"
    assert seen[0].headers.get("cookie") == "sid=session"


def test_insertion_wrappers_attach_to_the_reported_endpoint() -> None:
    for runner_cls, raw in (
        (ArjunRunner, '{"https://target.test/admin": ["next"]}'),
        (X8Runner, "https://target.test/search?q=x\nparam 'debug' reflected"),
    ):
        graph = ReachabilityGraph()
        runner = runner_cls(
            graph=graph, scope=ScopeGuard.from_hosts(["target.test"]), audit=AuditLog()
        )
        runner.ingest("target.test", raw)
        endpoint = endpoint_id("GET", "/admin" if runner_cls is ArjunRunner else "/search")
        names = {parameter.name for _, parameter in graph.parameters_of(endpoint)}
        assert names


def test_llm_surface_ranking_validates_parameter_ids(monkeypatch) -> None:  # noqa: ANN001
    graph = ReachabilityGraph()
    graph.add_host(Host(address="target.test"))
    endpoint = graph.add_endpoint(Endpoint(method="POST", path="/account"))
    parameter = graph.add_parameter(
        endpoint,
        Parameter(name="email", location="form", serialization="application/x-www-form-urlencoded"),
    )

    class Client:
        def propose(self, summaries, operator_prompt, target_type):  # noqa: ANN001
            return {
                "ranked_ids": [endpoint, "not-in-graph"],
                "ranked_parameter_ids": [parameter, "fake-param"],
                "rationale": "form endpoint with an account identifier",
            }

    monkeypatch.setenv("REACHAGENT_SURFACE_TUNING", "1")
    result = propose_surface_priority(graph, client=Client())
    assert result is not None
    assert result.ranked_ids == (endpoint,)
    assert result.ranked_parameter_ids == (parameter,)
    assert build_insertion_summaries(graph)[0].location == "form"
