"""Tests for OpenAPI/GraphQL spec ingestion, incl. the spec-can't-self-grant-scope guarantee."""

from __future__ import annotations

import httpx

from lalo.execution.firer import HttpFirer
from lalo.execution.scope import ScopeGuard
from lalo.execution.target import Engagement
from lalo.graph import ReachabilityGraph
from lalo.recon import (
    fetch_openapi_facts,
    merge_facts,
    parse_graphql_introspection,
    parse_postman_collection,
)


def _firer(handler) -> HttpFirer:
    eng = Engagement.from_specs(["app.example.com"])
    scope = ScopeGuard(engagement=eng, resolver=lambda h: frozenset({"93.184.216.34"}))
    return HttpFirer(scope, client=httpx.Client(transport=httpx.MockTransport(handler)))


_OPENAPI_DOC = {
    "openapi": "3.0.0",
    "paths": {
        "/users": {"get": {}, "post": {}},
        "/users/{id}": {"get": {}, "delete": {}},
    },
}


def test_fetch_openapi_facts_builds_one_endpoint_fact_per_path() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_OPENAPI_DOC)

    facts = fetch_openapi_facts(_firer(handler), "https://app.example.com/openapi.json")
    urls = {f.url for f in facts}
    assert urls == {"https://app.example.com/users", "https://app.example.com/users/{id}"}
    by_url = {f.url: f for f in facts}
    assert by_url["https://app.example.com/users"].extra["methods"] == ["GET", "POST"]


def test_fetch_openapi_facts_ignores_the_specs_own_claimed_servers_url() -> None:
    # The spec claims requests actually go to a completely different host --
    # this must never redirect where the resulting facts point.
    malicious_doc = {
        **_OPENAPI_DOC,
        "servers": [{"url": "https://attacker-controlled.example.org"}],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=malicious_doc)

    facts = fetch_openapi_facts(_firer(handler), "https://app.example.com/openapi.json")
    assert all(f.url.startswith("https://app.example.com/") for f in facts)
    assert not any("attacker-controlled" in f.url for f in facts)


def test_openapi_facts_from_an_out_of_engagement_spec_url_are_never_fired() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("an out-of-engagement spec URL must not be fired at all")

    facts = fetch_openapi_facts(_firer(handler), "https://evil.example.org/openapi.json")
    assert facts == []


def test_facts_from_a_legitimately_fetched_spec_still_pass_through_the_scope_gate() -> None:
    # Defense in depth: even a fact this module produced from an in-engagement
    # fetch is checked again by merge_facts before it can become a graph node.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_OPENAPI_DOC)

    facts = fetch_openapi_facts(_firer(handler), "https://app.example.com/openapi.json")
    graph = ReachabilityGraph()
    scope = ScopeGuard(
        engagement=Engagement.from_specs(["app.example.com"]),
        resolver=lambda h: frozenset({"93.184.216.34"}),
    )
    report = merge_facts(graph, scope, facts)
    assert len(report.accepted) == 2
    assert report.rejected == []


def test_fetch_openapi_facts_ignores_non_operation_sibling_keys() -> None:
    # A Path Item Object legitimately carries non-operation sibling fields
    # (summary, description, parameters, servers, $ref, ...) alongside real
    # HTTP methods, per the OpenAPI 3.x / Swagger 2.0 spec -- those must never
    # be recorded as if they were methods themselves.
    doc = {
        "paths": {
            "/users": {
                "summary": "Users collection",
                "description": "...",
                "parameters": [{"name": "id"}],
                "get": {},
            },
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=doc)

    facts = fetch_openapi_facts(_firer(handler), "https://app.example.com/openapi.json")
    assert facts[0].extra["methods"] == ["GET"]


def test_fetch_openapi_facts_returns_empty_on_non_2xx_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    assert fetch_openapi_facts(_firer(handler), "https://app.example.com/openapi.json") == []


def test_fetch_openapi_facts_returns_empty_on_malformed_json() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json at all")

    assert fetch_openapi_facts(_firer(handler), "https://app.example.com/openapi.json") == []


def test_parse_graphql_introspection_extracts_type_names() -> None:
    introspection = {
        "data": {
            "__schema": {
                "types": [{"name": "User"}, {"name": "Query"}, {"not_name": "skip me"}],
            }
        }
    }
    facts = parse_graphql_introspection(introspection, "https://app.example.com/graphql")
    assert len(facts) == 1
    assert facts[0].url == "https://app.example.com/graphql"
    assert facts[0].extra["graphql_types"] == ["User", "Query"]


def test_parse_graphql_introspection_handles_malformed_shape_gracefully() -> None:
    facts = parse_graphql_introspection({"data": None}, "https://app.example.com/graphql")
    assert facts[0].extra["graphql_types"] == []


def test_parse_postman_collection_extracts_a_flat_request() -> None:
    collection = {
        "item": [
            {
                "name": "Get users",
                "request": {"method": "GET", "url": "https://app.example.com/users"},
            }
        ]
    }
    facts = parse_postman_collection(collection)
    assert len(facts) == 1
    assert facts[0].url == "https://app.example.com/users"
    assert facts[0].source == "postman"
    assert facts[0].extra["methods"] == ["GET"]


def test_parse_postman_collection_handles_the_structured_url_object() -> None:
    collection = {
        "item": [
            {
                "request": {
                    "method": "POST",
                    "url": {"raw": "https://app.example.com/login", "host": ["app", "example"]},
                }
            }
        ]
    }
    facts = parse_postman_collection(collection)
    assert facts[0].url == "https://app.example.com/login"
    assert facts[0].extra["methods"] == ["POST"]


def test_parse_postman_collection_recurses_through_nested_folders() -> None:
    collection = {
        "item": [
            {
                "name": "Auth",
                "item": [
                    {
                        "name": "Users",
                        "item": [
                            {
                                "request": {
                                    "method": "GET",
                                    "url": "https://app.example.com/deep",
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    facts = parse_postman_collection(collection)
    assert len(facts) == 1
    assert facts[0].url == "https://app.example.com/deep"


def test_parse_postman_collection_skips_unresolved_template_variables() -> None:
    # Guessing what {{baseUrl}} resolves to would risk fabricating an
    # endpoint that was never actually declared -- skip it instead.
    collection = {
        "item": [
            {"request": {"method": "GET", "url": "{{baseUrl}}/users"}},
            {"request": {"method": "GET", "url": "https://app.example.com/real"}},
        ]
    }
    facts = parse_postman_collection(collection)
    assert len(facts) == 1
    assert facts[0].url == "https://app.example.com/real"


def test_parse_postman_collection_caps_pathological_folder_depth() -> None:
    # Build a collection nested far past the depth cap; a request at the
    # bottom of that pathological chain must never be reached at all.
    leaf = {"request": {"method": "GET", "url": "https://app.example.com/too-deep"}}
    collection: dict[str, object] = {"item": [leaf]}
    for _ in range(40):
        collection = {"item": [collection]}
    facts = parse_postman_collection(collection)
    assert facts == []


def test_parse_postman_collection_ignores_malformed_entries() -> None:
    collection = {
        "item": [
            "not a dict",
            {"request": "not a dict either"},
            {"request": {"url": None}},
            {},
        ]
    }
    assert parse_postman_collection(collection) == []


def test_parse_postman_collection_handles_a_non_dict_or_missing_item_list() -> None:
    assert parse_postman_collection({}) == []
    assert parse_postman_collection({"item": "not a list"}) == []
