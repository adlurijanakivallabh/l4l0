"""Hermetic Phase 4 GraphQL module tests for DVGA-shaped behavior."""

from __future__ import annotations

import ast
from pathlib import Path

import httpx
import pytest

from reachagent.execution import AuditLog, RequestFirer, ScopeGuard
from reachagent.graph.nodes import Protocol
from reachagent.graph.store import ReachabilityGraph
from reachagent.graphql import (
    ComplexityMeasurement,
    GraphQLClient,
    GraphQLResponse,
    check_batch_bypass,
    discover_schema,
    materialize_schema,
    measure_complexity_regression,
    resolver_bola_check,
)
from reachagent.oracles.timing_statistical import ValidationError
from tests._oracle_test_support import ALLOWS, CONFIRMS, DENIES, fixed_oracle_runner

_INTROSPECTION_BODY = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [
                {
                    "name": "Query",
                    "kind": "OBJECT",
                    "fields": [
                        {
                            "name": "publicProducts",
                            "type": {"name": "Product", "kind": "OBJECT", "ofType": None},
                            "args": [],
                        },
                        {
                            "name": "userSecret",
                            "type": {"name": "String", "kind": "SCALAR", "ofType": None},
                            "args": [{"name": "id"}],
                        },
                    ],
                }
            ],
        }
    }
}


def _client(handler: object) -> GraphQLClient:
    def dispatch(request: httpx.Request) -> httpx.Response:
        return handler(request)  # type: ignore[operator, no-any-return]

    http_client = httpx.Client(transport=httpx.MockTransport(dispatch))
    firer = RequestFirer(http_client, ScopeGuard.from_hosts(["dvga.test"]), AuditLog())
    return GraphQLClient(firer, base_url="http://dvga.test")


def test_introspection_enabled_recovers_query_fields() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "__schema" in request.url.params["query"]
        return httpx.Response(200, json=_INTROSPECTION_BODY)

    schema = discover_schema(_client(handler), "analyst")
    assert schema.introspection_enabled is True
    assert schema.query_type == "Query"
    assert [field.name for field in schema.fields] == ["publicProducts", "userSecret"]
    assert schema.fields[1].arguments == ("id",)


def test_introspection_disabled_uses_field_suggestion_fallback() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        query = request.url.params["query"]
        if "__schema" in query:
            return httpx.Response(400, json={"errors": [{"message": "Introspection is disabled"}]})
        return httpx.Response(
            400,
            json={"errors": [{"message": 'Cannot query field "users" on type "Query".'}]},
        )

    schema = discover_schema(_client(handler), "analyst", suggestions=["usr"])
    assert schema.introspection_enabled is False
    assert [field.name for field in schema.fields] == ["users", "usr"]


def test_schema_facts_materialize_as_graphql_endpoint_and_parameters() -> None:
    graph = ReachabilityGraph()
    schema = discover_schema(
        _client(lambda r: httpx.Response(200, json=_INTROSPECTION_BODY)), "analyst"
    )
    endpoint, parameters = materialize_schema(graph, schema)
    assert graph.endpoint(endpoint).protocol is Protocol.GRAPHQL
    assert set(parameters) == {"publicProducts", "userSecret"}
    assert {param.name for _, param in graph.parameters_of(endpoint)} == set(parameters)


# v3 (CLAUDE.md): decide() is gone — confirmation is now an LLM judgment, not
# something a hermetic test can re-derive deterministically. These tests now
# assert on WIRING (does resolver_bola_check/check_batch_bypass correctly
# relay a given oracle verdict into `.confirmed`/`.is_violation`) via an
# injected `oracle_runner`, not on judgment itself.


def test_resolver_bola_reuses_differential_and_public_field_is_not_flagged() -> None:
    owner = GraphQLResponse(200, '{"data":{"userSecret":"owner-value"}}')
    same_private = GraphQLResponse(200, '{"data":{"userSecret":"owner-value"}}')
    public = resolver_bola_check(
        owner, same_private, public=True, oracle_runner=fixed_oracle_runner(ALLOWS)
    )
    private = resolver_bola_check(
        owner, same_private, public=False, oracle_runner=fixed_oracle_runner(CONFIRMS)
    )
    assert public.confirmed is True
    assert public.is_violation is False
    assert private.confirmed is True
    assert private.is_violation is True


def test_resolver_bola_denied_probe_is_confirmed_safe() -> None:
    verdict = resolver_bola_check(
        GraphQLResponse(200, '{"data":{"userSecret":"owner-value"}}'),
        GraphQLResponse(403, '{"errors":[{"message":"forbidden"}]}'),
        oracle_runner=fixed_oracle_runner(DENIES),
    )
    assert verdict.confirmed is True
    assert verdict.is_violation is False


def test_batch_alias_bypass_reuses_differential_auth_bypass() -> None:
    verdict = check_batch_bypass(
        GraphQLResponse(403, '{"errors":[{"message":"rate limited"}]}'),
        GraphQLResponse(200, '{"data":{"a":1,"b":1}}'),
        oracle_runner=fixed_oracle_runner(CONFIRMS),
    )
    assert verdict.confirmed is True
    assert verdict.is_violation is True


def test_batch_alias_rate_limit_enforced_is_not_a_finding() -> None:
    verdict = check_batch_bypass(
        GraphQLResponse(403, "blocked"),
        GraphQLResponse(403, "blocked"),
        oracle_runner=fixed_oracle_runner(DENIES),
    )
    assert verdict.confirmed is True
    assert verdict.is_violation is False


def _curve(values: list[float], depths: tuple[int, ...] = (1, 2)) -> list[ComplexityMeasurement]:
    return [ComplexityMeasurement(depth, value) for depth in depths for value in values]


def _depth_curve(values_by_depth: dict[int, list[float]]) -> list[ComplexityMeasurement]:
    return [
        ComplexityMeasurement(depth, value)
        for depth, values in values_by_depth.items()
        for value in values
    ]


def test_complexity_regression_confirms_escalating_curve() -> None:
    baseline_values = [100, 101, 102, 103, 104, 105, 106, 107, 108, 109]
    baseline = _depth_curve({1: baseline_values, 2: [value + 100 for value in baseline_values]})
    escalated = _depth_curve({1: baseline_values, 2: [value + 400 for value in baseline_values]})
    verdict = measure_complexity_regression(
        baseline, escalated, oracle_runner=fixed_oracle_runner(CONFIRMS)
    )
    assert verdict.confirmed is True
    assert verdict.is_violation is True


def test_complexity_baseline_noise_only_has_zero_false_positive() -> None:
    baseline_values = [100, 101, 102, 103, 104, 105, 106, 107, 108, 109]
    baseline = _depth_curve({1: baseline_values, 2: [value + 100 for value in baseline_values]})
    noise = _depth_curve(
        {
            1: [101, 100, 103, 102, 105, 104, 107, 106, 109, 108],
            2: [201, 200, 203, 202, 205, 204, 207, 206, 209, 208],
        }
    )
    for _ in range(5):
        verdict = measure_complexity_regression(baseline, noise)
        assert verdict.confirmed is False
        assert verdict.is_violation is False


def test_complexity_regression_requires_paired_trials() -> None:
    baseline = _curve([100] * 9)
    probe = _curve([500] * 9)
    with pytest.raises(ValidationError):
        measure_complexity_regression(baseline, probe)


def test_graphql_client_rejects_mutation_before_network() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    with pytest.raises(ValueError, match="read-only"):
        _client(handler).query("analyst", "mutation { deleteUser(id: 1) }")
    assert called is False


def test_graphql_module_uses_only_existing_oracle_families() -> None:
    path = Path(__file__).parents[2] / "src" / "reachagent" / "graphql" / "module.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mechanisms = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "OracleMechanism"
        and node.attr.isupper()
    }
    assert mechanisms == {"DIFFERENTIAL", "TIMING_STATISTICAL"}
    imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not any("tools.validator" in module for module in imports)
