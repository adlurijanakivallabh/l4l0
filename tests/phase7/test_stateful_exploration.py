"""Focused Phase 7 checks for schema/stateful API exploration."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from reachagent.execution import AuditLog, RequestFirer, ScopeGuard
from reachagent.graph.chain_solver import ChainSolver
from reachagent.graph.nodes import Endpoint, Parameter, Protocol
from reachagent.graph.persistence import dump_graph, load_graph
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.oracles.differential import DiffExpectation
from reachagent.stateful import (
    ObservedExchange,
    ObservedRequest,
    RuntimeBindings,
    SequenceRole,
    StatefulExecution,
    StatefulExplorer,
    StatefulOracleCheck,
    StatefulPlan,
    StatefulPlanError,
    StatefulStep,
    ValueSelector,
    build_request_templates,
    build_stateful_prompt,
    generate_boundary_values,
    ingest_api_spec,
    ingest_graphql_schema,
    ingest_observed_traffic,
    learn_dependencies,
    validate_stateful_plan,
)


def _graph() -> tuple[ReachabilityGraph, str, str, str]:
    graph = ReachabilityGraph()
    producer = graph.add_endpoint(Endpoint(method="GET", path="/items"))
    consumer = graph.add_endpoint(Endpoint(method="GET", path="/items/{id}"))
    param = graph.add_parameter(consumer, Parameter(name="id", location="path", example='"0"'))
    return graph, producer, consumer, param


def _firer(
    handler: Callable[[httpx.Request], httpx.Response],
    audit: AuditLog | None = None,
    *,
    host: str = "api.test",
) -> tuple[RequestFirer, AuditLog]:
    log = audit or AuditLog()
    return (
        RequestFirer(
            httpx.Client(transport=httpx.MockTransport(handler)),
            ScopeGuard.from_hosts([host]),
            log,
        ),
        log,
    )


def test_schema_templates_and_prompt_are_graph_backed() -> None:
    graph, producer, consumer, param = _graph()
    templates = build_request_templates(graph)
    assert [template.endpoint_node for template in templates] == sorted([producer, consumer])
    assert any(param in template.parameter_nodes for template in templates)

    prompt = build_stateful_prompt(graph, target="https://api.test", operator_prompt="find paths")
    assert producer in prompt and consumer in prompt and param in prompt
    assert "raw request bodies" in prompt
    assert '"value"' not in prompt


def test_boundary_values_are_deterministic_and_non_payload() -> None:
    parameter = Parameter(name="quantity", location="json", example="2")
    first = generate_boundary_values(parameter)
    second = generate_boundary_values(parameter)
    assert first == second
    assert first[:5] == (2, 0, 1, -1, 2_147_483_647)
    assert all("<script" not in str(value) for value in first)


def test_validate_stateful_plan_rejects_raw_values_and_unknown_graph_ids() -> None:
    graph, _producer, consumer, param = _graph()
    valid = {
        "rationale": "follow the identifier returned by the collection endpoint",
        "steps": [
            {
                "endpoint_node": consumer,
                "role": "observe",
                "parameters": [{"param_node": param, "selector": "identifier"}],
            }
        ],
    }
    # The selector is valid; absence of a runtime value is reported at execution time.
    plan = validate_stateful_plan(valid, graph)
    assert plan.steps[0].assignments[0][1] is ValueSelector.IDENTIFIER
    firer, _audit = _firer(lambda _request: httpx.Response(200))
    result = StatefulExecution(graph, firer, base_url="https://api.test", identity="guest").run(
        plan
    )
    assert result.observations[0].outcome == "missing_identifier"

    raw_value = json.loads(json.dumps(valid))
    raw_value["steps"][0]["parameters"][0]["value"] = "not accepted"
    with pytest.raises(StatefulPlanError, match="unknown fields"):
        validate_stateful_plan(raw_value, graph)

    unknown = json.loads(json.dumps(valid))
    unknown["steps"][0]["endpoint_node"] = "endpoint:GET /missing"
    with pytest.raises(StatefulPlanError, match="unknown endpoint"):
        validate_stateful_plan(unknown, graph)


def test_probe_requires_an_oracle_and_oracle_steps_are_distinct() -> None:
    graph, producer, consumer, param = _graph()
    probe: dict[str, object] = {
        "rationale": "compare the producer response with a consumer probe",
        "steps": [
            {"endpoint_node": producer, "role": "control"},
            {
                "endpoint_node": consumer,
                "role": "probe",
                "parameters": [{"param_node": param, "selector": "one"}],
            },
        ],
    }
    with pytest.raises(StatefulPlanError, match="probe step requires"):
        validate_stateful_plan(probe, graph)

    probe["oracle"] = {
        "mechanism": "differential",
        "baseline_step": 0,
        "probe_step": 1,
        "expectation": "responses_invariant",
    }
    plan = validate_stateful_plan(probe, graph)
    assert plan.oracle_check is not None
    assert plan.oracle_check.mechanism is OracleMechanism.DIFFERENTIAL
    with pytest.raises(StatefulPlanError, match="different steps"):
        StatefulOracleCheck(
            OracleMechanism.DIFFERENTIAL,
            baseline_step=0,
            probe_step=0,
        )


def test_ingest_openapi_and_postman_materialize_templates() -> None:
    graph = ReachabilityGraph()
    openapi = {
        "openapi": "3.0.0",
        "info": {"title": "Example", "version": "1"},
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                    ]
                }
            }
        },
    }
    templates = ingest_api_spec(graph, openapi, base_url="https://api.test")
    assert len(templates) == 1
    assert templates[0].path == "/users/{id}"
    assert len(templates[0].parameter_nodes) == 1

    postman = {
        "info": {"_postman_id": "collection-1", "name": "Example"},
        "variable": [{"key": "base", "value": "https://api.test"}],
        "item": [
            {
                "name": "create",
                "request": {
                    "method": "POST",
                    "url": "{{base}}/users?role=user",
                    "body": {"mode": "raw", "raw": '{"name":"alice"}'},
                },
            }
        ],
    }
    postman_templates = ingest_api_spec(graph, postman, base_url="https://api.test")
    assert len(postman_templates) == 1
    postman_endpoint = graph.endpoint(postman_templates[0].endpoint_node)
    assert postman_endpoint.state_changing is True
    assert {graph.parameter(node).name for node in postman_templates[0].parameter_nodes} == {
        "role",
        "name",
    }


def test_ingest_graphql_schema_materializes_fields_and_arguments() -> None:
    graph = ReachabilityGraph()
    schema = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [
                    {
                        "name": "Query",
                        "fields": [
                            {"name": "user", "args": [{"name": "id"}]},
                            {"name": "health", "args": []},
                        ],
                    }
                ],
            }
        }
    }
    templates = ingest_graphql_schema(graph, schema, base_url="https://api.test")
    assert len(templates) == 1
    endpoint = graph.endpoint(templates[0].endpoint_node)
    assert endpoint.protocol.value == "graphql"
    assert {graph.parameter(node).name for node in templates[0].parameter_nodes} == {
        "user",
        "user.id",
        "health",
    }


def test_graphql_schema_rejects_document_injection_names() -> None:
    graph = ReachabilityGraph()
    with pytest.raises(StatefulPlanError, match="field name is invalid"):
        ingest_graphql_schema(
            graph,
            {
                "queryType": {"name": "Query"},
                "types": [
                    {
                        "name": "Query",
                        "fields": [{"name": "safe } mutation { dropAll"}],
                    }
                ],
            },
            base_url="https://api.test",
        )


def test_graphql_mutation_is_marked_state_changing_and_gated() -> None:
    graph = ReachabilityGraph()
    endpoint = graph.add_endpoint(
        Endpoint(
            method="POST",
            path="/graphql",
            protocol=Protocol.GRAPHQL,
            graphql_operation_type="mutation",
            state_changing=True,
        )
    )
    parameter = graph.add_parameter(
        endpoint,
        Parameter(name="createItem", location="graphql", serialization="application/json"),
    )
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(405 if request.method == "GET" else 200)

    firer, _audit = _firer(handler)
    plan = StatefulPlan(
        rationale="mutation safety",
        steps=(StatefulStep(endpoint, assignments=((parameter, ValueSelector.ONE),)),),
    )
    result = StatefulExecution(graph, firer, base_url="https://api.test", identity="guest").run(
        plan
    )
    assert seen == ["GET"]
    assert result.observations[0].outcome == "refused_read_only_first"


def test_ingest_observed_traffic_is_same_authority_and_secret_free() -> None:
    graph = ReachabilityGraph()
    templates = ingest_observed_traffic(
        graph,
        [
            ObservedRequest(
                method="POST",
                url="https://api.test/items?limit=2&token=never-store",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer never-store",
                },
                body='{"name":"book","token":"never-store"}',
                evidence_ref="traffic/capture",
            )
        ],
        base_url="https://api.test",
    )
    assert len(templates) == 1
    endpoint = graph.endpoint(templates[0].endpoint_node)
    assert endpoint.request_body is not None
    assert "never-store" not in endpoint.request_body
    assert {graph.parameter(node).name for node in templates[0].parameter_nodes} == {
        "limit",
        "name",
    }
    with pytest.raises(StatefulPlanError, match="outside the target authority"):
        ingest_observed_traffic(
            graph,
            [{"method": "GET", "url": "https://other.test/items"}],
            base_url="https://api.test",
        )


def test_camel_case_identifier_and_minimum_numeric_selector() -> None:
    graph, producer, consumer, _param = _graph()
    graph.add_parameter(consumer, Parameter(name="userId", location="query"))
    facts = learn_dependencies(
        graph,
        [
            ObservedExchange(
                endpoint_node=producer,
                status_code=200,
                response_body='{"userId": 7}',
                evidence_ref="traffic/camel",
            )
        ],
    )
    assert any(graph.parameter(fact.parameter_node).name == "userId" for fact in facts)
    numeric = Parameter(name="limit", location="query", example="5")
    firer, _audit = _firer(lambda _request: httpx.Response(200))
    request_url, _kwargs = StatefulExecution(
        graph, firer, base_url="https://api.test", identity="guest"
    )._request(  # noqa: SLF001 - focused selector assertion
        graph.endpoint(consumer),
        StatefulStep(consumer, assignments=((_param, ValueSelector.MINIMUM),)),
    )
    assert request_url.endswith("/items/0")
    assert generate_boundary_values(numeric)[0] == 5


def test_learn_dependencies_hashes_values_and_uses_header_ids() -> None:
    graph, producer, consumer, param = _graph()
    header_consumer = graph.add_endpoint(Endpoint(method="GET", path="/reports/{id}"))
    header_param = graph.add_parameter(header_consumer, Parameter(name="id", location="path"))
    bindings = RuntimeBindings()
    facts = learn_dependencies(
        graph,
        [
            ObservedExchange(
                endpoint_node=producer,
                status_code=200,
                response_body='{"id":"1234","token":"do-not-store"}',
                response_headers={
                    "Location": "https://api.test/items/1234",
                    "Set-Cookie": "sid=secret",
                },
                evidence_ref="traffic/producer",
            )
        ],
        bindings=bindings,
    )
    assert facts
    assert (producer, consumer) in graph.dependency_edges()
    assert (producer, header_consumer) in graph.dependency_edges()
    assert all(fact.value_ref.startswith("sha256:") for fact in facts)
    assert "1234" not in json.dumps(graph.dependency_details())
    assert "do-not-store" not in json.dumps(graph.dependency_details())
    assert bindings.safe_refs()["id"].startswith("sha256:")
    assert param in {fact.parameter_node for fact in facts}
    assert header_param in {fact.parameter_node for fact in facts}


def test_dependency_edges_round_trip_as_graph_evidence(tmp_path: Path) -> None:
    graph, producer, consumer, param = _graph()
    learn_dependencies(
        graph,
        [
            ObservedExchange(
                endpoint_node=producer,
                status_code=200,
                response_body='{"id":"1234"}',
                evidence_ref="traffic/round-trip",
            )
        ],
    )
    path = tmp_path / "state.json"
    dump_graph(graph, ChainSolver(graph), AuditLog(), path)
    restored, _solver, _audit = load_graph(path)
    assert restored.dependency_edges() == [(producer, consumer)]
    assert restored.dependency_details()[0]["parameter_node"] == param


def test_stateful_execution_binds_identifiers_and_routes_oracle() -> None:
    graph, producer, consumer, param = _graph()
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path == "/items":
            return httpx.Response(200, json={"id": "1234"})
        return httpx.Response(200, json={"id": "1234", "owner": "alice"})

    firer, audit = _firer(handler)
    plan = StatefulPlan(
        rationale="follow a server-produced identifier into its detail endpoint",
        steps=(
            StatefulStep(producer, role=SequenceRole.CONTROL, label="list"),
            StatefulStep(
                consumer,
                assignments=((param, ValueSelector.IDENTIFIER),),
                label="detail",
            ),
        ),
    )
    result = StatefulExplorer(graph, firer, base_url="https://api.test", identity="guest").run(plan)

    assert calls == ["https://api.test/items", "https://api.test/items/1234"]
    assert result.observations[0].status_code == 200
    assert result.observations[1].status_code == 200
    assert result.transitions[0].changed is True
    assert (producer, consumer) in graph.dependency_edges()
    assert len(audit.entries) == 2
    assert all("1234" not in entry.outcome for entry in audit.entries)

    # Replay shape is stable even though response values remain runtime-only.
    assert result.request_signature == plan.replay_key()
    assert result.identifiers[0].value_ref.startswith("sha256:")
    assert not hasattr(result.identifiers[0], "value")


def test_probe_outcome_is_checked_by_existing_differential_oracle() -> None:
    graph = ReachabilityGraph()
    endpoint = graph.add_endpoint(Endpoint(method="GET", path="/echo"))
    param = graph.add_parameter(endpoint, Parameter(name="q", location="query", example='"safe"'))

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("q", "")
        return httpx.Response(200, text=f"echo:{value}")

    firer, audit = _firer(handler)
    plan = StatefulPlan(
        rationale="compare a control value with a bounded probe value",
        steps=(
            StatefulStep(
                endpoint,
                assignments=((param, ValueSelector.EXAMPLE),),
                role=SequenceRole.CONTROL,
                label="control",
            ),
            StatefulStep(
                endpoint,
                assignments=((param, ValueSelector.EMPTY),),
                role=SequenceRole.PROBE,
                label="probe",
            ),
        ),
        oracle_check=StatefulOracleCheck(
            mechanism=OracleMechanism.DIFFERENTIAL,
            baseline_step=0,
            probe_step=1,
            expectation=DiffExpectation.RESPONSES_INVARIANT,
            evidence_ref="stateful/echo",
        ),
    )
    execution = StatefulExecution(graph, firer, base_url="https://api.test", identity="guest")
    result = execution.run(plan)
    assert result.oracle_outcome is not None
    assert result.oracle_outcome.is_violation is True
    assert result.oracle_outcome.status == "confirmed_violation"
    assert any(entry.method == "ORACLE" for entry in audit.entries)


def test_generated_state_changing_request_cannot_bypass_read_only_first() -> None:
    graph = ReachabilityGraph()
    endpoint = graph.add_endpoint(Endpoint(method="POST", path="/mutate", state_changing=True))
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        return httpx.Response(405 if request.method == "GET" else 200)

    firer, audit = _firer(handler)
    plan = StatefulPlan(rationale="test mutation gate", steps=(StatefulStep(endpoint),))
    result = StatefulExecution(graph, firer, base_url="https://api.test", identity="guest").run(
        plan
    )

    assert seen == ["GET"]
    assert result.observations[0].outcome == "refused_read_only_first"
    assert any("refused_read_only_first" in entry.outcome for entry in audit.entries)


def test_scope_refusal_is_audited_and_never_reaches_handler() -> None:
    graph = ReachabilityGraph()
    endpoint = graph.add_endpoint(Endpoint(method="GET", path="/items"))
    called = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    firer, audit = _firer(handler, host="other.test")
    plan = StatefulPlan(rationale="scope test", steps=(StatefulStep(endpoint),))
    result = StatefulExecution(graph, firer, base_url="https://api.test", identity="guest").run(
        plan
    )
    assert called is False
    assert result.observations[0].outcome == "refused_out_of_scope"
    assert any(entry.outcome == "refused_out_of_scope" for entry in audit.entries)
