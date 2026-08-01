"""GraphQL discovery and deterministic probe seams for DVGA-shaped targets.

GraphQL queries use the existing read-only HTTP execution layer. Schema fields are
materialized as Parameters on one GraphQL Endpoint-shaped node; no GraphQL-specific
node or oracle exists. Resolver authorization reuses the differential family, batch
bypass uses its auth-bypass expectation, and complexity regression reuses the paired
``timing_statistical`` family.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from statistics import mean

from reachagent.detection.oracle_gateway import OracleOutcome, OracleRunner, registry_runner
from reachagent.execution.firer import RequestFirer
from reachagent.graph.nodes import Endpoint, Parameter, Protocol
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.oracles.differential import (
    DiffAxis,
    DifferentialEvidence,
    DiffExpectation,
    Observation,
)
from reachagent.oracles.timing_statistical import PairedTrialEvidence, ValidationError

_INTROSPECTION_QUERY = (
    "query ReachAgentSchema { __schema { queryType { name } "
    "types { name kind fields { name type { name kind ofType { name kind } } "
    "args { name } } } } }"
)
_FIELD_SUGGESTION = re.compile(r"Cannot query field (?:\\)?[\"'](?P<field>[A-Za-z_][A-Za-z0-9_]*)")


@dataclass(frozen=True)
class GraphQLField:
    """Recovered GraphQL field, represented as an input parameter in graph facts."""

    name: str
    parent_type: str = "Query"
    return_type: str | None = None
    arguments: tuple[str, ...] = ()
    public: bool | None = None


@dataclass(frozen=True)
class GraphQLSchema:
    """Schema facts recovered by introspection or field suggestions."""

    query_type: str
    fields: tuple[GraphQLField, ...]
    introspection_enabled: bool


@dataclass(frozen=True)
class GraphQLResponse:
    """JSON-safe response signal captured by the GraphQL client."""

    status_code: int
    body: str
    elapsed_seconds: float = 0.0


@dataclass(frozen=True)
class ComplexityMeasurement:
    """One latency sample at a query-depth/complexity level."""

    depth: int
    latency_ms: float


class GraphQLClient:
    """Read-only GraphQL query client backed by scope/read-only execution gates."""

    def __init__(self, firer: RequestFirer, *, base_url: str, endpoint_path: str = "/graphql"):
        self._firer = firer
        self._url = base_url.rstrip("/") + "/" + endpoint_path.lstrip("/")

    def query(
        self,
        identity: str,
        document: str,
        *,
        variables: Mapping[str, object] | None = None,
    ) -> GraphQLResponse:
        """Send GraphQL query over GET; mutations are rejected before network I/O."""
        if re.search(r"\bmutation\b", document, re.IGNORECASE):
            raise ValueError("GraphQLClient only sends read-only queries")
        result = self._firer.fire(
            identity,
            "GET",
            self._url,
            params={
                "query": document,
                "variables": json.dumps(dict(variables or {}), sort_keys=True),
            },
        )
        return GraphQLResponse(
            status_code=result.status_code,
            body=result.body.decode("utf-8", errors="replace"),
            elapsed_seconds=result.elapsed_seconds,
        )


def _json_body(response: GraphQLResponse) -> object:
    try:
        return json.loads(response.body)
    except (TypeError, ValueError):
        return response.body


def _introspection_fields(body: object) -> tuple[str, tuple[GraphQLField, ...]]:
    if not isinstance(body, Mapping):
        raise ValueError("GraphQL introspection response must be a JSON object")
    schema = body.get("data", {}).get("__schema") if isinstance(body.get("data"), Mapping) else None
    if not isinstance(schema, Mapping):
        raise ValueError("GraphQL introspection response has no data.__schema")
    query_type = schema.get("queryType", {}).get("name", "Query")
    fields: list[GraphQLField] = []
    for type_info in schema.get("types", ()):
        if not isinstance(type_info, Mapping) or type_info.get("name") != query_type:
            continue
        for field in type_info.get("fields", ()) or ():
            if not isinstance(field, Mapping) or not field.get("name"):
                continue
            type_info_out = field.get("type", {})
            return_type = _type_name(type_info_out)
            args = tuple(
                str(arg["name"])
                for arg in field.get("args", ()) or ()
                if isinstance(arg, Mapping) and arg.get("name")
            )
            fields.append(GraphQLField(str(field["name"]), str(query_type), return_type, args))
    if not fields:
        raise ValueError("GraphQL introspection response has no query fields")
    return str(query_type), tuple(sorted(fields, key=lambda field: field.name))


def _type_name(type_info: object) -> str | None:
    current = type_info
    while isinstance(current, Mapping):
        if current.get("name"):
            return str(current["name"])
        current = current.get("ofType")
    return None


def _suggested_fields(response: GraphQLResponse) -> tuple[GraphQLField, ...]:
    """Extract field suggestions from JSON error messages or raw response text."""
    texts: list[str] = [response.body]
    try:
        parsed = json.loads(response.body)
    except (TypeError, ValueError):
        parsed = None

    def _strings(value: object) -> Iterable[str]:
        if isinstance(value, str):
            yield value
        elif isinstance(value, Mapping):
            for item in value.values():
                yield from _strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from _strings(item)

    texts.extend(_strings(parsed))
    fields = {match.group("field") for text in texts for match in _FIELD_SUGGESTION.finditer(text)}
    if not fields:
        raise ValueError("GraphQL field-suggestion fallback found no fields")
    return tuple(GraphQLField(name) for name in sorted(fields))


def discover_schema(
    client: GraphQLClient,
    identity: str,
    *,
    suggestions: Iterable[str] = (),
) -> GraphQLSchema:
    """Recover schema through ``__schema`` or deterministic field suggestions."""
    introspection = client.query(identity, _INTROSPECTION_QUERY)
    if introspection.status_code < 400:
        try:
            query_type, fields = _introspection_fields(_json_body(introspection))
            return GraphQLSchema(query_type, fields, True)
        except ValueError:
            pass

    recovered: set[str] = set(str(field) for field in suggestions)
    for field in tuple(recovered):
        response = client.query(identity, f"query ReachAgentGuess {{ {field} }}")
        recovered.update(item.name for item in _suggested_fields(response))
    if not recovered:
        raise ValueError("introspection disabled and no field suggestions supplied")
    return GraphQLSchema("Query", tuple(GraphQLField(field) for field in sorted(recovered)), False)


def materialize_schema(
    graph: ReachabilityGraph,
    schema: GraphQLSchema,
    *,
    endpoint_path: str = "/graphql",
) -> tuple[str, dict[str, str]]:
    """Emit GraphQL facts using existing Endpoint/Parameter node types."""
    endpoint_node = graph.add_endpoint(
        Endpoint(method="GET", path=endpoint_path, protocol=Protocol.GRAPHQL)
    )
    parameter_nodes = {
        field.name: graph.add_parameter(endpoint_node, Parameter(field.name, "body"))
        for field in schema.fields
    }
    return endpoint_node, parameter_nodes


def _run_differential(
    baseline: GraphQLResponse,
    probe: GraphQLResponse,
    expectation: DiffExpectation,
    evidence_ref: str,
    oracle_runner: OracleRunner,
) -> OracleOutcome:
    evidence = DifferentialEvidence(
        axis=DiffAxis.CROSS_IDENTITY,
        expectation=expectation,
        baseline=Observation("baseline", baseline.status_code, baseline.body),
        probe=Observation("probe", probe.status_code, probe.body),
        evidence_ref=evidence_ref,
    )
    return oracle_runner(OracleMechanism.DIFFERENTIAL, evidence)


def resolver_bola_check(
    baseline: GraphQLResponse,
    probe: GraphQLResponse,
    *,
    public: bool = False,
    evidence_ref: str = "graphql/resolver",
    oracle_runner: OracleRunner = registry_runner,
) -> OracleOutcome:
    """Check one resolver with existing differential access expectations.

    ``public=True`` selects ``PROBE_AUTHORIZED``; a public field returning the same
    data is therefore confirmed allowed, never a BOLA finding. Private fields use
    ``PROBE_UNAUTHORIZED`` and confirm only when unauthorized data matches baseline.
    """
    expectation = DiffExpectation.PROBE_AUTHORIZED if public else DiffExpectation.PROBE_UNAUTHORIZED
    return _run_differential(baseline, probe, expectation, evidence_ref, oracle_runner)


def check_batch_bypass(
    single: GraphQLResponse,
    batched: GraphQLResponse,
    *,
    evidence_ref: str = "graphql/batch",
    oracle_runner: OracleRunner = registry_runner,
) -> OracleOutcome:
    """Check refused single request versus granted batch/alias request.

    This is the existing differential ``AUTH_BYPASS`` expectation: no structural
    or GraphQL-specific oracle branch is needed. A refused single request followed
    by a granted batched request is the deterministic bypass signal.
    """
    return _run_differential(
        single,
        batched,
        DiffExpectation.AUTH_BYPASS,
        evidence_ref,
        oracle_runner,
    )


def measure_complexity_regression(
    baseline: Sequence[ComplexityMeasurement],
    escalated: Sequence[ComplexityMeasurement],
    *,
    threshold_multiplier: float = 3.0,
    evidence_ref: str = "graphql/complexity",
    oracle_runner: OracleRunner = registry_runner,
) -> OracleOutcome:
    """Normalize latency against same-depth baseline curve, then use timing oracle.

    For each depth, subtract that depth's baseline mean from both arms. The paired
    timing oracle then evaluates residual escalation against measured baseline noise,
    not a hardcoded absolute latency threshold. Both arms retain every trial and
    must contain at least ten samples through the existing oracle validation.
    """
    baseline_by_depth: dict[int, list[float]] = defaultdict(list)
    probe_by_depth: dict[int, list[float]] = defaultdict(list)
    for sample in baseline:
        baseline_by_depth[sample.depth].append(sample.latency_ms)
    for sample in escalated:
        probe_by_depth[sample.depth].append(sample.latency_ms)
    if set(baseline_by_depth) != set(probe_by_depth) or not baseline_by_depth:
        raise ValueError("baseline and escalated complexity curves need matching depths")
    if any(
        len(baseline_by_depth[depth]) < 10 or len(probe_by_depth[depth]) < 10
        for depth in baseline_by_depth
    ):
        raise ValidationError("each complexity depth requires at least 10 paired trials")

    baseline_residuals: list[float] = []
    probe_residuals: list[float] = []
    for depth in sorted(baseline_by_depth):
        center = mean(baseline_by_depth[depth])
        baseline_residuals.extend(value - center for value in baseline_by_depth[depth])
        probe_residuals.extend(value - center for value in probe_by_depth[depth])
    evidence = PairedTrialEvidence(
        probe_latencies_ms=tuple(probe_residuals),
        baseline_latencies_ms=tuple(baseline_residuals),
        threshold_multiplier=threshold_multiplier,
        evidence_ref=evidence_ref,
    )
    return oracle_runner(OracleMechanism.TIMING_STATISTICAL, evidence)
