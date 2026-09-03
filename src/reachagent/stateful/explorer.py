"""Bounded stateful API exploration over the existing graph and fire gates.

This module is deliberately split into two concerns.  ``ingest_api_spec`` and
``learn_dependencies`` only turn schema/traffic observations into graph facts;
``StatefulExecution`` executes a validated, model-proposed sequence.  A model
may choose graph ids, ordering, and a bounded value selector, never a raw URL,
request body, credential, payload, verdict, or finding.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, quote, urlsplit

from reachagent.detection.oracle_gateway import OracleOutcome, OracleRunner, registry_runner
from reachagent.execution.firer import FireResult, ReadOnlyFirstError, RequestFirer
from reachagent.execution.scope import OutOfScopeError
from reachagent.graph.nodes import Endpoint, Host, Parameter, Protocol
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.oracles.business_rule import (
    BusinessRule,
    BusinessRuleEvidence,
    ReplayObservation,
)
from reachagent.oracles.differential import (
    DiffAxis,
    DifferentialEvidence,
    DiffExpectation,
    Observation,
)
from reachagent.oracles.evidence import (
    EvidenceMetadata,
    validate_evidence_ref,
    validate_status_code,
)

MAX_SEQUENCE_STEPS = 16
MAX_ASSIGNMENTS_PER_STEP = 32
MAX_VALUE_CHARS = 512
MAX_RESPONSE_CHARS = 1_000_000
_READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_SECRET_NAME = re.compile(
    r"(?i)(?:password|passwd|secret|token|authorization|auth(?:entication)?|cookie|"
    r"api[_-]?key|csrf|session|jwt|credential)"
)
_IDENTIFIER_NAME = re.compile(r"(?i)(?:^id$|(?:[_-])id$|uuid|identifier|resource[_-]?key)")
_GRAPHQL_NAME = re.compile(r"^[_A-Za-z][_0-9A-Za-z]*$")
_HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "te",
        "transfer-encoding",
        "upgrade",
    }
)
_log = logging.getLogger(__name__)

if TYPE_CHECKING:
    from reachagent.graphql.module import GraphQLSchema


class StatefulPlanError(ValueError):
    """Raised when a model sequence is outside the graph-backed contract."""


class MissingIdentifierError(StatefulPlanError):
    """Raised when a sequence asks for a producer value not observed yet."""


class ValueSelector(StrEnum):
    """Schema-derived, non-payload values the model may request."""

    EXAMPLE = "example"
    EMPTY = "empty"
    ZERO = "zero"
    ONE = "one"
    MINIMUM = "minimum"
    MAXIMUM = "maximum"
    NULL = "null"
    IDENTIFIER = "identifier"


class SequenceRole(StrEnum):
    OBSERVE = "observe"
    CONTROL = "control"
    PROBE = "probe"


@dataclass(frozen=True)
class RequestTemplate:
    """Replayable request shape derived from one graph endpoint."""

    endpoint_node: str
    method: str
    path: str
    protocol: Protocol
    content_type: str | None
    parameter_nodes: tuple[str, ...]
    read_only: bool


@dataclass(frozen=True)
class StatefulStep:
    """One sequence step; assignments contain parameter node + selector only."""

    endpoint_node: str
    assignments: tuple[tuple[str, ValueSelector], ...] = ()
    role: SequenceRole = SequenceRole.OBSERVE
    label: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint_node, str) or not self.endpoint_node:
            raise StatefulPlanError("sequence step endpoint_node must be a graph id")
        if len(self.assignments) > MAX_ASSIGNMENTS_PER_STEP:
            raise StatefulPlanError(
                f"a sequence step may assign at most {MAX_ASSIGNMENTS_PER_STEP} parameters"
            )
        if self.label and len(self.label) > 128:
            raise StatefulPlanError("sequence step label exceeds 128 characters")
        if not isinstance(self.role, SequenceRole):
            raise StatefulPlanError("sequence step role is invalid")
        for param_node, selector in self.assignments:
            if not isinstance(param_node, str) or not param_node:
                raise StatefulPlanError("sequence assignment param_node must be a graph id")
            if not isinstance(selector, ValueSelector):
                raise StatefulPlanError("sequence assignment selector is invalid")


@dataclass(frozen=True)
class StatefulOracleCheck:
    """Deterministic check over two responses in a sequence."""

    mechanism: OracleMechanism
    baseline_step: int
    probe_step: int
    expectation: DiffExpectation = DiffExpectation.RESPONSES_INVARIANT
    rule: BusinessRule | None = None
    evidence_ref: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.mechanism, OracleMechanism):
            raise StatefulPlanError("stateful oracle mechanism is invalid")
        if not isinstance(self.expectation, DiffExpectation):
            raise StatefulPlanError("stateful oracle expectation is invalid")
        if self.mechanism not in {
            OracleMechanism.DIFFERENTIAL,
            OracleMechanism.BUSINESS_RULE_INVARIANT,
        }:
            raise StatefulPlanError(
                "stateful checks support only differential and business-rule oracle families"
            )
        if (
            isinstance(self.baseline_step, bool)
            or not isinstance(self.baseline_step, int)
            or isinstance(self.probe_step, bool)
            or not isinstance(self.probe_step, int)
        ):
            raise StatefulPlanError("oracle step indexes must be integers")
        if self.baseline_step < 0 or self.probe_step < 0:
            raise StatefulPlanError("oracle step indexes must be non-negative")
        if self.baseline_step == self.probe_step:
            raise StatefulPlanError("oracle baseline and probe must be different steps")
        if self.rule is not None and not isinstance(self.rule, BusinessRule):
            raise StatefulPlanError("stateful oracle rule is invalid")
        if self.mechanism is OracleMechanism.BUSINESS_RULE_INVARIANT and self.rule is None:
            raise StatefulPlanError("business-rule checks require a rule")
        validate_evidence_ref(self.evidence_ref)


@dataclass(frozen=True)
class StatefulPlan:
    """Validated, immutable model plan for one bounded sequence."""

    rationale: str
    steps: tuple[StatefulStep, ...]
    oracle_check: StatefulOracleCheck | None = None

    def __post_init__(self) -> None:
        if not self.rationale.strip() or len(self.rationale) > 1_000:
            raise StatefulPlanError("stateful plan rationale must be 1-1000 characters")
        if not 1 <= len(self.steps) <= MAX_SEQUENCE_STEPS:
            raise StatefulPlanError(f"stateful plan must contain 1-{MAX_SEQUENCE_STEPS} steps")
        if (
            any(step.role is SequenceRole.PROBE for step in self.steps)
            and self.oracle_check is None
        ):
            raise StatefulPlanError("a probe step requires a deterministic oracle check")
        if self.oracle_check is not None:
            if self.oracle_check.baseline_step >= len(
                self.steps
            ) or self.oracle_check.probe_step >= len(self.steps):
                raise StatefulPlanError("oracle step index is outside the sequence")
            if self.steps[self.oracle_check.probe_step].role is not SequenceRole.PROBE:
                raise StatefulPlanError("the oracle probe step must have role 'probe'")
            if self.steps[self.oracle_check.baseline_step].role is SequenceRole.PROBE:
                raise StatefulPlanError("the oracle baseline step cannot have role 'probe'")

    def replay_key(self) -> str:
        """Stable request-shape key; it contains no selected runtime values."""
        payload = {
            "steps": [
                {
                    "endpoint_node": step.endpoint_node,
                    "assignments": [
                        [param, selector.value] for param, selector in step.assignments
                    ],
                    "role": step.role.value,
                }
                for step in self.steps
            ],
            "oracle": (
                {
                    "mechanism": self.oracle_check.mechanism.value,
                    "baseline_step": self.oracle_check.baseline_step,
                    "probe_step": self.oracle_check.probe_step,
                    "expectation": self.oracle_check.expectation.value,
                    "rule": self.oracle_check.rule.value if self.oracle_check.rule else None,
                }
                if self.oracle_check
                else None
            ),
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


def _endpoint(graph: ReachabilityGraph, node: str) -> Endpoint:
    if not graph.has_node(node):
        raise StatefulPlanError(f"unknown endpoint node {node!r}")
    try:
        endpoint = graph.endpoint(node)
    except (AttributeError, KeyError, TypeError) as exc:
        raise StatefulPlanError(f"{node!r} is not an endpoint node") from exc
    if not isinstance(endpoint, Endpoint):
        raise StatefulPlanError(f"{node!r} is not an endpoint node")
    if not endpoint.path.startswith("/") or "://" in endpoint.path:
        raise StatefulPlanError(f"endpoint {node!r} does not contain a relative path")
    return endpoint


def _parameter_belongs(graph: ReachabilityGraph, endpoint_node: str, param_node: str) -> bool:
    return any(node == param_node for node, _ in graph.parameters_of(endpoint_node))


def _reject_keys(raw: Mapping[str, object], allowed: set[str], label: str) -> None:
    unknown = set(raw) - allowed
    if unknown:
        raise StatefulPlanError(f"{label} contains unknown fields: {sorted(unknown)}")


def validate_stateful_plan(
    raw: Mapping[str, object],
    graph: ReachabilityGraph,
    *,
    max_steps: int = MAX_SEQUENCE_STEPS,
) -> StatefulPlan:
    """Validate a JSON proposal against graph ids and safe value selectors."""
    if isinstance(max_steps, bool) or not isinstance(max_steps, int) or max_steps < 1:
        raise StatefulPlanError("max_steps must be a positive integer")
    _reject_keys(raw, {"rationale", "steps", "oracle"}, "stateful plan")
    rationale = raw.get("rationale")
    if not isinstance(rationale, str) or not 1 <= len(rationale.strip()) <= 1_000:
        raise StatefulPlanError("stateful plan rationale must be 1-1000 characters")
    raw_steps = raw.get("steps")
    if not isinstance(raw_steps, list) or not 1 <= len(raw_steps) <= min(
        max_steps, MAX_SEQUENCE_STEPS
    ):
        raise StatefulPlanError(
            f"stateful plan steps must contain 1-{min(max_steps, MAX_SEQUENCE_STEPS)} items"
        )

    steps: list[StatefulStep] = []
    for index, raw_step in enumerate(raw_steps):
        if not isinstance(raw_step, Mapping):
            raise StatefulPlanError(f"steps[{index}] must be an object")
        _reject_keys(
            raw_step,
            {"endpoint_node", "parameters", "assignments", "role", "label"},
            f"steps[{index}]",
        )
        endpoint_node = raw_step.get("endpoint_node")
        if not isinstance(endpoint_node, str):
            raise StatefulPlanError(f"steps[{index}].endpoint_node must be a graph id")
        _endpoint(graph, endpoint_node)
        raw_assignments = raw_step.get("parameters", raw_step.get("assignments", []))
        if not isinstance(raw_assignments, list):
            raise StatefulPlanError(f"steps[{index}].parameters must be a list")
        assignments: list[tuple[str, ValueSelector]] = []
        seen: set[str] = set()
        for assignment_index, raw_assignment in enumerate(raw_assignments):
            if not isinstance(raw_assignment, Mapping):
                raise StatefulPlanError(
                    f"steps[{index}].parameters[{assignment_index}] must be an object"
                )
            _reject_keys(
                raw_assignment,
                {"param_node", "selector"},
                f"steps[{index}].parameters[{assignment_index}]",
            )
            param_node = raw_assignment.get("param_node")
            if not isinstance(param_node, str) or not _parameter_belongs(
                graph, endpoint_node, param_node
            ):
                raise StatefulPlanError(
                    f"steps[{index}].parameters[{assignment_index}] is not accepted by "
                    f"{endpoint_node!r}"
                )
            if _SECRET_NAME.search(graph.parameter(param_node).name):
                raise StatefulPlanError(
                    f"steps[{index}].parameters[{assignment_index}] targets a "
                    "secret-bearing parameter"
                )
            if param_node in seen:
                raise StatefulPlanError(f"steps[{index}] assigns {param_node!r} more than once")
            seen.add(param_node)
            try:
                selector = ValueSelector(str(raw_assignment.get("selector", "")))
            except ValueError as exc:
                raise StatefulPlanError(
                    f"steps[{index}].parameters[{assignment_index}].selector is not an "
                    "allowed selector"
                ) from exc
            assignments.append((param_node, selector))
        try:
            role = SequenceRole(str(raw_step.get("role", SequenceRole.OBSERVE.value)))
        except ValueError as exc:
            raise StatefulPlanError(f"steps[{index}].role is invalid") from exc
        label = raw_step.get("label", "")
        if not isinstance(label, str):
            raise StatefulPlanError(f"steps[{index}].label must be a string")
        steps.append(
            StatefulStep(
                endpoint_node=endpoint_node,
                assignments=tuple(assignments),
                role=role,
                label=label.strip() or f"step-{index + 1}",
            )
        )

    oracle_check: StatefulOracleCheck | None = None
    raw_oracle = raw.get("oracle")
    if raw_oracle is not None:
        if not isinstance(raw_oracle, Mapping):
            raise StatefulPlanError("stateful plan oracle must be an object")
        _reject_keys(
            raw_oracle,
            {"mechanism", "baseline_step", "probe_step", "expectation", "rule", "evidence_ref"},
            "stateful plan oracle",
        )
        try:
            mechanism = OracleMechanism(str(raw_oracle.get("mechanism", "")))
            expectation = DiffExpectation(
                str(raw_oracle.get("expectation", DiffExpectation.RESPONSES_INVARIANT.value))
            )
        except ValueError as exc:
            raise StatefulPlanError("stateful oracle mechanism or expectation is invalid") from exc
        rule: BusinessRule | None = None
        if raw_oracle.get("rule") is not None:
            try:
                rule = BusinessRule(str(raw_oracle["rule"]))
            except ValueError as exc:
                raise StatefulPlanError("stateful oracle rule is invalid") from exc
        raw_baseline_step = raw_oracle.get("baseline_step")
        raw_probe_step = raw_oracle.get("probe_step")
        if isinstance(raw_baseline_step, bool) or not isinstance(raw_baseline_step, int):
            raise StatefulPlanError("stateful oracle baseline_step must be an integer")
        if isinstance(raw_probe_step, bool) or not isinstance(raw_probe_step, int):
            raise StatefulPlanError("stateful oracle probe_step must be an integer")
        try:
            baseline_step = int(raw_baseline_step)
            probe_step = int(raw_probe_step)
        except (TypeError, ValueError) as exc:  # pragma: no cover - guarded above
            raise StatefulPlanError("stateful oracle step indexes must be integers") from exc
        oracle_check = StatefulOracleCheck(
            mechanism=mechanism,
            baseline_step=baseline_step,
            probe_step=probe_step,
            expectation=expectation,
            rule=rule,
            evidence_ref=str(raw_oracle.get("evidence_ref", "")),
        )
    return StatefulPlan(rationale=rationale.strip(), steps=tuple(steps), oracle_check=oracle_check)


def build_request_templates(
    graph: ReachabilityGraph,
    endpoint_nodes: Sequence[str] | None = None,
) -> tuple[RequestTemplate, ...]:
    """Derive deterministic request templates from graph endpoints/parameters."""
    wanted = set(endpoint_nodes) if endpoint_nodes is not None else None
    rows: list[RequestTemplate] = []
    for endpoint_node, endpoint in sorted(graph.endpoints()):
        if wanted is not None and endpoint_node not in wanted:
            continue
        rows.append(
            RequestTemplate(
                endpoint_node=endpoint_node,
                method=endpoint.method.upper(),
                path=endpoint.path,
                protocol=endpoint.protocol,
                content_type=endpoint.content_type,
                parameter_nodes=tuple(
                    node for node, _ in sorted(graph.parameters_of(endpoint_node))
                ),
                read_only=endpoint.method.upper() in _READ_ONLY_METHODS
                and not endpoint.state_changing,
            )
        )
    return tuple(rows)


def build_stateful_prompt(
    graph: ReachabilityGraph,
    *,
    target: str = "",
    operator_prompt: str = "",
    max_steps: int = MAX_SEQUENCE_STEPS,
) -> str:
    """Build the bounded model context for a stateful sequence proposal."""
    endpoints: list[dict[str, object]] = []
    for endpoint_node, endpoint in sorted(graph.endpoints()):
        params = []
        for param_node, parameter in sorted(graph.parameters_of(endpoint_node)):
            params.append(
                {
                    "param_node": param_node,
                    "name": parameter.name[:128],
                    "location": parameter.location,
                    "serialization": parameter.serialization,
                    "required": parameter.required,
                    "has_example": parameter.example is not None,
                }
            )
        endpoints.append(
            {
                "endpoint_node": endpoint_node,
                "method": endpoint.method.upper(),
                "path": endpoint.path[:512],
                "protocol": endpoint.protocol.value,
                "content_type": endpoint.content_type,
                "state_changing": endpoint.state_changing,
                "parameters": params[:MAX_ASSIGNMENTS_PER_STEP],
            }
        )
    schema = {
        "rationale": "why this bounded sequence is useful",
        "steps": [
            {
                "endpoint_node": "graph endpoint id",
                "role": "observe|control|probe",
                "parameters": [
                    {
                        "param_node": "graph parameter id",
                        "selector": "example|empty|zero|one|minimum|maximum|null|identifier",
                    }
                ],
            }
        ],
        "oracle": {
            "mechanism": "differential|business_rule_invariant",
            "baseline_step": "zero-based index",
            "probe_step": "zero-based index",
            "expectation": (
                "responses_invariant|probe_unauthorized|probe_authorized|auth_bypass|database_error"
            ),
            "rule": "optional business rule",
            "evidence_ref": "optional opaque label",
        },
    }
    context = {
        "target": target[:500],
        "operator_goal": operator_prompt[:2000],
        "max_steps": min(max_steps, MAX_SEQUENCE_STEPS),
        "endpoints": endpoints[:200],
    }
    return (
        "You are the stateful API planner for an authorized assessment. Choose only graph endpoint/"
        "parameter ids and the listed schema value selectors. Do not emit URLs, raw request bodies,"
        "headers, credentials, payload text, status verdicts, findings, or commands. A probe role "
        "is only evidence for the existing deterministic oracle; the model never confirms it. "
        "Every generated request is executed by the scoped, audited fire layer, and state-changing "
        "requests"
        "must satisfy read-only-first. Return one JSON object matching this schema.\n"
        f"Context: {json.dumps(context, sort_keys=True)}\n"
        f"Allowed schema: {json.dumps(schema, sort_keys=True)}"
    )


def _json_example(value: str | None) -> object:
    if value is None:
        return "reachagent-probe"
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


def _dedupe_values(values: Sequence[object]) -> tuple[object, ...]:
    out: list[object] = []
    seen: set[str] = set()
    for value in values:
        try:
            key = json.dumps(value, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            key = repr(value)
        if len(key) > MAX_VALUE_CHARS:
            continue
        if key not in seen:
            seen.add(key)
            out.append(value)
    return tuple(out)


def generate_boundary_values(parameter: Parameter) -> tuple[object, ...]:
    """Return deterministic example and boundary values, never attack payloads."""
    example = _json_example(parameter.example)
    name = parameter.name.lower()
    numeric = isinstance(example, (int, float)) and not isinstance(example, bool)
    if not numeric:
        numeric = name.endswith(("id", "count", "limit", "amount", "quantity", "page"))
    if numeric:
        if not isinstance(example, (int, float)) or isinstance(example, bool):
            example = 1
        values: tuple[object, ...] = (example, 0, 1, -1, 2_147_483_647, None)
    elif isinstance(example, bool):
        values = (example, False, True, None)
    elif isinstance(example, list):
        values = (example, [], ["reachagent-probe"], None)
    else:
        text = str(example)
        values = (text[:MAX_VALUE_CHARS], "", "0", "reachagent-probe", "A" * 255, None)
    return _dedupe_values(values)


@dataclass(frozen=True)
class ObservedExchange:
    """A captured response used for dependency learning; body stays local."""

    endpoint_node: str
    status_code: int
    response_body: str | bytes = ""
    response_headers: Mapping[str, str] | Sequence[tuple[str, str]] = field(default_factory=dict)
    evidence_ref: str = ""

    def __post_init__(self) -> None:
        validate_status_code(self.status_code, field="status_code")
        validate_evidence_ref(self.evidence_ref)
        body = (
            self.response_body.decode("utf-8", errors="replace")
            if isinstance(self.response_body, bytes)
            else self.response_body
        )
        if not isinstance(body, str):
            raise StatefulPlanError("response_body must be text or bytes")
        if len(body) > MAX_RESPONSE_CHARS:
            raise StatefulPlanError("response_body exceeds the stateful evidence limit")


@dataclass(frozen=True)
class IdentifierFact:
    """Safe identifier fact; the runtime value is intentionally absent."""

    producer_endpoint: str
    source_field: str
    value_ref: str
    location: str
    evidence_ref: str = ""


@dataclass(frozen=True)
class DependencyFact:
    """Producer→consumer edge metadata, without the identifier value."""

    producer_endpoint: str
    consumer_endpoint: str
    parameter_node: str
    source_field: str
    value_ref: str
    evidence_ref: str = ""


class RuntimeBindings:
    """Short-lived producer values used only while building later requests."""

    def __init__(self) -> None:
        self._values: dict[str, tuple[str, str]] = {}

    def put(self, field: str, value: str) -> str:
        value_ref = identifier_ref(value)
        self._values[_normalise(field)] = (value_ref, value)
        return value_ref

    def resolve(self, parameter_name: str) -> str | None:
        key = _normalise(parameter_name)
        direct = self._values.get(key)
        if direct is not None:
            return direct[1]
        candidates = [
            item for name, item in self._values.items() if name.endswith(key) or key.endswith(name)
        ]
        return sorted(candidates, key=lambda item: item[0])[0][1] if candidates else None

    def safe_refs(self) -> dict[str, str]:
        return {key: ref for key, (ref, _value) in sorted(self._values.items())}


def identifier_ref(value: str) -> str:
    """Return a one-way stable reference for a runtime identifier."""
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _normalise(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _body_text(value: str | bytes) -> str:
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value


def _header_items(
    headers: Mapping[str, str] | Sequence[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    raw = tuple(headers.items()) if isinstance(headers, Mapping) else tuple(headers)
    out: list[tuple[str, str]] = []
    for item in raw:
        if not isinstance(item, Sequence) or isinstance(item, (str, bytes)) or len(item) != 2:
            raise StatefulPlanError("response headers must contain name/value pairs")
        name, value = item
        name_text = str(name).strip().lower()
        if _SECRET_NAME.search(name_text) or name_text in _HOP_BY_HOP_HEADERS:
            continue
        value_text = str(value)
        if len(value_text) <= MAX_VALUE_CHARS and not any(ord(char) < 32 for char in value_text):
            out.append((name_text, value_text))
    return tuple(sorted(out))


def _identifier_pairs(body: str) -> tuple[tuple[str, str, str], ...]:
    try:
        parsed: object = json.loads(body)
    except (TypeError, ValueError):
        return ()
    found: list[tuple[str, str, str]] = []

    def visit(value: object, path: str = "") -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                name = str(key)
                if _SECRET_NAME.search(name):
                    continue
                field = f"{path}.{name}" if path else name
                if (
                    _is_identifier_name(name)
                    and isinstance(child, (str, int, float))
                    and not isinstance(child, bool)
                ):
                    text = str(child)
                    if text and len(text) <= MAX_VALUE_CHARS:
                        found.append((name, text, field))
                visit(child, field)
        elif isinstance(value, list):
            for index, child in enumerate(value[:128]):
                visit(child, f"{path}[{index}]")

    visit(parsed)
    return tuple(found)


def _header_identifier_pairs(
    headers: Mapping[str, str] | Sequence[tuple[str, str]],
) -> tuple[tuple[str, str, str], ...]:
    found: list[tuple[str, str, str]] = []
    for name, value in _header_items(headers):
        if name == "location":
            path = urlsplit(value).path.rstrip("/")
            segments = [part for part in path.split("/") if part]
            segment = segments[-1] if segments else ""
            parent = segments[-2] if len(segments) > 1 else ""
            if segment and not _SECRET_NAME.search(parent):
                found.append(("id", segment, "header:location"))
        elif _is_identifier_name(name):
            found.append((name, value, f"header:{name}"))
    return tuple(found)


def _is_identifier_name(name: str) -> bool:
    """Recognize common snake_case and camelCase identifier field names."""
    if _IDENTIFIER_NAME.search(name):
        return True
    return len(name) > 2 and name.endswith("Id") and name[-3].isalnum()


def _field_matches(field: str, parameter: Parameter) -> bool:
    source = _normalise(field.rsplit(".", 1)[-1])
    target = _normalise(parameter.name)
    if not source or not target:
        return False
    if source == target:
        return True
    if source in {"id", "uuid", "identifier"}:
        return target in {"id", "uuid", "identifier"} or target.endswith("id")
    return source.endswith(target) or target.endswith(source)


def learn_dependencies(
    graph: ReachabilityGraph,
    exchanges: Sequence[ObservedExchange],
    *,
    bindings: RuntimeBindings | None = None,
    max_edges_per_identifier: int = 16,
) -> tuple[DependencyFact, ...]:
    """Learn producer→consumer edges from response JSON and safe headers."""
    if max_edges_per_identifier < 1:
        raise StatefulPlanError("max_edges_per_identifier must be positive")
    facts: list[DependencyFact] = []
    for exchange in exchanges:
        _endpoint(graph, exchange.endpoint_node)
        body = _body_text(exchange.response_body)
        pairs = (*_identifier_pairs(body), *_header_identifier_pairs(exchange.response_headers))
        for source_field, value, _location in pairs:
            ref = (
                bindings.put(source_field, value) if bindings is not None else identifier_ref(value)
            )
            candidates = 0
            for consumer_node, _consumer in sorted(graph.endpoints()):
                if consumer_node == exchange.endpoint_node:
                    continue
                for parameter_node, parameter in sorted(graph.parameters_of(consumer_node)):
                    if not _field_matches(source_field, parameter):
                        continue
                    if candidates >= max_edges_per_identifier:
                        break
                    graph.add_dependency(
                        exchange.endpoint_node,
                        consumer_node,
                        parameter_node=parameter_node,
                        source_field=source_field,
                        value_ref=ref,
                        evidence_ref=exchange.evidence_ref,
                    )
                    facts.append(
                        DependencyFact(
                            producer_endpoint=exchange.endpoint_node,
                            consumer_endpoint=consumer_node,
                            parameter_node=parameter_node,
                            source_field=source_field,
                            value_ref=ref,
                            evidence_ref=exchange.evidence_ref,
                        )
                    )
                    candidates += 1
    return tuple(dict.fromkeys(facts))


@dataclass(frozen=True)
class StepObservation:
    index: int
    label: str
    endpoint_node: str
    status_code: int | None
    elapsed_seconds: float
    body_length: int
    body_sha256: str | None
    outcome: str


@dataclass(frozen=True)
class StateTransition:
    """A deterministic transition summary between adjacent sequence steps."""

    from_step: int
    to_step: int
    from_status: int | None
    to_status: int | None
    changed: bool


@dataclass(frozen=True)
class StatefulRunResult:
    request_signature: str
    observations: tuple[StepObservation, ...]
    transitions: tuple[StateTransition, ...]
    identifiers: tuple[IdentifierFact, ...]
    dependencies: tuple[DependencyFact, ...]
    oracle_outcome: OracleOutcome | None = None


class StatefulExecution:
    """Execute a validated sequence through RequestFirer and an oracle seam."""

    def __init__(
        self,
        graph: ReachabilityGraph,
        firer: RequestFirer,
        *,
        base_url: str,
        identity: str,
        oracle_runner: OracleRunner = registry_runner,
        bindings: RuntimeBindings | None = None,
    ) -> None:
        self.graph = graph
        self.firer = firer
        self.base_url = base_url.rstrip("/")
        self.identity = identity
        self.oracle_runner = oracle_runner
        self.bindings = bindings or RuntimeBindings()

    def run(self, plan: StatefulPlan) -> StatefulRunResult:
        """Run the sequence; every actual request is delegated to the gated firer."""
        # Re-validate graph references at execution time so a stale plan cannot
        # fire against a changed graph.
        for step in plan.steps:
            endpoint = _endpoint(self.graph, step.endpoint_node)
            for param_node, _selector in step.assignments:
                if not _parameter_belongs(self.graph, step.endpoint_node, param_node):
                    raise StatefulPlanError(
                        f"parameter {param_node!r} no longer belongs to {step.endpoint_node!r}"
                    )
                if _SECRET_NAME.search(self.graph.parameter(param_node).name):
                    raise StatefulPlanError(
                        f"parameter {param_node!r} is secret-bearing and cannot be generated"
                    )
            del endpoint

        observations: list[StepObservation] = []
        fires: list[FireResult | None] = []
        exchanges: list[ObservedExchange] = []
        identifier_facts: list[IdentifierFact] = []
        for index, step in enumerate(plan.steps):
            endpoint = self.graph.endpoint(step.endpoint_node)
            try:
                url, kwargs = self._request(endpoint, step)
            except MissingIdentifierError:
                observations.append(
                    StepObservation(
                        index,
                        step.label,
                        step.endpoint_node,
                        None,
                        0.0,
                        0,
                        None,
                        "missing_identifier",
                    )
                )
                fires.append(None)
                continue

            state_changing = (
                endpoint.state_changing
                or endpoint.method.upper() not in _READ_ONLY_METHODS
                or (
                    endpoint.protocol is Protocol.GRAPHQL
                    and str(endpoint.graphql_operation_type or "").lower()
                    in {"mutation", "subscription"}
                )
            )
            if state_changing:
                # Establish a safe read-only control first. Failure is deliberately
                # ignored; the actual mutating call still goes through the firer,
                # which refuses it when clearance was not earned.
                try:
                    preflight_kwargs = {
                        key: value
                        for key, value in kwargs.items()
                        if key in {"params", "headers", "cookies"}
                    }
                    self.firer.fire(
                        self.identity,
                        "GET",
                        url,
                        state_changing=False,
                        **preflight_kwargs,
                    )
                except Exception as exc:  # noqa: BLE001 - mutation remains gated below
                    _log.debug("stateful read-only preflight failed: %s", exc)
            try:
                result = self.firer.fire(
                    self.identity,
                    endpoint.method,
                    url,
                    state_changing=state_changing,
                    **kwargs,
                )
            except OutOfScopeError:
                observations.append(
                    StepObservation(
                        index,
                        step.label,
                        step.endpoint_node,
                        None,
                        0.0,
                        0,
                        None,
                        "refused_out_of_scope",
                    )
                )
                fires.append(None)
                continue
            except ReadOnlyFirstError:
                observations.append(
                    StepObservation(
                        index,
                        step.label,
                        step.endpoint_node,
                        None,
                        0.0,
                        0,
                        None,
                        "refused_read_only_first",
                    )
                )
                fires.append(None)
                continue
            except Exception as exc:  # noqa: BLE001 - transport errors are not evidence
                observations.append(
                    StepObservation(
                        index,
                        step.label,
                        step.endpoint_node,
                        None,
                        0.0,
                        0,
                        None,
                        f"error:{type(exc).__name__}",
                    )
                )
                fires.append(None)
                continue

            body = result.body
            digest = hashlib.sha256(body).hexdigest()
            observations.append(
                StepObservation(
                    index,
                    step.label,
                    step.endpoint_node,
                    result.status_code,
                    result.elapsed_seconds,
                    len(body),
                    digest,
                    "fired",
                )
            )
            fires.append(result)
            exchange = ObservedExchange(
                endpoint_node=step.endpoint_node,
                status_code=result.status_code,
                response_body=body,
                response_headers=result.headers,
                evidence_ref=f"stateful/{plan.replay_key()}/{index}",
            )
            exchanges.append(exchange)
            for source_field, value, location in (
                *_identifier_pairs(_body_text(body)),
                *_header_identifier_pairs(result.headers),
            ):
                value_ref = self.bindings.put(source_field, value)
                identifier_facts.append(
                    IdentifierFact(
                        step.endpoint_node, source_field, value_ref, location, exchange.evidence_ref
                    )
                )

        dependencies = learn_dependencies(self.graph, exchanges, bindings=self.bindings)
        oracle_outcome = self._check_oracle(plan, fires)
        transitions = tuple(
            StateTransition(
                from_step=left.index,
                to_step=right.index,
                from_status=left.status_code,
                to_status=right.status_code,
                changed=(
                    left.status_code != right.status_code or left.body_sha256 != right.body_sha256
                ),
            )
            for left, right in zip(observations, observations[1:], strict=False)
        )
        return StatefulRunResult(
            request_signature=plan.replay_key(),
            observations=tuple(observations),
            transitions=transitions,
            identifiers=tuple(dict.fromkeys(identifier_facts)),
            dependencies=dependencies,
            oracle_outcome=oracle_outcome,
        )

    def _request(self, endpoint: Endpoint, step: StatefulStep) -> tuple[str, dict[str, object]]:
        params: dict[str, object] = {}
        headers: dict[str, str] = {
            str(name): str(value)
            for name, value in endpoint.request_headers
            if str(name).lower() not in _HOP_BY_HOP_HEADERS
            and not _SECRET_NAME.search(str(name))
            and str(value) != "<redacted>"
        }
        cookies: dict[str, str] = {}
        form: dict[str, str] = {}
        body: dict[str, object] = {}
        path = endpoint.path
        assigned: dict[str, object] = {}
        for param_node, selector in step.assignments:
            parameter = self.graph.parameter(param_node)
            value = self._value(parameter, selector)
            assigned[parameter.name] = value
            if parameter.location == "path":
                path = path.replace("{" + parameter.name + "}", quote(str(value), safe=""))
            elif parameter.location == "query":
                params[parameter.name] = value
            elif parameter.location == "header":
                headers[parameter.name] = str(value)
            elif parameter.location == "cookie":
                cookies[parameter.name] = str(value)
            elif parameter.location in {"json", "body"}:
                body[parameter.name] = value
            elif parameter.location in {"form", "multipart"}:
                form[parameter.name] = str(value)
            elif parameter.location == "graphql":
                # GraphQL uses the document query string as its insertion surface.
                pass
            else:
                raise StatefulPlanError(
                    f"parameter {param_node!r} has unsupported location {parameter.location!r}"
                )

        if "{" in path:
            raise StatefulPlanError(f"unresolved path placeholder in {endpoint.path!r}")
        kwargs: dict[str, object] = {}
        if endpoint.request_body:
            try:
                seed = json.loads(endpoint.request_body)
            except (TypeError, ValueError):
                seed = None
            if isinstance(seed, Mapping):
                body = {
                    str(key): value
                    for key, value in seed.items()
                    if not _SECRET_NAME.search(str(key))
                } | body
        if endpoint.protocol is Protocol.GRAPHQL or any(
            self.graph.parameter(node).location == "graphql" for node, _ in step.assignments
        ):
            fields: dict[str, dict[str, object]] = {}
            for name, value in assigned.items():
                field, _, argument = name.partition(".")
                if not _GRAPHQL_NAME.fullmatch(field) or (
                    argument and not _GRAPHQL_NAME.fullmatch(argument)
                ):
                    raise StatefulPlanError("GraphQL field or argument name is invalid")
                fields.setdefault(field, {})[argument] = value if argument else None
            selections = []
            for field, arguments in sorted(fields.items()):
                args = [(key, value) for key, value in arguments.items() if key]
                rendered_args = ", ".join(
                    f"{key}: {json.dumps(value, sort_keys=True)}" for key, value in args
                )
                rendered = f"{field}({rendered_args})" if args else field
                selections.append(rendered)
            operation = (
                "mutation"
                if str(endpoint.graphql_operation_type or "").lower() == "mutation"
                else "query"
            )
            if str(endpoint.graphql_operation_type or "query").lower() not in {
                "query",
                "mutation",
            }:
                raise StatefulPlanError("GraphQL operation type is unsupported")
            document = (
                f"{operation} ReachAgentState {{ " + " ".join(selections or ["__typename"]) + " }"
            )
            variables: dict[str, object] = {}
            if endpoint.method.upper() in _READ_ONLY_METHODS:
                params["query"] = document
                params["variables"] = json.dumps(variables, sort_keys=True)
            else:
                body = {"query": document, "variables": variables} | body
        if params:
            kwargs["params"] = params
        if headers:
            kwargs["headers"] = headers
        if cookies:
            kwargs["cookies"] = cookies
        if form:
            kwargs["data"] = form
        elif body:
            kwargs["json"] = body
        return self.base_url + path, kwargs

    def _value(self, parameter: Parameter, selector: ValueSelector) -> object:
        if selector is ValueSelector.IDENTIFIER:
            value = self.bindings.resolve(parameter.name)
            if value is None:
                raise MissingIdentifierError(
                    f"no producer identifier is available for parameter {parameter.name!r}"
                )
            return value
        values = generate_boundary_values(parameter)
        if selector is ValueSelector.EXAMPLE:
            return values[0] if values else "reachagent-probe"
        if selector is ValueSelector.EMPTY:
            return ""
        if selector is ValueSelector.ZERO:
            return 0 if values and isinstance(values[0], (int, float)) else "0"
        if selector is ValueSelector.ONE:
            return 1 if values and isinstance(values[0], (int, float)) else "1"
        if selector is ValueSelector.MINIMUM:
            if values and isinstance(values[0], (int, float)) and not isinstance(values[0], bool):
                return 0
            return values[-3] if len(values) >= 3 else ""
        if selector is ValueSelector.MAXIMUM:
            if values and isinstance(values[0], (int, float)) and not isinstance(values[0], bool):
                return 2_147_483_647
            return values[-2] if len(values) >= 2 else "A" * 255
        return None

    def _check_oracle(
        self, plan: StatefulPlan, fires: Sequence[FireResult | None]
    ) -> OracleOutcome | None:
        check = plan.oracle_check
        if check is None:
            return None
        baseline = fires[check.baseline_step]
        probe = fires[check.probe_step]
        if baseline is None or probe is None:
            return None
        evidence_ref = check.evidence_ref or f"stateful/{plan.replay_key()}"
        metadata = EvidenceMetadata(
            baseline_response_ref=f"response-{plan.replay_key()}-{check.baseline_step}",
            probe_response_ref=f"response-{plan.replay_key()}-{check.probe_step}",
            baseline_body_projection=f"sha256:{hashlib.sha256(baseline.body).hexdigest()}",
            probe_body_projection=f"sha256:{hashlib.sha256(probe.body).hexdigest()}",
            timing_samples_ms=(baseline.elapsed_seconds * 1000, probe.elapsed_seconds * 1000),
        ).validated()
        if check.mechanism is OracleMechanism.DIFFERENTIAL:
            evidence: object = DifferentialEvidence(
                axis=DiffAxis.CROSS_REQUEST,
                expectation=check.expectation,
                baseline=Observation("baseline", baseline.status_code, _body_text(baseline.body)),
                probe=Observation("probe", probe.status_code, _body_text(probe.body)),
                evidence_ref=evidence_ref,
                metadata=metadata,
            )
        else:
            if check.rule is None:
                return None
            evidence = BusinessRuleEvidence(
                rule=check.rule,
                baseline=ReplayObservation(
                    "baseline", baseline.status_code, _body_text(baseline.body)
                ),
                violating=ReplayObservation("violating", probe.status_code, _body_text(probe.body)),
                evidence_ref=evidence_ref,
                metadata=metadata,
            )
        outcome = self.oracle_runner(check.mechanism, evidence)
        self.firer.audit.record_oracle_result(
            self.identity,
            f"{self.base_url}{self.graph.endpoint(plan.steps[check.probe_step].endpoint_node).path}",
            outcome.reason,
            evidence_ref=evidence_ref,
        )
        return outcome


StatefulExplorer = StatefulExecution


@dataclass(frozen=True)
class ObservedRequest:
    """One captured request used to extend the graph with a replay shape.

    The request is an input fact, not an instruction to fire traffic.  Header
    and body values are sanitized before they become graph metadata; callers
    should still treat the object itself as short-lived capture data.
    """

    method: str
    url: str
    headers: Mapping[str, str] | Sequence[tuple[str, str]] = field(default_factory=dict)
    body: str | bytes | None = None
    evidence_ref: str = ""
    source: str = "observed-traffic"

    def __post_init__(self) -> None:
        method = self.method.upper() if isinstance(self.method, str) else ""
        if not re.fullmatch(r"[A-Z][A-Z0-9_-]{0,15}", method):
            raise StatefulPlanError("observed request method is invalid")
        if not isinstance(self.url, str) or not self.url.strip():
            raise StatefulPlanError("observed request url must be non-empty")
        validate_evidence_ref(self.evidence_ref)
        if (
            not isinstance(self.source, str)
            or not self.source.strip()
            or len(self.source) > 128
            or any(ord(char) < 32 for char in self.source)
        ):
            raise StatefulPlanError("observed request source is invalid")
        if self.body is not None:
            if not isinstance(self.body, (str, bytes)):
                raise StatefulPlanError("observed request body must be text or bytes")
            if len(_body_text(self.body)) > MAX_RESPONSE_CHARS:
                raise StatefulPlanError("observed request body exceeds the evidence limit")


def _base_authority(base_url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise StatefulPlanError("base_url must be an absolute http(s) URL")
    try:
        port = parsed.port
    except ValueError as exc:
        raise StatefulPlanError("base_url contains an invalid port") from exc
    return parsed.scheme.lower(), parsed.hostname.lower(), port


def _validate_source(source: str) -> str:
    if (
        not isinstance(source, str)
        or not source.strip()
        or len(source) > 128
        or any(ord(char) < 32 for char in source)
    ):
        raise StatefulPlanError("provenance source is invalid or secret-bearing")
    return source.strip()


def _observed_url(url: str, base_url: str) -> tuple[str, str]:
    """Resolve a captured URL and reject hosts outside the target authority."""
    scheme, host, port = _base_authority(base_url)
    parsed = urlsplit(url)
    if parsed.scheme or parsed.netloc:
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise StatefulPlanError("observed request url must use http(s)")
        try:
            observed_port = parsed.port
        except ValueError as exc:
            raise StatefulPlanError("observed request url contains an invalid port") from exc
        if parsed.hostname.lower() != host or observed_port != port:
            raise StatefulPlanError("observed request host is outside the target authority")
    else:
        parsed = urlsplit(base_url.rstrip("/") + "/" + url.lstrip("/"))
    path = parsed.path or "/"
    if not path.startswith("/") or len(path) > 4_096:
        raise StatefulPlanError("observed request path is invalid")
    return path, parsed.query


def _mapping_request(raw: Mapping[str, object], source: str) -> ObservedRequest:
    method = raw.get("method")
    url = raw.get("url", raw.get("target"))
    if not isinstance(method, str) or not isinstance(url, str):
        raise StatefulPlanError("observed traffic entries need method and url")
    headers = raw.get("headers", {})
    if not isinstance(headers, Mapping) and (
        not isinstance(headers, Sequence) or isinstance(headers, (str, bytes))
    ):
        raise StatefulPlanError("observed request headers must be a mapping or pairs")
    body = raw.get("body", raw.get("request_body"))
    if body is not None and not isinstance(body, (str, bytes)):
        raise StatefulPlanError("observed request body must be text or bytes")
    evidence_ref = raw.get("evidence_ref", "")
    item_source = raw.get("source", source)
    if not isinstance(evidence_ref, str) or not isinstance(item_source, str):
        raise StatefulPlanError("observed request provenance must be text")
    return ObservedRequest(
        method=method,
        url=url,
        headers=headers,
        body=body,
        evidence_ref=evidence_ref,
        source=item_source,
    )


def _content_type(headers: Sequence[tuple[str, str]]) -> str | None:
    for name, value in headers:
        if name.lower() == "content-type":
            return value.split(";", 1)[0].strip().lower() or None
    return None


def _observed_body_parameters(
    body: str,
    content_type: str | None,
    source: str,
    evidence_ref: str,
) -> list[Parameter]:
    if not body:
        return []
    if content_type == "application/json" or body.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(body)
        except (TypeError, ValueError):
            return []
        if not isinstance(parsed, Mapping):
            return []
        return [
            Parameter(
                name=str(name),
                location="json",
                serialization="application/json",
                source=source,
                evidence_ref=evidence_ref,
            )
            for name, value in parsed.items()
            if not _SECRET_NAME.search(str(name))
        ]
    if content_type == "application/x-www-form-urlencoded":
        return [
            Parameter(
                name=name,
                location="form",
                serialization="application/x-www-form-urlencoded",
                source=source,
                evidence_ref=evidence_ref,
            )
            for name, value in parse_qsl(body, keep_blank_values=True)
            if not _SECRET_NAME.search(name)
        ]
    if content_type == "multipart/form-data":
        names = re.findall(r"name=[\"']([^\"']+)[\"']", body, flags=re.IGNORECASE)
        return [
            Parameter(
                name=name,
                location="multipart",
                serialization="multipart/form-data",
                source=source,
                evidence_ref=evidence_ref,
            )
            for name in dict.fromkeys(names)
            if not _SECRET_NAME.search(name)
        ]
    return []


def ingest_observed_traffic(
    graph: ReachabilityGraph,
    requests: Sequence[ObservedRequest | Mapping[str, object]],
    *,
    base_url: str,
    source: str = "observed-traffic",
) -> tuple[RequestTemplate, ...]:
    """Materialize same-authority captured requests as replayable templates."""
    source = _validate_source(source)
    _scheme, host, _port = _base_authority(base_url)
    host_node = graph.add_host(Host(address=host, hostname=host, source=source))
    endpoint_nodes: list[str] = []
    for raw in requests:
        request = raw if isinstance(raw, ObservedRequest) else _mapping_request(raw, source)
        path, query = _observed_url(request.url, base_url)
        safe_headers = _header_items(request.headers)
        method = request.method.upper()
        body = _body_text(request.body or "")
        endpoint_node = graph.add_endpoint(
            Endpoint(
                method=method,
                path=path,
                content_type=_content_type(safe_headers),
                state_changing=method not in _READ_ONLY_METHODS,
                source=request.source,
                evidence_ref=request.evidence_ref,
                request_headers=safe_headers,
                request_body=body or None,
            )
        )
        graph.add_resolves_to(host_node, endpoint_node)
        endpoint_nodes.append(endpoint_node)
        for name, _value in parse_qsl(query, keep_blank_values=True):
            if _SECRET_NAME.search(name):
                continue
            graph.add_parameter(
                endpoint_node,
                Parameter(
                    name=name,
                    location="query",
                    serialization="application/x-www-form-urlencoded",
                    source=request.source,
                    evidence_ref=request.evidence_ref,
                ),
            )
        for parameter in _observed_body_parameters(
            body, _content_type(safe_headers), request.source, request.evidence_ref
        ):
            graph.add_parameter(endpoint_node, parameter)
    return build_request_templates(graph, tuple(dict.fromkeys(endpoint_nodes)))


def _postman_variables(raw: Mapping[str, object]) -> dict[str, str]:
    entries = raw.get("variable")
    if not isinstance(entries, list):
        return {}
    return {
        str(entry["key"]): str(entry.get("value", ""))
        for entry in entries
        if isinstance(entry, Mapping) and entry.get("key") is not None
    }


def _postman_url(value: object, variables: Mapping[str, str]) -> str:
    if isinstance(value, str):
        raw = value
    elif isinstance(value, Mapping):
        raw = value.get("raw", "")
        if not isinstance(raw, str) or not raw:
            protocol = str(value.get("protocol", "https"))
            host = value.get("host", "")
            path = value.get("path", "")
            host_text = (
                ".".join(str(part) for part in host) if isinstance(host, list) else str(host)
            )
            path_text = (
                "/".join(str(part) for part in path) if isinstance(path, list) else str(path)
            )
            query = value.get("query", ())
            query_parts = (
                [
                    f"{entry.get('key')}={entry.get('value', '')}"
                    for entry in query
                    if isinstance(entry, Mapping)
                    and entry.get("key")
                    and not entry.get("disabled", False)
                ]
                if isinstance(query, list)
                else []
            )
            raw = f"{protocol}://{host_text}/{path_text.lstrip('/')}"
            if query_parts:
                raw += "?" + "&".join(query_parts)
    else:
        raw = ""
    text = str(raw)
    return re.sub(
        r"\{\{\s*([^}]+?)\s*\}\}",
        lambda match: variables.get(match.group(1).strip(), match.group(0)),
        text,
    )


def _postman_items(items: object, variables: Mapping[str, str]) -> list[Mapping[str, object]]:
    if not isinstance(items, list):
        return []
    out: list[Mapping[str, object]] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        if isinstance(item.get("item"), list):
            out.extend(_postman_items(item["item"], variables))
        elif isinstance(item.get("request"), Mapping):
            out.append(item)
    return out


def _graphql_schema_mapping(raw: Mapping[str, object]) -> GraphQLSchema:
    """Convert an introspection-shaped mapping to the existing schema types."""
    from reachagent.graphql.module import GraphQLField, GraphQLSchema

    candidate: object = raw
    data = raw.get("data")
    if isinstance(data, Mapping) and isinstance(data.get("__schema"), Mapping):
        candidate = data["__schema"]
    elif isinstance(raw.get("__schema"), Mapping):
        candidate = raw["__schema"]
    if not isinstance(candidate, Mapping):
        raise StatefulPlanError("GraphQL schema must contain an introspection object")
    query_info = candidate.get("queryType")
    query_type = (
        str(query_info.get("name"))
        if isinstance(query_info, Mapping) and query_info.get("name")
        else "Query"
    )
    fields: list[GraphQLField] = []
    types = candidate.get("types", ())
    if isinstance(types, list):
        for type_info in types:
            if not isinstance(type_info, Mapping) or type_info.get("name") != query_type:
                continue
            raw_fields = type_info.get("fields", ())
            if not isinstance(raw_fields, list):
                continue
            for field_info in raw_fields:
                if not isinstance(field_info, Mapping) or not field_info.get("name"):
                    continue
                field_name = str(field_info["name"])
                if _GRAPHQL_NAME.fullmatch(field_name) is None:
                    raise StatefulPlanError("GraphQL field name is invalid")
                args = field_info.get("args", ())
                arguments = (
                    tuple(
                        str(arg["name"])
                        for arg in args
                        if isinstance(arg, Mapping)
                        and arg.get("name")
                        and _GRAPHQL_NAME.fullmatch(str(arg["name"]))
                    )
                    if isinstance(args, list)
                    else ()
                )
                if isinstance(args, list) and len(arguments) != sum(
                    1 for arg in args if isinstance(arg, Mapping) and arg.get("name")
                ):
                    raise StatefulPlanError("GraphQL argument name is invalid")
                fields.append(
                    GraphQLField(
                        name=field_name,
                        parent_type=query_type,
                        arguments=arguments,
                    )
                )
    if not fields:
        raise StatefulPlanError("GraphQL schema contains no query fields")
    return GraphQLSchema(query_type, tuple(sorted(fields, key=lambda item: item.name)), True)


def ingest_graphql_schema(
    graph: ReachabilityGraph,
    schema: Mapping[str, object] | object,
    *,
    base_url: str,
    endpoint_path: str = "/graphql",
    source: str = "graphql-schema",
) -> tuple[RequestTemplate, ...]:
    """Materialize a GraphQL introspection schema, including field arguments."""
    source = _validate_source(source)
    from reachagent.graphql.module import GraphQLSchema

    if isinstance(schema, GraphQLSchema):
        parsed_schema = schema
    elif isinstance(schema, Mapping):
        parsed_schema = _graphql_schema_mapping(schema)
    else:
        raise StatefulPlanError("GraphQL schema must be a GraphQLSchema or mapping")
    _scheme, host, _port = _base_authority(base_url)
    if not endpoint_path.startswith("/") or "?" in endpoint_path or "://" in endpoint_path:
        raise StatefulPlanError("GraphQL endpoint_path must be a relative path")
    host_node = graph.add_host(Host(address=host, hostname=host, source=source))
    endpoint_node = graph.add_endpoint(
        Endpoint(
            method="GET",
            path=endpoint_path,
            protocol=Protocol.GRAPHQL,
            content_type="application/json",
            graphql_operation_type="query",
            source=source,
        )
    )
    graph.add_resolves_to(host_node, endpoint_node)
    for schema_field in parsed_schema.fields:
        graph.add_parameter(
            endpoint_node,
            Parameter(
                name=schema_field.name,
                location="graphql",
                serialization="application/json",
                source=source,
            ),
        )
        for argument in schema_field.arguments:
            graph.add_parameter(
                endpoint_node,
                Parameter(
                    name=f"{schema_field.name}.{argument}",
                    location="graphql",
                    serialization="application/json",
                    source=source,
                ),
            )
    return build_request_templates(graph, (endpoint_node,))


def ingest_api_spec(
    graph: ReachabilityGraph,
    spec: Mapping[str, object],
    *,
    base_url: str,
    source: str = "api-spec",
) -> tuple[RequestTemplate, ...]:
    """Materialize OpenAPI/GraphQL/Postman operations into replay templates."""
    source = _validate_source(source)
    _scheme, host, _port = _base_authority(base_url)
    host_node = graph.add_host(Host(address=host, hostname=host, source=source))
    if isinstance(spec.get("paths"), Mapping):
        from reachagent.recon.api_discovery import _materialize, _parse_openapi

        surface = _parse_openapi(spec, source)
        endpoint_nodes, _parameter_nodes, _forms = _materialize(graph, host_node, surface)
        return build_request_templates(graph, endpoint_nodes)
    data = spec.get("data")
    if (
        isinstance(spec.get("queryType"), Mapping)
        or isinstance(spec.get("__schema"), Mapping)
        or (isinstance(data, Mapping) and isinstance(data.get("__schema"), Mapping))
    ):
        return ingest_graphql_schema(graph, spec, base_url=base_url, source=source)
    info = spec.get("info")
    is_postman = isinstance(info, Mapping) and ("_postman_id" in info or "item" in spec)
    if not is_postman:
        raise StatefulPlanError(
            "spec must contain OpenAPI/GraphQL paths or a Postman item collection"
        )
    postman_endpoint_nodes: list[str] = []
    variables = _postman_variables(spec)
    for item in _postman_items(spec.get("item"), variables):
        request = item.get("request")
        if not isinstance(request, Mapping):
            continue
        parsed = urlsplit(_postman_url(request.get("url"), variables))
        if parsed.netloc:
            try:
                parsed_port = parsed.port
            except ValueError as exc:
                raise StatefulPlanError("Postman request url contains an invalid port") from exc
            if parsed.hostname is None or parsed.hostname.lower() != host or parsed_port != _port:
                raise StatefulPlanError("Postman request host is outside the target authority")
        path = parsed.path or "/"
        path_parameters = re.findall(r":([A-Za-z_][A-Za-z0-9_]*)", path)
        path = re.sub(r":([A-Za-z_][A-Za-z0-9_]*)", r"{\1}", path)
        method = str(request.get("method", "GET")).upper()
        headers: list[tuple[str, str]] = []
        raw_headers = request.get("header")
        if isinstance(raw_headers, list):
            headers = [
                (str(header.get("key")), str(header.get("value", "")))
                for header in raw_headers
                if isinstance(header, Mapping)
                and header.get("key")
                and not _SECRET_NAME.search(str(header.get("key")))
            ]
        params = [
            Parameter(
                name=name,
                location="query",
                serialization="application/x-www-form-urlencoded",
                example=json.dumps(value),
                source=source,
            )
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
            if not _SECRET_NAME.search(name)
        ]
        params.extend(
            Parameter(
                name=name,
                location="path",
                serialization="path",
                required=True,
                source=source,
            )
            for name in dict.fromkeys(path_parameters)
        )
        request_body: str | None = None
        raw_body = request.get("body")
        if isinstance(raw_body, Mapping):
            mode = str(raw_body.get("mode", "")).lower()
            if mode == "raw" and isinstance(raw_body.get("raw"), str):
                request_body = str(raw_body["raw"])
                try:
                    body_value = json.loads(request_body)
                except (TypeError, ValueError):
                    body_value = None
                if isinstance(body_value, Mapping):
                    params.extend(
                        Parameter(
                            name=str(name),
                            location="json",
                            serialization="application/json",
                            example=json.dumps(value, sort_keys=True),
                            source=source,
                        )
                        for name, value in body_value.items()
                        if not _SECRET_NAME.search(str(name))
                    )
            elif mode in {"urlencoded", "formdata"}:
                entries = raw_body.get(mode)
                if isinstance(entries, list):
                    for entry in entries:
                        if not isinstance(entry, Mapping) or not entry.get("key"):
                            continue
                        params.append(
                            Parameter(
                                name=str(entry["key"]),
                                location="form",
                                serialization="application/x-www-form-urlencoded",
                                example=json.dumps(entry.get("value", "")),
                                source=source,
                            )
                        )
        endpoint_node = graph.add_endpoint(
            Endpoint(
                method=method,
                path=path,
                content_type=_content_type(
                    tuple((str(name).lower(), str(value)) for name, value in headers)
                ),
                state_changing=method not in _READ_ONLY_METHODS,
                source=source,
                request_headers=tuple(sorted(headers)),
                request_body=request_body,
                protocol=Protocol.REST,
            )
        )
        graph.add_resolves_to(host_node, endpoint_node)
        for parameter in params:
            graph.add_parameter(endpoint_node, parameter)
        postman_endpoint_nodes.append(endpoint_node)
    return build_request_templates(graph, postman_endpoint_nodes)


__all__ = [
    "DependencyFact",
    "IdentifierFact",
    "MAX_SEQUENCE_STEPS",
    "MissingIdentifierError",
    "ObservedRequest",
    "ObservedExchange",
    "RequestTemplate",
    "RuntimeBindings",
    "SequenceRole",
    "StatefulExecution",
    "StatefulExplorer",
    "StatefulOracleCheck",
    "StatefulPlan",
    "StatefulPlanError",
    "StatefulRunResult",
    "StatefulStep",
    "StateTransition",
    "StepObservation",
    "ValueSelector",
    "build_request_templates",
    "build_stateful_prompt",
    "generate_boundary_values",
    "identifier_ref",
    "ingest_api_spec",
    "ingest_graphql_schema",
    "ingest_observed_traffic",
    "learn_dependencies",
    "validate_stateful_plan",
]
