"""Coordinator state, candidate records, and §4 scoring helpers.

Kept outside ``coordinator.py`` so the MCP/tool manifest remains exactly the three
Coordinator callables: ``query_graph``, ``score_and_select``, and ``check_budget``.
This module only reads graph state and ChainSolver state. It never fires requests,
invokes an oracle, or writes findings.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from reachagent.graph.chain_solver import ChainSolver
from reachagent.graph.nodes import FindingStatus, SinkType
from reachagent.graph.store import ReachabilityGraph

# Monotonic sink impact weights. RCE-adjacent sinks lead; HTML reflection is lower
# impact. Values need only preserve the plan's ordering, while distinct values make
# score explanations auditable.
SINK_SEVERITY_WEIGHT: dict[SinkType | None, int] = {
    SinkType.SHELL: 6,
    SinkType.DESERIALIZE_TARGET: 6,
    SinkType.TEMPLATE: 5,
    SinkType.SQL: 4,
    SinkType.NOSQL: 4,
    SinkType.LDAP: 3,
    SinkType.FILE_PATH: 3,
    SinkType.URL: 2,
    SinkType.HTML_REFLECTION: 1,
    None: 0,
}


@dataclass(frozen=True)
class CoordinatorContext:
    """Per-run Coordinator collaborators and path budget identity."""

    graph: ReachabilityGraph
    solver: ChainSolver
    path_id: str = "default"
    run_id: str = "default"


@dataclass(frozen=True)
class CoordinatorCandidate:
    """One untested identity/endpoint edge, optionally narrowed to a parameter."""

    identity_node: str
    endpoint_node: str
    parameter_node: str | None
    context: CoordinatorContext
    recent_findings: tuple[str, ...] = ()
    spawned_identity_nodes: frozenset[str] = frozenset()

    @property
    def is_newly_spawned_identity(self) -> int:
        """§4 indicator: derived by this ChainSolver instance in this run."""
        return int(self.identity_node in self.spawned_identity_nodes)


@dataclass(frozen=True)
class Selection:
    """Highest-scoring candidate plus the auditable §4 score components."""

    candidate: CoordinatorCandidate
    score: int
    object_sensitivity_tier: int
    is_newly_spawned_identity: int
    sink_severity_weight: int
    prior_attempts_in_neighborhood: int

    @property
    def identity_node(self) -> str:
        return self.candidate.identity_node

    @property
    def endpoint_node(self) -> str:
        return self.candidate.endpoint_node

    @property
    def parameter_node(self) -> str | None:
        return self.candidate.parameter_node


@dataclass(frozen=True)
class BudgetStatus:
    """Auditable view of the one ChainSolver-owned path budget."""

    path_id: str
    remaining: int
    allowed: bool

    def __bool__(self) -> bool:
        return self.allowed


_ACTIVE_CONTEXTS: dict[tuple[str, str], CoordinatorContext] = {}
_ACTIVE_SOLVERS: dict[tuple[str, str], ChainSolver] = {}
_ACTIVE_PATH_KEYS: dict[str, set[tuple[str, str]]] = {}


def _registry_key(context: CoordinatorContext) -> tuple[str, str]:
    return (context.run_id, context.path_id)


def register_context(context: CoordinatorContext) -> None:
    """Make context discoverable by string-based tool calls within this process."""
    key = _registry_key(context)
    _ACTIVE_CONTEXTS[key] = context
    _ACTIVE_SOLVERS[key] = context.solver
    _ACTIVE_PATH_KEYS.setdefault(context.path_id, set()).add(key)


def context_from(value: object) -> CoordinatorContext:
    """Coerce a context or mapping accepted at the JSON/tool boundary."""
    if isinstance(value, CoordinatorContext):
        register_context(value)
        return value
    if isinstance(value, ReachabilityGraph):
        context = CoordinatorContext(value, ChainSolver(value))
        register_context(context)
        return context
    if isinstance(value, Mapping):
        raw_context = value.get("context")
        if isinstance(raw_context, CoordinatorContext):
            register_context(raw_context)
            return raw_context
        graph = value.get("graph")
        solver = value.get("solver")
        if isinstance(graph, ReachabilityGraph):
            if not isinstance(solver, ChainSolver):
                solver = ChainSolver(graph)
            context = CoordinatorContext(graph, solver, str(value.get("path_id", "default")))
            register_context(context)
            return context
    if isinstance(value, str):
        matches = [key for key in _ACTIVE_CONTEXTS if ":".join(key) == value]
        if len(matches) == 1:
            return _ACTIVE_CONTEXTS[matches[0]]
        if len(matches) > 1:
            raise ValueError(f"ambiguous Coordinator path {value!r}; include run_id")
    raise TypeError("Coordinator input must provide CoordinatorContext, graph, and ChainSolver")


def candidates_from(value: object) -> list[CoordinatorCandidate]:
    """Coerce score input while keeping public Coordinator surface minimal."""
    if isinstance(value, CoordinatorCandidate):
        return [value]
    if isinstance(value, Mapping):
        value = value.get("candidates", [])
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
        raise TypeError("candidates must be an iterable of CoordinatorCandidate records")
    result: list[CoordinatorCandidate] = []
    for item in value:
        if isinstance(item, CoordinatorCandidate):
            result.append(item)
        elif isinstance(item, Mapping):
            context = context_from(item.get("context"))
            spawned = item.get("spawned_identity_nodes")
            if spawned is None:
                spawned_nodes = context.solver.spawned_identity_nodes(context.path_id)
            else:
                spawned_nodes = frozenset(str(node) for node in spawned)
            result.append(
                CoordinatorCandidate(
                    identity_node=str(item["identity_node"]),
                    endpoint_node=str(item["endpoint_node"]),
                    parameter_node=(
                        str(item["parameter_node"])
                        if item.get("parameter_node") is not None
                        else None
                    ),
                    context=context,
                    spawned_identity_nodes=spawned_nodes,
                )
            )
    return result


def _object_sensitivity(graph: ReachabilityGraph, endpoint_node: str) -> int:
    """Use highest returned-object tier, clamped to §4's 0–3 range."""
    return min(
        3, max((obj.sensitivity_tier for _, obj in graph.returns_of(endpoint_node)), default=0)
    )


def _sink_weight(graph: ReachabilityGraph, parameter_node: str | None) -> int:
    """Return highest-impact sink weight for candidate's selected parameter."""
    sink = graph.parameter_sink(parameter_node) if parameter_node is not None else None
    return SINK_SEVERITY_WEIGHT.get(sink, 0)


def _prior_attempts(graph: ReachabilityGraph, identity_node: str, endpoint_node: str) -> int:
    """Count tested can_call edges sharing identity or endpoint (one graph hop).

    A can_call edge is adjacent to this candidate when it shares either endpoint
    node: same Identity (local neighborhood) or same Endpoint (cross-identity
    neighborhood). Each tested edge counts once; inconclusive attempts count too.
    """
    return sum(
        1
        for other_identity, other_endpoint, status in graph.can_call_edges()
        if status in FindingStatus
        and (other_identity == identity_node or other_endpoint == endpoint_node)
    )


def score(candidate: CoordinatorCandidate) -> Selection:
    """Compute exact §4 formula against current graph state."""
    graph = candidate.context.graph
    object_tier = _object_sensitivity(graph, candidate.endpoint_node)
    spawned = candidate.is_newly_spawned_identity
    sink_weight = _sink_weight(graph, candidate.parameter_node)
    prior = _prior_attempts(graph, candidate.identity_node, candidate.endpoint_node)
    total = object_tier * 3 + spawned * 5 + sink_weight - prior
    return Selection(candidate, total, object_tier, spawned, sink_weight, prior)


def budget_status(path_id: object, *, consume: bool = False) -> BudgetStatus:
    """Read or reserve ChainSolver's one path budget.

    ``consume=True`` is the Coordinator's pre-dispatch admission gate. The
    ChainSolver remains the sole owner of remaining units; this function only
    delegates to its public ledger operation.
    """
    if isinstance(path_id, CoordinatorContext):
        context = path_id
        register_context(context)
        solver = context.solver
        actual_path = context.path_id
    else:
        value = str(path_id)
        matches = [key for key in _ACTIVE_CONTEXTS if ":".join(key) == value]
        if not matches:
            matches = list(_ACTIVE_PATH_KEYS.get(value, ()))
        if len(matches) != 1:
            raise ValueError(
                f"unknown or ambiguous Coordinator path {value!r}; use 'run_id:path_id'"
            )
        run_id, actual_path = matches[0]
        solver = _ACTIVE_SOLVERS[(run_id, actual_path)]
    if consume:
        allowed = solver.consume_budget(actual_path)
        remaining = solver.budget_remaining(actual_path)
        return BudgetStatus(actual_path, remaining, allowed)
    remaining = solver.budget_remaining(actual_path)
    return BudgetStatus(actual_path, remaining, remaining > 0)


def _recent_findings(graph: ReachabilityGraph) -> tuple[str, ...]:
    return tuple(node for node, _ in graph.findings()[-8:])
