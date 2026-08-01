"""Coordinator tool subset (plan §13, §4, Phase 5).

Coordinator reads graph state and selects the next test. It never fires requests,
runs an oracle, or writes findings. Implementation details live in
:mod:`coordinator_support` so this module's public callable surface remains the
three tools pinned by ``test_tool_boundaries``.
"""

from __future__ import annotations

from reachagent.tools import coordinator_support as _support


def query_graph(filter: object) -> list[_support.CoordinatorCandidate]:
    """Return untested identity/endpoint candidates from a Coordinator run.

    ``filter`` accepts a :class:`CoordinatorContext` or a mapping containing one
    under ``context`` (alternatively ``graph``, ``solver``, and ``path_id``) plus
    optional ``identity_node``/``endpoint_node`` filters. Existing confirmed
    verdicts are excluded; inconclusive edges remain eligible for reassessment.
    Query is read-only and registers context solely for the budget read tool.
    """
    context = _support.context_from(filter)
    if isinstance(filter, dict):
        identity_filter = filter.get("identity_node") or filter.get("identity")
        endpoint_filter = filter.get("endpoint_node") or filter.get("endpoint")
    else:
        identity_filter = None
        endpoint_filter = None

    graph = context.graph
    identities = {node for node, _ in graph.identities()}
    identities.update(context.solver.spawned_identity_nodes(context.path_id))
    endpoints = {node for node, _ in graph.endpoints()}
    if identity_filter is not None:
        identities &= {str(identity_filter)}
    if endpoint_filter is not None:
        endpoints &= {str(endpoint_filter)}

    findings = _support._recent_findings(graph)
    spawned = context.solver.spawned_identity_nodes(context.path_id)
    candidates: list[_support.CoordinatorCandidate] = []
    for identity_node in sorted(identities):
        for endpoint_node in sorted(endpoints):
            status = graph.can_call_status(identity_node, endpoint_node)
            if status is not None and status.value != "inconclusive":
                continue
            parameters = graph.parameters_of(endpoint_node) or [(None, None)]
            for parameter_node, _ in parameters:
                candidates.append(
                    _support.CoordinatorCandidate(
                        identity_node=identity_node,
                        endpoint_node=endpoint_node,
                        parameter_node=parameter_node,
                        context=context,
                        recent_findings=findings,
                        spawned_identity_nodes=spawned,
                    )
                )
    return candidates


def score_and_select(candidates: object) -> _support.Selection | None:
    """Re-score current candidates and return highest §4 score.

    Re-scoring happens on every call rather than maintaining a stale priority
    queue. This makes graph mutations from Validator and ChainSolver visible at
    each pop and gives deterministic tie-breaking by identity, endpoint, and
    parameter node.
    """
    records = _support.candidates_from(candidates)
    if not records:
        return None
    current: list[_support.CoordinatorCandidate] = []
    for record in records:
        status = record.context.graph.can_call_status(record.identity_node, record.endpoint_node)
        if status is None or status.value == "inconclusive":
            current.append(record)
    if not current:
        return None
    scored = [_support.score(record) for record in current]
    selected = max(
        scored,
        key=lambda item: (
            item.score,
            item.is_newly_spawned_identity,
            item.identity_node,
            item.endpoint_node,
            item.parameter_node or "",
        ),
    )
    if not _support.budget_status(selected.candidate.context, consume=True):
        return None
    return selected


def check_budget(path_id: str) -> _support.BudgetStatus:
    """Read ChainSolver's single source-of-truth path budget.

    ``query_graph`` must first register a run context when ``path_id`` is a
    string. The Coordinator does not decrement or duplicate this counter;
    ``ChainSolver.advance`` owns consumption and returns no candidates at zero.
    """
    return _support.budget_status(path_id)
