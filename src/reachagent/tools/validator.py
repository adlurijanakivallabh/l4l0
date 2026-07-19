"""Validator tool subset (plan §13, §4).

Independently re-derives confirmation using deterministic oracles only — no
access to or incentive to agree with the Explorer's classification (§4).
Sonnet-tier, constrained to pre-defined verification procedures (§4). The only
role that can call ``run_oracle`` and ``write_finding`` (§13, CLAUDE.md
non-negotiable).

``run_oracle`` (Task 6) is the sole code path that can produce a *confirmed*
result: it dispatches to one of the deterministic oracle families (§7), each of
which returns an :class:`~reachagent.oracles.base.OracleVerdict` — the only type
in the codebase that carries a confirmed verdict. ``write_finding`` /
``mark_inconclusive`` (Task 7) commit the outcome; they are stubbed here until
that task.

**Module surface is load-bearing.** ``tests/phase1/test_tool_boundaries.py``
asserts this module exposes *exactly* ``run_oracle``, ``write_finding``, and
``mark_inconclusive`` among non-underscore callables. Oracle classes, mechanisms,
and the registry are therefore reached through module aliases (``_oracles`` and
friends), never imported by name — a name-bound class is callable and would leak
into the tool surface (the same discipline as the Explorer, Task 5).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from reachagent.graph import nodes as _nodes
from reachagent.oracles import OracleMechanism as _OracleMechanism
from reachagent.oracles import registry as _registry
from reachagent.tools import validator_support as _support

if TYPE_CHECKING:
    from reachagent.graph.nodes import Finding
    from reachagent.graph.store import ReachabilityGraph
    from reachagent.oracles.base import OracleVerdict


def run_oracle(mechanism: str | _OracleMechanism, evidence: object) -> OracleVerdict:
    """Execute one deterministic oracle family (§7) — the only path to a confirmed result.

    Resolves ``mechanism`` to its registered :class:`~reachagent.oracles.base.Oracle`
    and runs it against ``evidence``. The oracle's scripted logic — never any LLM
    input — decides the :class:`~reachagent.graph.nodes.FindingStatus`. The returned
    :class:`OracleVerdict` is the sole carrier of a ``confirmed`` verdict in the
    system; ``write_finding`` (Task 7) is gated behind ``verdict.is_violation``.

    Raises :class:`~reachagent.oracles.registry.UnknownOracleError` (from the
    registry) if no oracle is registered for ``mechanism`` — an unimplemented or
    mistyped family fails loudly rather than passing as a silent inconclusive.
    """
    mech = _OracleMechanism(mechanism) if not isinstance(mechanism, _OracleMechanism) else mechanism
    return _registry.get_oracle(mech).run(evidence)


def write_finding(
    graph: ReachabilityGraph,
    finding: Finding,
    verdict: OracleVerdict,
) -> str:
    """Commit a ``Finding`` node — gated entirely behind a confirmed *violation* (§13).

    The gate is the CLAUDE.md non-negotiable made real: a ``Finding`` is written
    only when backed by an :class:`~reachagent.oracles.base.OracleVerdict` whose
    verdict is ``confirmed_violation``. The gate is on ``verdict.is_violation``,
    **not** ``verdict.confirmed`` (Task 6 decision): ``confirmed_allowed`` and
    ``confirmed_denied`` are confirmed *facts* about a ``can_call`` edge (§6), not
    findings, so a verdict that is confirmed-but-not-a-violation is refused here.

    Because an ``OracleVerdict`` is constructed only inside an oracle run (Task 6's
    AST-checked invariant) and ``run_oracle`` is the only tool that invokes one,
    ``write_finding`` cannot be reached with a fabricated verdict: there is no way
    to hand it a passing verdict that did not come from a deterministic oracle.

    Anything that is not an ``OracleVerdict`` — e.g. an Explorer ``Candidate`` — is
    rejected before the violation check, so a raw candidate can never be written.

    Returns the persisted finding's id. Raises :class:`~reachagent.tools.
    validator_support.UnconfirmedFindingError` if the verdict does not back a
    violation.
    """
    if not isinstance(verdict, _support.oracle_verdict_type()):
        raise _support.UnconfirmedFindingError(
            "write_finding requires an OracleVerdict from run_oracle; "
            f"got {type(verdict).__name__} — a candidate is not a confirmation"
        )
    if not verdict.is_violation:
        raise _support.UnconfirmedFindingError(
            "refusing to write a Finding: verdict is "
            f"{verdict.status.value!r}, not a confirmed_violation "
            "(confirmed_allowed/confirmed_denied are facts about the edge, not findings)"
        )
    # Stamp the finding with the confirmed status and its oracle provenance, so the
    # persisted node reflects the verdict rather than whatever the caller defaulted.
    finding.status = _nodes.FindingStatus.CONFIRMED_VIOLATION
    if not finding.oracle_used:
        finding.oracle_used = verdict.mechanism.value
    if not finding.evidence_ref:
        finding.evidence_ref = verdict.evidence_ref
    return graph.add_finding(finding)


def mark_inconclusive(
    graph: ReachabilityGraph,
    identity_node: str,
    endpoint_node: str,
    *,
    evidence: str = "",
) -> None:
    """Write a negative result back to a ``can_call`` edge so it isn't retested (§13).

    The counterpart to ``write_finding``: when an oracle returns ``inconclusive``
    (or a candidate simply doesn't confirm), the Validator records that on the edge
    so the Coordinator's scoring doesn't re-select it for the same test. Verified
    by re-query: :meth:`ReachabilityGraph.can_call_status` returns ``inconclusive``
    afterward.
    """
    graph.mark_edge_inconclusive(identity_node, endpoint_node, evidence=evidence)
