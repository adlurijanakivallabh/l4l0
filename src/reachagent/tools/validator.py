"""Validator tool subset (plan §13, §4; v3 architecture decision — CLAUDE.md).

The only role that can call ``run_oracle`` and ``write_finding`` (§13, CLAUDE.md).

``run_oracle`` is still the sole code path that can produce a *confirmed*
result — that discipline is unchanged — but per the operator's explicit,
final v3 decision it now judges real, already-fired evidence via LLM
reasoning (``oracles/llm_judgment.py``) rather than a fixed per-mechanism
``decide()`` function. It still returns an
:class:`~reachagent.oracles.base.OracleVerdict` — the only type in the
codebase that carries a confirmed verdict — so every existing driver call
site and ``write_finding``'s own gate are unchanged. ``write_finding`` /
``mark_inconclusive`` commit the outcome.

**Module surface is load-bearing.** ``tests/phase1/test_tool_boundaries.py``
asserts this module exposes *exactly* ``run_oracle``, ``write_finding``, and
``mark_inconclusive`` among non-underscore callables. Oracle classes, mechanisms,
and the judgment function are therefore reached through module aliases (``_oracles``
and friends), never imported by name — a name-bound class is callable and would leak
into the tool surface (the same discipline as the Explorer, Task 5).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from reachagent.graph import nodes as _nodes
from reachagent.oracles import OracleMechanism as _OracleMechanism
from reachagent.oracles import evidence as _evidence
from reachagent.oracles import llm_judgment as _llm_judgment
from reachagent.tools import validator_support as _support

if TYPE_CHECKING:
    from reachagent.graph.nodes import Finding
    from reachagent.graph.store import ReachabilityGraph
    from reachagent.oracles.base import OracleVerdict


def run_oracle(
    mechanism: str | _OracleMechanism,
    evidence: object,
    *,
    audit: object | None = None,
    identity: str = "validator",
    target: str = "oracle",
    client: object | None = None,
) -> OracleVerdict:
    """Judge real, already-fired evidence via LLM reasoning — the only path to a confirmed result.

    Resolves ``mechanism`` and hands ``evidence`` (a real request/response capture —
    unchanged from before) to :func:`reachagent.oracles.llm_judgment.judge`, which
    reasons over it and returns an :class:`OracleVerdict`. Fail-closed throughout
    that function: any LLM/parsing failure comes back ``INCONCLUSIVE``, never a
    fabricated violation. ``write_finding`` is gated behind ``verdict.is_violation``,
    exactly as before this decision. ``client`` (any object exposing ``propose_json``)
    is injectable for hermetic tests — omit it in production to use the scan's
    configured provider.
    """
    mech = _OracleMechanism(mechanism) if not isinstance(mechanism, _OracleMechanism) else mechanism
    verdict = _llm_judgment.judge(mech, evidence, client=client)
    if audit is not None and verdict.status is _nodes.FindingStatus.INCONCLUSIVE:
        record = getattr(audit, "record_oracle_result", None)
        if callable(record):
            record(identity, target, verdict.reason, evidence_ref=verdict.evidence_ref)
    return verdict


def write_finding(
    graph: ReachabilityGraph,
    finding: Finding,
    verdict: OracleVerdict,
    *,
    metadata: dict[str, str] | None = None,
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
    _evidence.validate_evidence_ref(finding.evidence_ref)
    clean_metadata = _evidence.validate_metadata_dict(metadata or {})
    # Stamp the finding with the confirmed status and its oracle provenance, so the
    # persisted node reflects the verdict rather than whatever the caller defaulted.
    finding.status = _nodes.FindingStatus.CONFIRMED_VIOLATION
    if not finding.oracle_used:
        finding.oracle_used = verdict.mechanism.value
    if not finding.evidence_ref:
        finding.evidence_ref = verdict.evidence_ref
    if verdict.reason:
        finding.metadata.setdefault("oracle_reason", verdict.reason)
    if verdict.evidence_metadata.as_dict():
        finding.metadata.setdefault("evidence_metadata", verdict.evidence_metadata.as_json())
    if clean_metadata:
        # Provenance the confirmation itself established (e.g. how a chained hop's
        # consumed identifier is obtained — disclosed vs enumerable). Never LLM
        # judgment: the caller derives it deterministically from the fired evidence.
        finding.metadata.update(clean_metadata)
    return graph.add_finding(finding)


def mark_inconclusive(
    graph: ReachabilityGraph,
    identity_node: str,
    endpoint_node: str,
    *,
    evidence: str = "",
    reason: str = "caller_marked_inconclusive",
    audit: object | None = None,
) -> None:
    """Write a negative result back to a ``can_call`` edge so it isn't retested (§13).

    The counterpart to ``write_finding``: when an oracle returns ``inconclusive``
    (or a candidate simply doesn't confirm), the Validator records that on the edge
    so the Coordinator's scoring doesn't re-select it for the same test. Verified
    by re-query: :meth:`ReachabilityGraph.can_call_status` returns ``inconclusive``
    afterward.
    """
    safe_evidence = _evidence.validate_evidence_ref(evidence, field="inconclusive_evidence")
    safe_reason = _evidence.validate_reason(reason, field="inconclusive_reason")
    graph.mark_edge_inconclusive(identity_node, endpoint_node, evidence=safe_evidence)
    if audit is not None:
        record = getattr(audit, "record_oracle_result", None)
        if callable(record):
            record(
                identity_node,
                endpoint_node,
                f"inconclusive:{safe_reason}",
                evidence_ref=safe_evidence,
            )
