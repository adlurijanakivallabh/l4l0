"""Validator tools — the confirmed-violation gate + negative write-back (plan §13; Task 7).

Asserts the Task 7 DoD invariants:

  1. ``write_finding`` commits a ``Finding`` only when backed by a
     ``confirmed_violation`` verdict from ``run_oracle`` — the gate is on
     ``verdict.is_violation``, not ``verdict.confirmed`` (Task 6 decision).
       * a *raw candidate* (no oracle verdict) is refused;
       * a ``confirmed_allowed`` / ``confirmed_denied`` verdict is *also* refused,
         because those are confirmed facts about a ``can_call`` edge (§6), not
         findings.
  2. ``mark_inconclusive`` writes the negative result back onto the edge so it
     isn't retested — verified by re-query.
  3. The role-boundary invariant still holds: the Validator is the only holder of
     ``run_oracle`` / ``write_finding`` (asserted here and in
     ``test_tool_boundaries.py``).
"""

from __future__ import annotations

import pytest

from reachagent.graph.nodes import AuthState, Endpoint, Finding, FindingStatus, Identity, Provenance
from reachagent.graph.store import ReachabilityGraph, identity_id
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import OracleVerdict
from reachagent.oracles.differential import (
    DiffAxis,
    DifferentialEvidence,
    DiffExpectation,
    Observation,
)
from reachagent.tools import validator
from reachagent.tools.candidate import Candidate, ResponseSignal
from reachagent.tools.validator_support import UnconfirmedFindingError
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient


def _violation_verdict(ref: str = "bola/orders/42") -> OracleVerdict:
    """A confirmed_violation verdict, produced through run_oracle.

    v3 (CLAUDE.md): confirmation is now an LLM judgment, not something a
    hermetic test can re-derive deterministically from evidence content — so
    the judgment is pinned via an injected client, and what's under test is
    that run_oracle/write_finding correctly relay that verdict.
    """
    ev = DifferentialEvidence(
        axis=DiffAxis.CROSS_IDENTITY,
        expectation=DiffExpectation.PROBE_UNAUTHORIZED,
        baseline=Observation("owner", 200, '{"ssn":"1"}'),
        probe=Observation("attacker", 200, '{"ssn":"1"}'),
        evidence_ref=ref,
    )
    return validator.run_oracle(
        OracleMechanism.DIFFERENTIAL, ev, client=FixedJudgmentClient(CONFIRMS.value)
    )


def _finding() -> Finding:
    return Finding(
        vuln_class="bola",
        severity="high",
        oracle_used="",
        evidence_ref="",
    )


# -- Invariant 1a: a confirmed violation IS written -----------------------


def test_write_finding_persists_a_confirmed_violation() -> None:
    graph = ReachabilityGraph()
    verdict = _violation_verdict()
    assert verdict.is_violation is True

    node = validator.write_finding(graph, _finding(), verdict)

    assert graph.has_node(node)
    findings = graph.findings()
    assert len(findings) == 1
    _, stored = findings[0]
    assert stored.status is FindingStatus.CONFIRMED_VIOLATION
    # Provenance is stamped from the verdict when the finding didn't carry it.
    assert stored.oracle_used == OracleMechanism.DIFFERENTIAL.value
    assert stored.evidence_ref == "bola/orders/42"


# -- Invariant 1b: a raw candidate (no verdict) is refused ----------------


def test_write_finding_refuses_a_raw_candidate() -> None:
    graph = ReachabilityGraph()
    # An Explorer candidate — a lead, never a confirmation. It carries a
    # *suggested* oracle but no verdict.
    candidate = Candidate(
        identity="attacker",
        endpoint_node="endpoint:GET /orders/42",
        param_node=None,
        vuln_class="bola",
        suggested_oracle=OracleMechanism.DIFFERENTIAL,
        payload_ref=None,
        signal=ResponseSignal(status_code=200, body_length=10, elapsed_seconds=0.1),
    )

    with pytest.raises(UnconfirmedFindingError):
        validator.write_finding(graph, _finding(), candidate)  # type: ignore[arg-type]
    # Nothing was written.
    assert graph.findings() == []


# -- Invariant 1c: confirmed_allowed / confirmed_denied are facts, not findings --


def test_write_finding_refuses_confirmed_allowed() -> None:
    graph = ReachabilityGraph()
    allowed = OracleVerdict(
        mechanism=OracleMechanism.DIFFERENTIAL,
        status=FindingStatus.CONFIRMED_ALLOWED,
        evidence_ref="e",
    )
    # It IS confirmed — but not a violation. The gate must be on is_violation.
    assert allowed.confirmed is True
    assert allowed.is_violation is False

    with pytest.raises(UnconfirmedFindingError):
        validator.write_finding(graph, _finding(), allowed)
    assert graph.findings() == []


def test_write_finding_refuses_confirmed_denied() -> None:
    graph = ReachabilityGraph()
    denied = OracleVerdict(
        mechanism=OracleMechanism.DIFFERENTIAL,
        status=FindingStatus.CONFIRMED_DENIED,
        evidence_ref="e",
    )
    assert denied.confirmed is True
    assert denied.is_violation is False

    with pytest.raises(UnconfirmedFindingError):
        validator.write_finding(graph, _finding(), denied)
    assert graph.findings() == []


def test_write_finding_refuses_inconclusive() -> None:
    graph = ReachabilityGraph()
    inconclusive = OracleVerdict(
        mechanism=OracleMechanism.DIFFERENTIAL,
        status=FindingStatus.INCONCLUSIVE,
        evidence_ref="e",
    )
    assert inconclusive.confirmed is False
    with pytest.raises(UnconfirmedFindingError):
        validator.write_finding(graph, _finding(), inconclusive)
    assert graph.findings() == []


# -- Defense in depth: the store itself refuses a non-violation finding ---


def test_store_refuses_finding_without_violation_status() -> None:
    # Even bypassing write_finding, the persistence layer won't land a finding
    # whose status isn't confirmed_violation — the CLAUDE.md non-negotiable has a
    # second, independent guard.
    graph = ReachabilityGraph()
    inconclusive_finding = Finding(
        vuln_class="bola",
        severity="high",
        oracle_used="differential",
        evidence_ref="e",
        status=FindingStatus.INCONCLUSIVE,
    )
    with pytest.raises(ValueError):
        graph.add_finding(inconclusive_finding)


# -- Invariant 2: mark_inconclusive writes back, verified by re-query -----


def test_mark_inconclusive_writes_back_and_is_requeryable() -> None:
    graph = ReachabilityGraph()
    ident = identity_id("user_a")
    graph.add_identity("user_a", Identity("user", AuthState.USER, Provenance.SEEDED))
    ep = graph.add_endpoint(Endpoint(method="GET", path="/orders/99"))

    # Before: the edge is unprobed.
    assert graph.can_call_status(ident, ep) is None

    validator.mark_inconclusive(graph, ident, ep, evidence="oracle: inconclusive")

    # Re-query confirms the negative result is recorded, so scoring won't retest.
    assert graph.can_call_status(ident, ep) is FindingStatus.INCONCLUSIVE


def test_mark_inconclusive_overwrites_a_provisional_status() -> None:
    graph = ReachabilityGraph()
    ident = identity_id("user_a")
    graph.add_identity("user_a", Identity("user", AuthState.USER, Provenance.SEEDED))
    ep = graph.add_endpoint(Endpoint(method="GET", path="/orders/99"))
    graph.set_can_call(ident, ep, FindingStatus.CONFIRMED_ALLOWED, evidence="HTTP 200")

    validator.mark_inconclusive(graph, ident, ep, evidence="re-test inconclusive")

    # Single edge slot: inconclusive overwrites, not stacks.
    assert graph.can_call_status(ident, ep) is FindingStatus.INCONCLUSIVE
    edges = [e for e in graph.can_call_edges() if e[0] == ident and e[1] == ep]
    assert len(edges) == 1


# -- Invariant 3: role boundary intact ------------------------------------


def test_validator_is_the_only_holder_of_run_oracle_and_write_finding() -> None:
    from reachagent.tools import coordinator, explorer

    def public(module: object) -> set[str]:
        return {n for n in vars(module) if callable(getattr(module, n)) and not n.startswith("_")}

    assert public(validator) == {"run_oracle", "write_finding", "mark_inconclusive"}
    assert "write_finding" not in public(explorer)
    assert "run_oracle" not in public(explorer)
    assert "run_oracle" not in public(coordinator)
    assert "write_finding" not in public(coordinator)
