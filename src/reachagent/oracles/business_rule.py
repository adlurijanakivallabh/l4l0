"""Business-rule invariant oracle (plan §5, §7, §9).

The ``business_rule_invariant`` family (§7). One deterministic mechanism backs
the whole four-template library (§5): single-use reuse, quantity/limit,
price/parameter tamper, and step-order. Each template reduces to the *same*
security invariant —

    a secure app MUST refuse the rule-breaking action.

so the oracle needs no per-template branch: the :class:`BusinessRule` is
*provenance* recorded on the verdict (and the downstream ``Finding``), never an
input to the decision, exactly as :class:`~reachagent.oracles.differential.
DiffAxis` is provenance for the differential oracle. What drives the verdict is
whether a legitimate baseline action succeeded and whether the rule-breaking
action was then *accepted* rather than refused.

The decision path contains **zero LLM input**: it is pure comparison of two
observation records. Same evidence in, same
:class:`~reachagent.graph.nodes.FindingStatus` out, every time.

The evidence is always the product of a *sequential replay* (the template runner
fires the steps one after another, never a concurrent/single-packet delivery —
that race-condition escalation is the deferred Phase 6 module, §7/§15).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import Oracle, OracleVerdict, decision_reason
from reachagent.oracles.evidence import (
    EvidenceMetadata,
    validate_evidence_metadata,
    validate_evidence_ref,
    validate_status_code,
)


class BusinessRule(StrEnum):
    """The four business-logic invariants (§5, §7). Provenance on the verdict.

    Exactly four — the §7 family names four templates, and CLAUDE.md forbids
    growing the family set without a plan change first. Adding a fifth member
    here is the plan-change tripwire the template-library test guards.
    """

    SINGLE_USE_REUSE = "single_use_reuse"  # a single-use token/coupon redeemed twice
    QUANTITY_LIMIT = "quantity_limit"  # a quantity/limit parameter driven out of bounds
    PRICE_TAMPER = "price_tamper"  # a priced action replayed at a tampered price
    STEP_ORDER = "step_order"  # a later workflow step reached without its prerequisite


class _Outcome(StrEnum):
    """Deterministic normalization of one response's accept/refuse signal."""

    GRANTED = "granted"  # 2xx — the action was accepted
    REFUSED = "refused"  # 4xx — the action was rejected (rule enforced)
    AMBIGUOUS = "ambiguous"  # 3xx/5xx/other — no trustworthy accept/refuse signal


@dataclass(frozen=True)
class ReplayObservation:
    """One response in a sequential replay, reduced to what the oracle needs.

    ``status_code`` is the observed HTTP status; ``0`` marks a step that a safety
    gate refused before any packet left the process (out-of-scope or
    read-only-first), so it reads as ``AMBIGUOUS`` rather than a false accept.
    """

    label: str
    status_code: int
    body: str = ""


@dataclass(frozen=True)
class BusinessRuleEvidence:
    """A legitimate baseline action and the rule-breaking action, from one replay.

    ``baseline`` is the legitimate action a secure app accepts (the first
    redemption, an in-bounds quantity, the real price, the prerequisite step);
    ``violating`` is the rule-breaking action a secure app must refuse (the
    replay, the out-of-bounds value, the tampered price, the out-of-order step).

    ``evidence_ref`` is a short, secret-free provenance handle recorded on the
    verdict (and downstream ``Finding``) so a confirmation traces back to the
    resource and replay that produced it (§13).
    """

    rule: BusinessRule
    baseline: ReplayObservation
    violating: ReplayObservation
    evidence_ref: str = ""
    metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)


def _validate_evidence(evidence: BusinessRuleEvidence) -> None:
    validate_evidence_ref(evidence.evidence_ref)
    validate_evidence_metadata(evidence.metadata)
    for name, observation in (("baseline", evidence.baseline), ("violating", evidence.violating)):
        if not isinstance(observation.label, str) or not observation.label.strip():
            raise ValueError(f"{name}.label must be a non-empty string")
        if len(observation.label) > 256:
            raise ValueError(f"{name}.label exceeds 256 characters")
        if not isinstance(observation.body, str):
            raise TypeError(f"{name}.body must be a string")
        if len(observation.body) > 1_000_000:
            raise ValueError(f"{name}.body exceeds 1000000 characters")
        validate_status_code(observation.status_code, field=f"{name}.status_code")


def _outcome(status_code: int) -> _Outcome:
    """Normalize an HTTP status into an accept/refuse outcome (deterministic)."""
    if 200 <= status_code < 300:
        return _Outcome.GRANTED
    if 400 <= status_code < 500:
        return _Outcome.REFUSED
    return _Outcome.AMBIGUOUS


def decide(evidence: BusinessRuleEvidence) -> FindingStatus:
    """Map business-rule replay evidence to exactly one verdict — the whole decision.

    Pure and total: every input returns exactly one of the four
    :class:`FindingStatus` values, with no LLM anywhere in the path. Extracted as
    a free function so the decision table can be exhaustively tested independently
    of oracle/verdict plumbing.

      * The baseline must have been *accepted* (2xx). Without a legitimate action
        that worked, there is nothing the rule-breaking action deviates from, so
        the result is ``inconclusive`` — never a manufactured violation.
      * With a valid baseline, the rule-breaking action being **accepted** (2xx)
        is the defining business-logic violation: the app honored an action a
        secure app must refuse.
      * The rule-breaking action being **refused** (4xx) is a confirmed *fact*
        that the rule was enforced — ``confirmed_denied``, not a finding.
      * Anything else (3xx/5xx/gate-refused) carries no trustworthy signal →
        ``inconclusive``.
    """
    _validate_evidence(evidence)
    if _outcome(evidence.baseline.status_code) is not _Outcome.GRANTED:
        return FindingStatus.INCONCLUSIVE

    violating = _outcome(evidence.violating.status_code)
    if violating is _Outcome.GRANTED:
        return FindingStatus.CONFIRMED_VIOLATION
    if violating is _Outcome.REFUSED:
        return FindingStatus.CONFIRMED_DENIED
    return FindingStatus.INCONCLUSIVE


def _reason(evidence: BusinessRuleEvidence, status: FindingStatus) -> str:
    if status is not FindingStatus.INCONCLUSIVE:
        return decision_reason(OracleMechanism.BUSINESS_RULE_INVARIANT, status)
    detail = (
        "baseline_not_accepted"
        if _outcome(evidence.baseline.status_code) is not _Outcome.GRANTED
        else "violating_action_ambiguous"
    )
    return decision_reason(OracleMechanism.BUSINESS_RULE_INVARIANT, status, detail)


class BusinessRuleOracle(Oracle):
    """Confirms a business-logic invariant break — one of the six §7 families."""

    mechanism = OracleMechanism.BUSINESS_RULE_INVARIANT

    def run(self, evidence: object) -> OracleVerdict:
        """Return the deterministic verdict for ``evidence`` (must be BusinessRuleEvidence).

        Narrows the base ``evidence: object`` contract, raising ``TypeError`` on
        anything else rather than silently returning inconclusive — a mis-wired
        caller is a bug, not an inconclusive result (mirrors the differential oracle).
        """
        if not isinstance(evidence, BusinessRuleEvidence):
            raise TypeError(
                f"BusinessRuleOracle needs BusinessRuleEvidence, got {type(evidence).__name__}"
            )
        status = decide(evidence)
        return OracleVerdict(
            mechanism=self.mechanism,
            status=status,
            evidence_ref=evidence.evidence_ref,
            reason=_reason(evidence, status),
            evidence_metadata=validate_evidence_metadata(evidence.metadata),
        )
