"""Business-rule invariant evidence shapes (plan §5, §7, §9).

v3 architecture decision (CLAUDE.md): the fixed, per-mechanism ``decide()``
function that used to map (baseline accepted? rule-breaking action accepted or
refused?) to exactly one deterministic verdict has been REMOVED. Live
confirmation judgment now happens in ``oracles/llm_judgment.py``, which
reasons over the same evidence objects instead of running a scripted decision
table. ``BusinessRuleOracle`` is kept only as a registered-mechanism marker
(``oracles/registry.py`` and ``recon/tools/signal_gated.py`` still look it
up); it no longer computes a verdict itself — see
:class:`~reachagent.oracles.base.Oracle` for the inherited (raising) default
``run()``.

The dataclasses and enum below remain in use as the evidence-shape vocabulary
for this family: :class:`BusinessRule` is still *provenance* recorded on the
verdict (and the downstream ``Finding``), never an input to the decision,
exactly as :class:`~reachagent.oracles.differential.DiffAxis` is provenance
for the differential oracle; :class:`BusinessRuleEvidence` /
:class:`ReplayObservation` are still how the four-template library (§5)
describes a legitimate baseline action and the rule-breaking action from one
replay — ``llm_judgment.judge`` takes the same objects the old ``decide()``
did.

The evidence is always the product of a *sequential replay* (the template runner
fires the steps one after another, never a concurrent/single-packet delivery —
that race-condition escalation is the deferred Phase 6 module, §7/§15).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import Oracle
from reachagent.oracles.evidence import EvidenceMetadata


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


class BusinessRuleOracle(Oracle):
    """Registered-mechanism marker for the business-rule-invariant family (§7).

    No longer computes a verdict itself (v3 decision — CLAUDE.md): the fixed
    ``decide()`` this class used to wrap is deleted, and live judgment happens
    in ``oracles/llm_judgment.py``. Kept as a class (rather than deleted
    outright) because ``oracles/registry.py`` still instantiates it and
    ``recon/tools/signal_gated.py`` still looks it up via
    ``OracleMechanism.BUSINESS_RULE_INVARIANT`` to validate a candidate's
    suggested mechanism — neither is part of this file's family and so is out
    of scope here. ``run()`` is inherited unchanged from :class:`Oracle`
    (raises ``NotImplementedError``); nothing in the live scan path calls it.
    """

    mechanism = OracleMechanism.BUSINESS_RULE_INVARIANT
