"""Differential cross-identity/cross-request/cross-condition evidence shapes (plan §7).

v3 architecture decision (CLAUDE.md): the fixed, per-mechanism ``decide()``
function that used to map (observed relationship vs. expectation) to exactly
one deterministic verdict has been REMOVED. Live confirmation judgment now
happens in ``oracles/llm_judgment.py``, which reasons over the same evidence
objects instead of running a scripted decision table. ``DifferentialOracle``
is kept only as a registered-mechanism marker (``oracles/registry.py`` and
``recon/tools/signal_gated.py`` still look it up); it no longer computes a
verdict itself — see :class:`~reachagent.oracles.base.Oracle` for the
inherited (raising) default ``run()``.

The dataclasses and enums below remain in use as the evidence-shape
vocabulary for this family: :class:`DifferentialEvidence` /
:class:`Observation` are still how detectors describe cross-identity,
cross-request, and cross-condition evidence, and :class:`DiffAxis` /
:class:`DiffExpectation` still record provenance and the security invariant
being tested — ``llm_judgment.judge`` takes the same objects the old
``decide()`` did.

Three axes (§7):

  * **cross-identity** — same request, two identities (owner vs. another
    principal). BOLA/BFLA: an unauthorized identity getting the owner's data is a
    violation.
  * **cross-request** — same identity, a mutation then an independent re-read
    (mass assignment: did a client-supplied privileged field actually stick?).
  * **cross-condition** — same identity/endpoint, two payload conditions a safe
    app answers identically (boolean-blind injection: divergence proves the
    condition reached the backend).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import Oracle
from reachagent.oracles.evidence import EvidenceMetadata


class DiffAxis(StrEnum):
    """Which dimension varied between ``baseline`` and ``probe`` (§7). Provenance."""

    CROSS_IDENTITY = "cross_identity"
    CROSS_REQUEST = "cross_request"
    CROSS_CONDITION = "cross_condition"


class DiffExpectation(StrEnum):
    """What a *secure* system does — the invariant the diff tests against (§7).

    This, not the axis, drives the verdict, which is what keeps the mechanism
    generic across every class in §7.
    """

    # Access control: the probe identity/request must NOT obtain the baseline's
    # access (cross-user BOLA/BFLA, privilege escalation via mass-assignment).
    PROBE_UNAUTHORIZED = "probe_unauthorized"
    # Access control: the probe identity legitimately should obtain the same
    # access as the baseline (confirms correct authorization).
    PROBE_AUTHORIZED = "probe_authorized"
    # Injection: baseline and probe are one request under two conditions a safe
    # app answers identically; a divergence proves the condition reached the sink.
    RESPONSES_INVARIANT = "responses_invariant"
    # Auth bypass: baseline is the same request with a benign credential that is
    # correctly REFUSED; probe is the operator-injection variant. If the injection
    # turns a refusal into a grant, authentication was bypassed. Body-equivalence
    # is NOT the signal here (a fresh session returns a different body/token than
    # the refused attempt) — the state transition refused→granted is.
    AUTH_BYPASS = "auth_bypass"
    # Injection: baseline is served and probe returns an allowlisted DB error.
    DATABASE_ERROR = "database_error"


@dataclass(frozen=True)
class Observation:
    """One response reduced to what the diff needs: status + a comparable body.

    ``body`` should already be normalized by the caller (volatile fields such as
    timestamps/nonces/CSRF tokens stripped) so equivalence is meaningful; the
    oracle applies only a deterministic whitespace normalization on top, never any
    fuzzy or model-based comparison.
    """

    label: str
    status_code: int
    body: str = ""


@dataclass(frozen=True)
class DifferentialEvidence:
    """The two responses to diff, plus the security invariant they're tested against.

    ``evidence_ref`` is a short, secret-free provenance handle recorded on the
    resulting verdict (and, downstream, the ``Finding``) so a confirmation is
    always traceable to the trials that produced it (§13).
    """

    axis: DiffAxis
    expectation: DiffExpectation
    baseline: Observation
    probe: Observation
    evidence_ref: str = ""
    error_signatures: tuple[str, ...] = ()
    metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)


class DifferentialOracle(Oracle):
    """Registered-mechanism marker for the differential family (§7).

    No longer computes a verdict itself (v3 decision — CLAUDE.md): the fixed
    ``decide()`` this class used to wrap is deleted, and live judgment happens
    in ``oracles/llm_judgment.py``. Kept as a class (rather than deleted
    outright) because ``oracles/registry.py`` still instantiates it and
    ``recon/tools/signal_gated.py`` still looks it up via
    ``OracleMechanism.DIFFERENTIAL`` to validate a candidate's suggested
    mechanism — neither is part of this file's family and so is out of scope
    here. ``run()`` is inherited unchanged from :class:`Oracle` (raises
    ``NotImplementedError``); nothing in the live scan path calls it.
    """

    mechanism = OracleMechanism.DIFFERENTIAL
