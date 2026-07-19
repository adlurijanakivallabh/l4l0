"""Differential cross-identity/cross-request/cross-condition diff oracle (plan §7).

The Phase 1 oracle (§15). One generic mechanism covers BOLA, BFLA, GraphQL
resolver BOLA, mass assignment, boolean-blind SQLi, NoSQLi, and LDAP, and
business-logic price/parameter tampering (§7) — not per-class checkers. That
genericity is the point: the *axis* records what varied between two responses,
the *expectation* records what a secure app would do, and one decision table maps
(observed relationship vs expectation) to exactly one deterministic verdict.

The decision path contains **zero LLM input**: it is pure comparison of two
:class:`Observation` records against a declared :class:`DiffExpectation`. Same
evidence in, same :class:`~reachagent.graph.nodes.FindingStatus` out, every time.

Three axes, one mechanism (§7):

  * **cross-identity** — same request, two identities (owner vs. another
    principal). BOLA/BFLA: an unauthorized identity getting the owner's data is a
    violation.
  * **cross-request** — same identity, a mutation then an independent re-read
    (mass assignment: did a client-supplied privileged field actually stick?).
  * **cross-condition** — same identity/endpoint, two payload conditions a safe
    app answers identically (boolean-blind injection: divergence proves the
    condition reached the backend).

The axis is provenance only; the *expectation* drives the decision, so the same
table serves all three without branching per class.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import Oracle, OracleVerdict


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


class _AccessOutcome(StrEnum):
    """Deterministic normalization of one response's authorization outcome."""

    GRANTED = "granted"  # 2xx — the request was served
    REFUSED = "refused"  # 401/403 — authorization explicitly denied
    NOT_FOUND = "not_found"  # 404 — resource not exposed to this caller
    AMBIGUOUS = "ambiguous"  # 3xx/5xx/other — no authorization signal to trust


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


def _outcome(status_code: int) -> _AccessOutcome:
    """Normalize an HTTP status into an authorization outcome (deterministic)."""
    if 200 <= status_code < 300:
        return _AccessOutcome.GRANTED
    if status_code in (401, 403):
        return _AccessOutcome.REFUSED
    if status_code == 404:
        return _AccessOutcome.NOT_FOUND
    return _AccessOutcome.AMBIGUOUS


def _normalize_body(body: str) -> str:
    """Deterministic body normalization for equivalence — whitespace only.

    Deliberately not fuzzy: collapsing runs of whitespace and trimming is the
    entire transformation, so two bodies compare equal iff they are identical up
    to whitespace. Semantic normalization (dropping volatile fields) is the
    caller's responsibility, kept out of here so the comparison stays auditable.
    """
    return " ".join(body.split())


def _access_equivalent(a: Observation, b: Observation) -> bool:
    """True iff both responses were granted and returned the same (normalized) body.

    "Same access" means the probe obtained what the baseline obtained — the signal
    a BOLA/BFLA read actually succeeded, not merely returned some 2xx.
    """
    return (
        _outcome(a.status_code) is _AccessOutcome.GRANTED
        and _outcome(b.status_code) is _AccessOutcome.GRANTED
        and _normalize_body(a.body) == _normalize_body(b.body)
    )


def decide(evidence: DifferentialEvidence) -> FindingStatus:
    """Map differential evidence to exactly one verdict — the whole decision (§7).

    Pure and total: every input returns exactly one of the four
    :class:`FindingStatus` values, with no LLM anywhere in the path. Extracted as
    a free function so the decision table can be exhaustively tested independently
    of oracle/verdict plumbing.
    """
    baseline_outcome = _outcome(evidence.baseline.status_code)
    probe_outcome = _outcome(evidence.probe.status_code)
    equivalent = _access_equivalent(evidence.baseline, evidence.probe)

    if evidence.expectation is DiffExpectation.RESPONSES_INVARIANT:
        # Injection: a safe app answers both conditions identically. Both served
        # but diverging → the condition reached the backend → violation. Anything
        # else (identical, or a non-served response) yields no trustworthy blind
        # signal, so it stays inconclusive rather than a false "safe".
        both_granted = (
            baseline_outcome is _AccessOutcome.GRANTED and probe_outcome is _AccessOutcome.GRANTED
        )
        if both_granted and not equivalent:
            return FindingStatus.CONFIRMED_VIOLATION
        return FindingStatus.INCONCLUSIVE

    # Access-control axes need a valid baseline (the owner/authorized reference
    # must actually have been served) to diff against; without it, no verdict.
    if baseline_outcome is not _AccessOutcome.GRANTED:
        return FindingStatus.INCONCLUSIVE

    if evidence.expectation is DiffExpectation.PROBE_UNAUTHORIZED:
        if equivalent:
            # An identity/request that should have been blocked obtained the
            # baseline's access — the defining BOLA/BFLA/mass-assign violation.
            return FindingStatus.CONFIRMED_VIOLATION
        if probe_outcome in (_AccessOutcome.REFUSED, _AccessOutcome.NOT_FOUND):
            # Correctly blocked — a confirmed authorization fact, not a finding.
            return FindingStatus.CONFIRMED_DENIED
        # Served-but-different (e.g. a filtered view) or an errored/ambiguous
        # response: no clean confirmation in either direction.
        return FindingStatus.INCONCLUSIVE

    # PROBE_AUTHORIZED: the probe identity is entitled to the baseline's access.
    if equivalent:
        return FindingStatus.CONFIRMED_ALLOWED
    if probe_outcome in (_AccessOutcome.REFUSED, _AccessOutcome.NOT_FOUND):
        # Entitled but blocked: still a confirmed *denied* fact about the edge
        # (§6). Whether that denial is itself a bug is not this oracle's call.
        return FindingStatus.CONFIRMED_DENIED
    return FindingStatus.INCONCLUSIVE


class DifferentialOracle(Oracle):
    """Confirms via cross-identity/request/condition diff — one of the six §7 families."""

    mechanism = OracleMechanism.DIFFERENTIAL

    def run(self, evidence: object) -> OracleVerdict:
        """Return the deterministic verdict for ``evidence`` (must be DifferentialEvidence).

        Narrows the base ``evidence: object`` contract to
        :class:`DifferentialEvidence`, raising ``TypeError`` on anything else
        rather than silently returning inconclusive — a mis-wired caller is a bug,
        not an inconclusive result.
        """
        if not isinstance(evidence, DifferentialEvidence):
            raise TypeError(
                f"DifferentialOracle needs DifferentialEvidence, got {type(evidence).__name__}"
            )
        status = decide(evidence)
        return OracleVerdict(
            mechanism=self.mechanism,
            status=status,
            evidence_ref=evidence.evidence_ref,
        )
