"""Differential cross-identity/cross-request/cross-condition diff oracle (plan §7).

The Phase 1 oracle (§15). One generic mechanism covers BOLA, BFLA, GraphQL
resolver BOLA, mass assignment, boolean-blind SQLi, NoSQLi auth-bypass, LDAP,
and business-logic price/parameter tampering (§7) — not per-class checkers. The
*axis* records what varied between two responses; the *expectation* records what
a secure app would do; one ``decide()`` function maps (observed relationship vs
expectation) to exactly one deterministic verdict.

The decision path contains **zero LLM input**: it is pure comparison of two
:class:`Observation` records against a declared :class:`DiffExpectation`. Same
evidence in, same :class:`~reachagent.graph.nodes.FindingStatus` out, every time.

Three axes (§7):

  * **cross-identity** — same request, two identities (owner vs. another
    principal). BOLA/BFLA: an unauthorized identity getting the owner's data is a
    violation.
  * **cross-request** — same identity, a mutation then an independent re-read
    (mass assignment: did a client-supplied privileged field actually stick?).
  * **cross-condition** — same identity/endpoint, two payload conditions a safe
    app answers identically (boolean-blind injection: divergence proves the
    condition reached the backend).

**Two structural groups in ``decide()`` — not one flat table:**

  * **Access-control expectations** (``PROBE_UNAUTHORIZED``, ``PROBE_AUTHORIZED``):
    the baseline is a *reference access* that must be GRANTED before the diff
    means anything. A refused or errored baseline yields no trustworthy verdict.
    These pass through the baseline-GRANTED guard.

  * **Injection/bypass expectations** (``RESPONSES_INVARIANT``, ``AUTH_BYPASS``):
    the baseline plays a different role — one side of a condition pair, or a
    *refused* reference that proves a bypass. Neither requires the baseline to be
    GRANTED; both are handled before the access-control guard for that principled
    reason, not as ad-hoc exceptions. The two groups map onto two semantic
    categories; any new expectation would fall into one of them.

The axis is provenance only; the expectation drives the decision, so the same
``decide()`` function serves all classes without per-class branching.
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
    error_signatures: tuple[str, ...] = ()
    metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)


def _validate_evidence(evidence: DifferentialEvidence) -> None:
    """Reject malformed observations before comparison can manufacture a signal."""
    validate_evidence_ref(evidence.evidence_ref)
    validate_evidence_metadata(evidence.metadata)
    for name, observation in (("baseline", evidence.baseline), ("probe", evidence.probe)):
        if not isinstance(observation.label, str) or not observation.label.strip():
            raise ValueError(f"{name}.label must be a non-empty string")
        if len(observation.label) > 256:
            raise ValueError(f"{name}.label exceeds 256 characters")
        if not isinstance(observation.body, str):
            raise TypeError(f"{name}.body must be a string")
        if len(observation.body) > 1_000_000:
            raise ValueError(f"{name}.body exceeds 1000000 characters")
        validate_status_code(observation.status_code, field=f"{name}.status_code")
    if not isinstance(evidence.error_signatures, (tuple, list)):
        raise TypeError("error_signatures must be a list or tuple of strings")
    if len(evidence.error_signatures) > 64:
        raise ValueError("error_signatures exceeds 64 entries")
    for index, signature in enumerate(evidence.error_signatures):
        if not isinstance(signature, str) or not signature.strip():
            raise ValueError(f"error_signatures[{index}] must be a non-empty string")
        if len(signature) > 512:
            raise ValueError(f"error_signatures[{index}] exceeds 512 characters")


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
    _validate_evidence(evidence)
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

    if evidence.expectation is DiffExpectation.AUTH_BYPASS:
        # Baseline is the benign attempt that a secure app REFUSES; probe is the
        # operator-injection variant. Refused-then-granted is the bypass.
        if baseline_outcome is _AccessOutcome.REFUSED and probe_outcome is _AccessOutcome.GRANTED:
            return FindingStatus.CONFIRMED_VIOLATION
        if baseline_outcome is _AccessOutcome.REFUSED and probe_outcome is _AccessOutcome.REFUSED:
            return FindingStatus.CONFIRMED_DENIED
        return FindingStatus.INCONCLUSIVE

    if evidence.expectation is DiffExpectation.DATABASE_ERROR:
        baseline_served = baseline_outcome is _AccessOutcome.GRANTED
        probe_is_error = evidence.probe.status_code >= 400
        body_lower = evidence.probe.body.lower()
        signature_present = any(
            signature.lower() in body_lower for signature in evidence.error_signatures
        )
        if baseline_served and probe_is_error and signature_present:
            return FindingStatus.CONFIRMED_VIOLATION
        if baseline_served and evidence.probe.status_code in (401, 403, 404):
            return FindingStatus.CONFIRMED_DENIED
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


def _reason(evidence: DifferentialEvidence, status: FindingStatus) -> str:
    if status is not FindingStatus.INCONCLUSIVE:
        return decision_reason(OracleMechanism.DIFFERENTIAL, status)
    baseline = _outcome(evidence.baseline.status_code)
    probe = _outcome(evidence.probe.status_code)
    if evidence.expectation is DiffExpectation.RESPONSES_INVARIANT:
        detail = (
            "control_not_served"
            if baseline is not _AccessOutcome.GRANTED or probe is not _AccessOutcome.GRANTED
            else "responses_equivalent"
        )
    elif evidence.expectation is DiffExpectation.AUTH_BYPASS:
        detail = (
            "baseline_not_refused"
            if baseline is not _AccessOutcome.REFUSED
            else "probe_not_decisive"
        )
    elif evidence.expectation is DiffExpectation.DATABASE_ERROR:
        detail = (
            "baseline_not_served"
            if baseline is not _AccessOutcome.GRANTED
            else "database_error_signal_absent"
        )
    elif baseline is not _AccessOutcome.GRANTED:
        detail = "baseline_not_granted"
    else:
        detail = "probe_access_difference_ambiguous"
    return decision_reason(OracleMechanism.DIFFERENTIAL, status, detail)


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
            reason=_reason(evidence, status),
            evidence_metadata=validate_evidence_metadata(evidence.metadata),
        )
