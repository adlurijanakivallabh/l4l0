"""NoSQL injection detection — auth-bypass and blind extraction (§7, §9; Task 3).

Two sub-cases, both reusing existing oracle families (no new mechanism):

  1. **Auth-bypass** (``differential`` / ``AUTH_BYPASS``) — operator injection
     turns a correctly-refused credential into a grant. Baseline: benign
     credential, correctly refused (401/403). Probe: operator-injected variant
     (e.g. ``{"$gt": ""}``) against the same endpoint. Refused→granted is the
     bypass signal; body-equivalence is NOT required (a fresh session returns a
     different token than the refused attempt).

     A confirmed bypass produces a ``derived_credential`` edge into a new
     synthetic Identity — same treatment as JWT forgery (§8). The detector
     returns the result only; the caller drives chain_solver.

  2. **Blind extraction** (``timing_statistical``) — operator-based boolean
     conditions (e.g. ``$regex``-style probes) instead of SQL conditions, same
     paired-trial harness from Task 2. No new oracle family; the mechanism is
     identical, only the payload set differs.

Ordering: auth-bypass first (definitive, no statistical noise), timing fallback
only when bypass was not confirmed. Same prober-injection seam as blind SQLi so
the ordering guarantee is unit-testable without a network.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from reachagent.oracles import OracleMechanism
from reachagent.oracles.differential import (
    DiffAxis,
    DifferentialEvidence,
    DiffExpectation,
    Observation,
)
from reachagent.oracles.timing_statistical import PairedTrialEvidence
from reachagent.tools.validator import run_oracle


@dataclass(frozen=True)
class AuthBypassProbe:
    """One auth-bypass probe pair: the refused baseline and the injected probe."""

    baseline: Observation  # benign credential — must be refused by a secure app
    probe: Observation  # operator-injected variant — granted iff bypass succeeded


@dataclass(frozen=True)
class TimingProbe:
    """Measured latencies from a paired timing probe (probe vs benign baseline)."""

    probe_latencies_ms: tuple[float, ...]
    baseline_latencies_ms: tuple[float, ...]


@dataclass(frozen=True)
class NoSqliResult:
    """Outcome of a NoSQL injection detection attempt.

    ``confirmed`` is true only if an oracle returned ``confirmed_violation``.
    ``mechanism`` names which family confirmed (or None if none did).
    ``attempted`` records every mechanism tried, in order — the audit trail.
    ``bypass_identity_hint`` is set when auth-bypass confirmed; the caller
    should spawn a synthetic Identity with this role hint and write a
    ``derived_credential`` edge via chain_solver (§8).
    """

    confirmed: bool
    mechanism: OracleMechanism | None
    attempted: tuple[OracleMechanism, ...] = ()
    evidence_ref: str = ""
    bypass_identity_hint: str = ""


@dataclass
class NoSqliProber:
    """Injectable probe callbacks — keeps detection hermetic and ordering testable.

    Tests supply in-memory fakes; the live detector supplies firer-backed
    implementations. The detector contains only ordering logic, no I/O.
    """

    # Fire the auth-bypass probe pair; return (baseline_obs, probe_obs).
    fire_auth_bypass: Callable[[], AuthBypassProbe]
    # Fire the paired timing trials; return measured latencies.
    fire_timing: Callable[[], TimingProbe]


def _auth_bypass_confirms(prober: NoSqliProber, evidence_ref: str) -> bool:
    """Attempt the auth-bypass path. Return whether it confirmed."""
    probe = prober.fire_auth_bypass()
    evidence = DifferentialEvidence(
        axis=DiffAxis.CROSS_CONDITION,
        expectation=DiffExpectation.AUTH_BYPASS,
        baseline=probe.baseline,
        probe=probe.probe,
        evidence_ref=evidence_ref,
    )
    verdict = run_oracle(OracleMechanism.DIFFERENTIAL, evidence)
    return verdict.is_violation


def _timing_confirms(prober: NoSqliProber, evidence_ref: str) -> bool:
    """Attempt the timing fallback. Return whether it confirmed."""
    probe = prober.fire_timing()
    evidence = PairedTrialEvidence(
        probe_latencies_ms=probe.probe_latencies_ms,
        baseline_latencies_ms=probe.baseline_latencies_ms,
        evidence_ref=evidence_ref,
    )
    verdict = run_oracle(OracleMechanism.TIMING_STATISTICAL, evidence)
    return verdict.is_violation


def detect_nosqli(
    prober: NoSqliProber,
    *,
    evidence_ref: str = "",
    bypass_identity_hint: str = "nosqli-bypass-principal",
) -> NoSqliResult:
    """Detect NoSQL injection — auth-bypass first, timing fallback (§7, §9).

    Auth-bypass is attempted first: it is definitive (no statistical noise) and
    the higher-severity finding. Timing is reached only when bypass produced no
    confirmation. Returns at the first confirmation; ``attempted`` records the
    order for audit.

    On a confirmed bypass, ``bypass_identity_hint`` is set in the result so the
    caller can spawn a synthetic Identity and write a ``derived_credential`` edge
    via chain_solver (§8). The detector itself never touches the graph.
    """
    attempted: list[OracleMechanism] = []

    # 1. Auth-bypass — definitive, tried first.
    attempted.append(OracleMechanism.DIFFERENTIAL)
    if _auth_bypass_confirms(prober, evidence_ref):
        return NoSqliResult(
            confirmed=True,
            mechanism=OracleMechanism.DIFFERENTIAL,
            attempted=tuple(attempted),
            evidence_ref=evidence_ref,
            bypass_identity_hint=bypass_identity_hint,
        )

    # 2. Timing fallback — operator-based boolean conditions, same §7 harness.
    attempted.append(OracleMechanism.TIMING_STATISTICAL)
    if _timing_confirms(prober, evidence_ref):
        return NoSqliResult(
            confirmed=True,
            mechanism=OracleMechanism.TIMING_STATISTICAL,
            attempted=tuple(attempted),
            evidence_ref=evidence_ref,
        )

    return NoSqliResult(
        confirmed=False,
        mechanism=None,
        attempted=tuple(attempted),
        evidence_ref=evidence_ref,
    )
