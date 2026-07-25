"""LDAP injection detection — auth-bypass and blind extraction (§7, §9; Task 4).

Two sub-cases, both reusing existing oracle families (no new mechanism, and —
per the #21 drift test — no new DiffExpectation either):

  1. **Auth-bypass** (``differential`` / ``AUTH_BYPASS``) — a wildcard/filter
     injection (e.g. ``*)(uid=*``, ``*))%00``) turns a correctly-refused bind
     into a grant. Baseline: benign credential, correctly refused (401/403).
     Probe: wildcard/filter-injected variant. Refused→granted is the bypass
     signal — the exact same "required-refused reference" baseline role as the
     NoSQLi auth-bypass, so it lands in the differential oracle's injection/bypass
     structural group with no new branch (see Phase3-decisions.md, #21 correction).

     A confirmed bypass produces a ``derived_credential`` edge into a new
     synthetic Identity — same treatment as JWT forgery / NoSQLi bypass (§8).
     The detector returns the result only; the caller drives chain_solver.

  2. **Blind extraction** (``timing_statistical``) — attribute-existence boolean
     conditions (a true filter vs a false filter) measured through the Task 2
     paired-trial harness. Same mechanism, LDAP-filter payload set.

**Detection ceiling is lower than SQLi (§5), and this module does not pretend
otherwise.** LDAP has no DB-native out-of-band channel — there is no OOB stage
here, unlike blind SQLi's definitive OOB-first path. Confirmation rests on the
differential auth-bypass (definitive when it fires) and the statistical timing
fallback (noisier). No OOB means no definitive channel for the blind-extraction
sub-case, so support for LDAP stays **Partial** in the §5 matrix, not Full.

Ordering: auth-bypass first (definitive), timing fallback only when bypass was
not confirmed. Same prober-injection seam as the SQLi/NoSQLi detectors.
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
    probe: Observation  # wildcard/filter-injected variant — granted iff bypass worked


@dataclass(frozen=True)
class TimingProbe:
    """Measured latencies from a paired timing probe (probe vs benign baseline)."""

    probe_latencies_ms: tuple[float, ...]
    baseline_latencies_ms: tuple[float, ...]


@dataclass(frozen=True)
class LdapiResult:
    """Outcome of an LDAP injection detection attempt.

    ``confirmed`` is true only if an oracle returned ``confirmed_violation``.
    ``mechanism`` names which family confirmed (or None). ``attempted`` records
    every mechanism tried, in order. ``bypass_identity_hint`` is set when
    auth-bypass confirmed; the caller spawns a synthetic Identity with this hint
    and writes a ``derived_credential`` edge via chain_solver (§8).

    There is no OOB field: LDAP has no out-of-band channel (§5) — a deliberate
    omission, not an oversight.
    """

    confirmed: bool
    mechanism: OracleMechanism | None
    attempted: tuple[OracleMechanism, ...] = ()
    evidence_ref: str = ""
    bypass_identity_hint: str = ""


@dataclass
class LdapiProber:
    """Injectable probe callbacks — keeps detection hermetic and ordering testable."""

    # Fire the auth-bypass probe pair; return the refused baseline and injected probe.
    fire_auth_bypass: Callable[[], AuthBypassProbe]
    # Fire the paired timing trials; return measured latencies.
    fire_timing: Callable[[], TimingProbe]


def _auth_bypass_confirms(prober: LdapiProber, evidence_ref: str) -> bool:
    """Attempt the wildcard/filter auth-bypass path. Return whether it confirmed."""
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


def _timing_confirms(prober: LdapiProber, evidence_ref: str) -> bool:
    """Attempt the attribute-existence timing fallback. Return whether it confirmed."""
    probe = prober.fire_timing()
    evidence = PairedTrialEvidence(
        probe_latencies_ms=probe.probe_latencies_ms,
        baseline_latencies_ms=probe.baseline_latencies_ms,
        evidence_ref=evidence_ref,
    )
    verdict = run_oracle(OracleMechanism.TIMING_STATISTICAL, evidence)
    return verdict.is_violation


def detect_ldapi(
    prober: LdapiProber,
    *,
    evidence_ref: str = "",
    bypass_identity_hint: str = "ldapi-bypass-principal",
) -> LdapiResult:
    """Detect LDAP injection — auth-bypass first, timing fallback (§7, §9).

    No OOB stage exists for this class (§5); confirmation is the definitive
    differential auth-bypass or the noisier statistical timing fallback. Returns
    at the first confirmation; ``attempted`` records the order for audit.

    On a confirmed bypass, ``bypass_identity_hint`` is set so the caller can spawn
    a synthetic Identity and write a ``derived_credential`` edge via chain_solver
    (§8). The detector itself never touches the graph.
    """
    attempted: list[OracleMechanism] = []

    # 1. Wildcard/filter auth-bypass — definitive, tried first.
    attempted.append(OracleMechanism.DIFFERENTIAL)
    if _auth_bypass_confirms(prober, evidence_ref):
        return LdapiResult(
            confirmed=True,
            mechanism=OracleMechanism.DIFFERENTIAL,
            attempted=tuple(attempted),
            evidence_ref=evidence_ref,
            bypass_identity_hint=bypass_identity_hint,
        )

    # 2. Attribute-existence timing fallback — noisier, no OOB alternative here.
    attempted.append(OracleMechanism.TIMING_STATISTICAL)
    if _timing_confirms(prober, evidence_ref):
        return LdapiResult(
            confirmed=True,
            mechanism=OracleMechanism.TIMING_STATISTICAL,
            attempted=tuple(attempted),
            evidence_ref=evidence_ref,
        )

    return LdapiResult(
        confirmed=False,
        mechanism=None,
        attempted=tuple(attempted),
        evidence_ref=evidence_ref,
    )
