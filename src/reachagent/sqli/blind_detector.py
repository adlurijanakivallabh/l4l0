"""Blind SQL injection detection — OOB-first, timing fallback (plan §7, §9; Task 1).

Orchestrates the three deterministic oracles blind SQLi can use, in the §9
confidence order, so the *definitive* mechanism is always attempted before the
noisy one:

  1. **OOB callback** (``oob_callback``) — a DB-native out-of-band payload exfils
     to a per-probe subdomain on the self-hosted collaborator. If the callback
     with this probe's nonce arrives, the :class:`OOBCallbackOracle` confirms.
     Definitive, no statistical noise → tried first (§9 ordering).
  2. **Paired-trial timing** (``timing_statistical``) — only when no OOB callback
     was received. N≥10 probe trials (time-delay payload) vs N≥10 baseline
     trials (benign control), decided by the Task 2 oracle. The fallback, never
     the default.
  3. **Boolean-blind differential** (``differential``) — for boolean-blind
     targets: a TRUE-condition and a FALSE-condition request a safe app answers
     identically. Divergence proves the condition reached the backend. Required
     to be **consistent across ≥3 repeated trial pairs** before it counts — a
     single divergent pair could be noise; a stable separation is signal.

The ordering is the load-bearing guarantee: :func:`detect_blind_sqli` selects
payloads via the library (already ranked OOB-before-timing, §9) and returns at
the first confirmation, so timing is reached *only* after OOB was genuinely
attempted and produced no callback — never used unconditionally.

Every oracle call goes through the Validator's ``run_oracle`` — the same
deterministic gate as every other finding (CLAUDE.md non-negotiable). This
module proposes candidates and sequences probes; it never mints a verdict.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles import OracleMechanism
from reachagent.oracles.differential import (
    DiffAxis,
    DifferentialEvidence,
    DiffExpectation,
    Observation,
)
from reachagent.oracles.oob_callback import OOBCallbackEvidence
from reachagent.oracles.timing_statistical import PairedTrialEvidence
from reachagent.tools.validator import run_oracle

# A boolean-blind separation must repeat across at least this many trial pairs
# before it counts — one divergent pair could be jitter, a stable run is signal.
_MIN_BOOLEAN_TRIALS = 3


@dataclass(frozen=True)
class OOBProbe:
    """One OOB probe: the nonce it embedded and the callback domain it exfil'd to."""

    nonce: str
    callback_domain: str


@dataclass(frozen=True)
class TimingProbe:
    """Measured latencies from a paired timing probe (probe vs benign baseline)."""

    probe_latencies_ms: tuple[float, ...]
    baseline_latencies_ms: tuple[float, ...]


@dataclass(frozen=True)
class BooleanTrialPair:
    """One TRUE/FALSE condition pair a safe app should answer identically."""

    true_condition: Observation
    false_condition: Observation


@dataclass(frozen=True)
class BlindSqliResult:
    """Outcome of a blind-SQLi detection attempt.

    ``confirmed`` is true only if an oracle returned ``confirmed_violation``.
    ``mechanism`` names which family confirmed (or was last tried). ``attempted``
    records every mechanism tried, in order — the audit trail proving OOB was
    attempted before timing, not skipped.
    """

    confirmed: bool
    mechanism: OracleMechanism | None
    attempted: tuple[OracleMechanism, ...] = ()
    evidence_ref: str = ""


@dataclass
class BlindSqliProber:
    """Injectable probe callbacks — the seam that keeps detection hermetic.

    Each callable performs the actual firing for one mechanism and returns the
    measured evidence. Tests supply in-memory fakes; the live detector supplies
    firer/collaborator-backed implementations. The detector itself contains only
    the *ordering* logic, no I/O — so the OOB-first guarantee is unit-testable
    without a network.
    """

    # Fire the OOB payload for a probe; return the OOBProbe it launched, or None
    # if this target has no OOB-capable payload available.
    fire_oob: Callable[[], OOBProbe | None]
    # Snapshot the collaborator's observed nonces after the OOB probe window.
    observed_nonces: Callable[[], frozenset[str]]
    # Fire the paired timing trials; return measured latencies.
    fire_timing: Callable[[], TimingProbe]
    # Fire ≥3 boolean TRUE/FALSE pairs; return them. Empty if not a boolean-blind
    # candidate (then this path is skipped).
    fire_boolean_pairs: Callable[[], Sequence[BooleanTrialPair]] = lambda: ()


def _oob_confirms(prober: BlindSqliProber, evidence_ref: str) -> tuple[bool, OOBProbe | None]:
    """Attempt the OOB path. Return (confirmed, probe). Probe is None if unavailable."""
    probe = prober.fire_oob()
    if probe is None:
        return False, None
    evidence = OOBCallbackEvidence(
        probe_nonce=probe.nonce,
        observed_nonces=prober.observed_nonces(),
        evidence_ref=evidence_ref,
    )
    verdict = run_oracle(OracleMechanism.OOB_CALLBACK, evidence)
    return verdict.is_violation, probe


def _timing_confirms(prober: BlindSqliProber, evidence_ref: str) -> bool:
    """Attempt the timing fallback. Return whether it confirmed."""
    probe = prober.fire_timing()
    evidence = PairedTrialEvidence(
        probe_latencies_ms=probe.probe_latencies_ms,
        baseline_latencies_ms=probe.baseline_latencies_ms,
        evidence_ref=evidence_ref,
    )
    verdict = run_oracle(OracleMechanism.TIMING_STATISTICAL, evidence)
    return verdict.is_violation


def _boolean_confirms(prober: BlindSqliProber, evidence_ref: str) -> bool:
    """Boolean-blind via differential, required consistent across ≥3 trial pairs.

    Each pair is a TRUE/FALSE condition a safe app answers identically; the
    differential oracle flags a divergence (RESPONSES_INVARIANT violated) as the
    condition reaching the backend. A single divergent pair is not enough — every
    one of the ≥3 pairs must diverge the same way, or it's treated as noise.
    """
    pairs = list(prober.fire_boolean_pairs())
    if len(pairs) < _MIN_BOOLEAN_TRIALS:
        return False
    for pair in pairs:
        evidence = DifferentialEvidence(
            axis=DiffAxis.CROSS_CONDITION,
            expectation=DiffExpectation.RESPONSES_INVARIANT,
            baseline=pair.true_condition,
            probe=pair.false_condition,
            evidence_ref=evidence_ref,
        )
        verdict = run_oracle(OracleMechanism.DIFFERENTIAL, evidence)
        if verdict.status is not FindingStatus.CONFIRMED_VIOLATION:
            # Any pair that does not diverge breaks the consistency requirement.
            return False
    return True


def detect_blind_sqli(
    prober: BlindSqliProber,
    *,
    evidence_ref: str = "",
    try_boolean: bool = True,
) -> BlindSqliResult:
    """Detect blind SQLi OOB-first, falling back to timing, then boolean (§7, §9).

    Ordering is the contract: OOB is attempted first and, only if it produced no
    callback, timing is tried. Boolean-blind differential is an independent path
    tried after timing (a target may be boolean-blind without a time/OOB sink).
    Returns at the first confirmation; ``attempted`` records the order for audit.
    """
    attempted: list[OracleMechanism] = []

    # 1. OOB callback — definitive, tried first (§9 ordering).
    attempted.append(OracleMechanism.OOB_CALLBACK)
    oob_ok, _probe = _oob_confirms(prober, evidence_ref)
    if oob_ok:
        return BlindSqliResult(True, OracleMechanism.OOB_CALLBACK, tuple(attempted), evidence_ref)

    # 2. Timing fallback — only reached because OOB produced no callback.
    attempted.append(OracleMechanism.TIMING_STATISTICAL)
    if _timing_confirms(prober, evidence_ref):
        return BlindSqliResult(
            True, OracleMechanism.TIMING_STATISTICAL, tuple(attempted), evidence_ref
        )

    # 3. Boolean-blind differential — independent path, ≥3 consistent trial pairs.
    if try_boolean:
        attempted.append(OracleMechanism.DIFFERENTIAL)
        if _boolean_confirms(prober, evidence_ref):
            return BlindSqliResult(
                True, OracleMechanism.DIFFERENTIAL, tuple(attempted), evidence_ref
            )

    return BlindSqliResult(False, None, tuple(attempted), evidence_ref)
