"""Paired-trial statistical timing oracle (plan §7, Phase 3 Task 2).

The ``timing_statistical`` §7 oracle family. Confirms a time-delay injection
only when a statistically significant latency effect is present in the probe
trials and absent in the negative-control (baseline) trials — ruling out
network jitter as the cause.

Decision path contains **zero LLM input**: pure arithmetic over measured
latencies. Same evidence in, same verdict out, every time.

OOB-first discipline (§7): this oracle is the *fallback* for blind SQLi (the
``OOB_CALLBACK`` family is tried first); it is the *primary* oracle for NoSQLi
and LDAP extraction, which have no OOB channel. The caller (detector) decides
which oracle to invoke — this oracle has no knowledge of OOB availability.

Negative control is mandatory: a single timing measurement cannot confirm a
violation. The oracle requires a paired baseline trial fired under identical
conditions (same endpoint, same identity, same non-delay payload). Supplying
only probe trials raises :class:`ValidationError` rather than returning
inconclusive — a mis-wired caller is a bug, not an ambiguous result.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import Oracle, OracleVerdict

# Minimum trials per arm — fewer is not a paired trial, it's a guess.
_MIN_TRIALS = 10


class ValidationError(ValueError):
    """Raised when evidence fails structural requirements before any decision.

    Distinct from inconclusive: a missing baseline or too-few trials is a
    caller bug, not an ambiguous timing result. The oracle never silently
    returns inconclusive for a structurally invalid input.
    """


@dataclass(frozen=True)
class PairedTrialEvidence:
    """Latency measurements from a paired probe/baseline trial run.

    ``probe_latencies_ms``: N≥10 measurements with the time-delay payload.
    ``baseline_latencies_ms``: N≥10 measurements with the benign control
    payload, fired under identical conditions (same endpoint, same identity).
    ``threshold_multiplier``: how many baseline standard deviations above the
    baseline mean the probe mean must exceed to confirm. Default 3.0 — chosen
    to reject jitter (typically 1–2σ) while confirming deliberate delays
    (a 5 s delay against a sub-second baseline is always >> 3σ).
    ``evidence_ref``: short, secret-free provenance handle (§13).
    """

    probe_latencies_ms: tuple[float, ...]
    baseline_latencies_ms: tuple[float, ...]
    threshold_multiplier: float = 3.0
    evidence_ref: str = ""


def _mean(xs: tuple[float, ...]) -> float:
    return sum(xs) / len(xs)


def _std(xs: tuple[float, ...]) -> float:
    """Population standard deviation — deterministic, no sampling."""
    m = _mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs))


def decide(evidence: PairedTrialEvidence) -> FindingStatus:
    """Map paired-trial evidence to exactly one verdict — the whole decision (§7).

    Pure and total: every valid input returns exactly one of the four
    :class:`FindingStatus` values, with no LLM anywhere in the path.

    Raises :class:`ValidationError` (not inconclusive) when structural
    requirements are not met — a missing baseline or too-few trials is a
    caller bug.

    Decision rule:
      probe_mean >= baseline_mean + threshold_multiplier * baseline_std
      AND probe_mean > baseline_mean  (directional — delays are one-way)

    When baseline_std == 0 (perfectly stable baseline), the threshold
    collapses to probe_mean > baseline_mean, which is correct: any probe
    latency above a perfectly stable baseline is a real signal.
    """
    if len(evidence.baseline_latencies_ms) < _MIN_TRIALS:
        raise ValidationError(
            f"baseline requires ≥{_MIN_TRIALS} trials, "
            f"got {len(evidence.baseline_latencies_ms)} — "
            "a single measurement cannot rule out network jitter"
        )
    if len(evidence.probe_latencies_ms) < _MIN_TRIALS:
        raise ValidationError(
            f"probe requires ≥{_MIN_TRIALS} trials, got {len(evidence.probe_latencies_ms)}"
        )

    baseline_mean = _mean(evidence.baseline_latencies_ms)
    baseline_std = _std(evidence.baseline_latencies_ms)
    probe_mean = _mean(evidence.probe_latencies_ms)

    threshold = baseline_mean + evidence.threshold_multiplier * baseline_std
    if probe_mean >= threshold and probe_mean > baseline_mean:
        return FindingStatus.CONFIRMED_VIOLATION
    return FindingStatus.INCONCLUSIVE


class TimingStatisticalOracle(Oracle):
    """Confirms via paired-trial timing — one of the six §7 families."""

    mechanism = OracleMechanism.TIMING_STATISTICAL

    def run(self, evidence: object) -> OracleVerdict:
        """Return the deterministic verdict for ``evidence`` (must be PairedTrialEvidence).

        Raises ``TypeError`` on wrong evidence type — a mis-wired caller is a
        bug, not an inconclusive result (mirrors the differential oracle).
        Raises ``ValidationError`` when structural requirements fail (missing
        baseline, too-few trials).
        """
        if not isinstance(evidence, PairedTrialEvidence):
            raise TypeError(
                f"TimingStatisticalOracle needs PairedTrialEvidence, got {type(evidence).__name__}"
            )
        status = decide(evidence)
        return OracleVerdict(
            mechanism=self.mechanism,
            status=status,
            evidence_ref=evidence.evidence_ref,
        )
