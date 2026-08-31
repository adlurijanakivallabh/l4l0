"""HTTP request smuggling — CL.TE desync detection via timing (plan §7).

A front-end/back-end pair that disagrees about where one request's body ends
(one honors ``Content-Length``, the other ``Transfer-Encoding``) can be probed
safely with a single, self-contained request: a body shaped so a CL-reading
front-end forwards it whole, while a TE-reading back-end treats it as a
complete request followed by the *start* of a second one it never receives the
rest of — and hangs. No second "smuggled" request is ever sent to complete
that hang, so no other connection or user's traffic is ever touched; the hang
itself, bounded by a hard timeout, is the signal. This is a live-transport
probe a request library can't construct (ambiguous CL/TE pairs get normalized
away) — the raw-socket half lives in ``raw_probe.py``; this module only
sequences already-measured latencies through the oracle.

Reuses the existing paired-trial statistical oracle unchanged (§7,
``timing_statistical``) — same shape as the blind-SQLi timing fallback, no new
oracle mechanism. Every oracle call goes through the Validator's ``run_oracle``
(CLAUDE.md non-negotiable); this module never mints a verdict itself.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from reachagent.detection.oracle_gateway import OracleRunner, registry_runner
from reachagent.oracles import OracleMechanism
from reachagent.oracles.timing_statistical import PairedTrialEvidence


@dataclass(frozen=True)
class SmugglingTimingProbe:
    """Measured latencies: CL.TE-ambiguous probe vs well-formed baseline."""

    probe_latencies_ms: tuple[float, ...]
    baseline_latencies_ms: tuple[float, ...]


@dataclass
class SmugglingProber:
    """Injectable probe callback — keeps detection hermetic and ordering testable.

    ``fire_timing``: fire the paired baseline/CL.TE-probe trials and return the
    measured latencies. ``oracle_runner``: injectable oracle seam; defaults to
    registry (no validator import).
    """

    fire_timing: Callable[[], SmugglingTimingProbe]
    oracle_runner: OracleRunner = registry_runner


@dataclass(frozen=True)
class SmugglingResult:
    """Outcome of a request-smuggling detection attempt."""

    confirmed: bool
    evidence_ref: str = ""


def detect_request_smuggling(
    prober: SmugglingProber,
    *,
    evidence_ref: str = "",
) -> SmugglingResult:
    """Detect a CL.TE desync via timing (§7).

    Fires the paired trials and routes the latencies through the existing
    TIMING_STATISTICAL oracle's paired-trial decision — the same rigor (≥10
    trials/arm, 3-sigma threshold) every other timing-based class already
    requires, so a single network hiccup can't confirm a violation.
    """
    probe = prober.fire_timing()
    evidence = PairedTrialEvidence(
        probe_latencies_ms=probe.probe_latencies_ms,
        baseline_latencies_ms=probe.baseline_latencies_ms,
        evidence_ref=evidence_ref,
    )
    verdict = prober.oracle_runner(OracleMechanism.TIMING_STATISTICAL, evidence)
    return SmugglingResult(confirmed=verdict.is_violation, evidence_ref=evidence_ref)
