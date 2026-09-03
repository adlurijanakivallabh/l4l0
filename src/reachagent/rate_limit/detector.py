"""Login rate-limit absence (§7, Build Order 0).

Fires a small, bounded burst of wrong-credential login attempts — never a
real brute force, a fixed small N (``_BURST_SIZE``) — and checks whether
ANY attempt triggered a defensive signal (a 429 status, or a known
lockout/throttle body marker). No signal across a complete burst proves
the app never engages any rate limiting or account lockout, letting an
attacker try credentials indefinitely.

Maps onto the existing STRUCTURAL oracle family unchanged (§7,
``StructuralCheckType.RATE_LIMIT_ABSENT``) — no new mechanism, and
deliberately not BUSINESS_RULE_INVARIANT: that family's four templates are a
closed, tested set (CLAUDE.md — no fifth without a plan change), and none of
them model "did behavior change across a burst of otherwise-identical
requests," which is what this check actually needs.

Optional, OPT-IN technique-diversity corroboration (v3 V3): ``fire_second_attempt``
lets the caller wire in a SECOND, independent bounded burst, fired only after a
real cooldown window (``_COOLDOWN_S``, monkeypatchable for tests) and only when
the first burst already suggests absent rate-limiting — a confirmed absence is
only trusted once a second, independent burst ALSO shows no lockout signal,
ruling out a first burst that happened to run during a brief gap in the app's
own defensive throttling (e.g. a sliding window that had just reset) rather
than a systemic absence of rate limiting. Unlike every other v3 V3 slice, this
one is gated by the ORCHESTRATOR behind an explicit opt-in flag, never
default-on — see ``scan/orchestrator.py::run_rate_limit_absence`` for why
(doubling live attempts against a real auth endpoint is a materially
different risk profile than a read-only or idempotent-write re-probe).
Optional and additive at this module's own level too: when
``fire_second_attempt`` is omitted (the default), behavior is byte-for-byte
unchanged from before this was added.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from reachagent.confirmation.corroboration import corroborate_with_variant
from reachagent.detection.oracle_gateway import OracleRunner, registry_runner
from reachagent.oracles import OracleMechanism
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence

# Small, fixed, never brute-force-scale. Matches the plan's own "bounded,
# small, fixed-N probe" requirement.
_BURST_SIZE = 6

# How long the corroborating second burst waits before firing — long enough
# that a hit can't be explained by both bursts landing in the same brief
# window of the target's own rate-limit state. A module-level constant so
# tests can monkeypatch it down to 0 rather than paying the real delay.
_COOLDOWN_S = 30.0

# Known lockout/throttle body markers — same disclosed-limit shape as the
# other marker tables in this codebase (subdomain_takeover, info_disclosure).
LOCKOUT_MARKERS: tuple[str, ...] = (
    "too many attempts",
    "too many requests",
    "account locked",
    "account is locked",
    "temporarily locked",
    "try again later",
    "rate limit",
)


def has_lockout_signal(status_code: int, body: str) -> bool:
    """Whether one response shows a rate-limit/lockout defensive signal."""
    if status_code == 429:
        return True
    lowered = body.lower()
    return any(marker in lowered for marker in LOCKOUT_MARKERS)


@dataclass(frozen=True)
class RateLimitProbe:
    """One login attempt's outcome."""

    status: int
    body: str


@dataclass
class RateLimitProber:
    """Injectable probe callback — keeps detection hermetic and ordering testable.

    ``fire_attempt``: fire one wrong-credential login attempt and return its
    status/body. Called up to ``_BURST_SIZE`` times.
    ``oracle_runner``: injectable oracle seam; defaults to registry.
    ``fire_second_attempt`` (v3 V3, optional, opt-in): a second, independent
    burst's per-attempt callable, same shape as ``fire_attempt`` — see module
    docstring.
    """

    fire_attempt: Callable[[int], RateLimitProbe]
    oracle_runner: OracleRunner = registry_runner
    fire_second_attempt: Callable[[int], RateLimitProbe] | None = None


@dataclass(frozen=True)
class RateLimitResult:
    """Outcome of a rate-limit-absence detection attempt."""

    confirmed: bool
    attempts_completed: int = 0
    evidence_ref: str = ""
    corroborated: bool = False


def _fire_burst(fire_attempt: Callable[[int], RateLimitProbe]) -> tuple[int, bool]:
    """Fire up to ``_BURST_SIZE`` attempts; return (completed, lockout_observed).

    Stops early (without penalty — the burst simply completed) the moment a
    lockout signal is observed; a network/transport failure mid-burst ends
    the burst early with whatever completed so far.
    """
    completed = 0
    lockout_observed = False
    for i in range(_BURST_SIZE):
        try:
            probe = fire_attempt(i)
        except Exception:  # noqa: BLE001 — a transport failure ends the burst early
            break
        completed += 1
        if has_lockout_signal(probe.status, probe.body):
            lockout_observed = True
            break
    return completed, lockout_observed


def _burst_evidence(
    completed: int, lockout_observed: bool, *, evidence_ref: str
) -> StructuralEvidence:
    # A lockout observed before the full burst ran is still a complete,
    # decisive answer ("rate limiting works") — stopping early is not an
    # incomplete burst, so attempts_completed reads as the full plan in that
    # case; only a transport failure with no lockout signal is incomplete.
    return StructuralEvidence(
        check_type=StructuralCheckType.RATE_LIMIT_ABSENT,
        attempts_planned=_BURST_SIZE,
        attempts_completed=_BURST_SIZE if lockout_observed else completed,
        lockout_signal_observed=lockout_observed,
        evidence_ref=evidence_ref,
    )


def detect_rate_limit_absence(
    prober: RateLimitProber,
    *,
    evidence_ref: str = "",
) -> RateLimitResult:
    """Fire the bounded burst and reconfirm through the STRUCTURAL oracle.

    When ``prober.fire_second_attempt`` is set, a confirmed first burst is
    corroborated against a second, independent burst (fired after a real
    cooldown — see ``_COOLDOWN_S``) before being trusted (v3 V3, opt-in) — a
    contradicted corroboration fails closed to not-confirmed, never falls
    back to the uncorroborated first result.
    """
    completed, lockout_observed = _fire_burst(prober.fire_attempt)
    evidence = _burst_evidence(completed, lockout_observed, evidence_ref=evidence_ref)
    verdict = prober.oracle_runner(OracleMechanism.STRUCTURAL, evidence)
    if prober.fire_second_attempt is None:
        return RateLimitResult(
            confirmed=verdict.is_violation, attempts_completed=completed, evidence_ref=evidence_ref
        )
    if not verdict.is_violation:
        return RateLimitResult(
            confirmed=False, attempts_completed=completed, evidence_ref=evidence_ref
        )

    def _second_attempt() -> object:
        time.sleep(_COOLDOWN_S)
        second_completed, second_lockout = _fire_burst(prober.fire_second_attempt)  # type: ignore[arg-type]
        second_evidence = _burst_evidence(
            second_completed, second_lockout, evidence_ref=evidence_ref
        )
        return prober.oracle_runner(OracleMechanism.STRUCTURAL, second_evidence)

    result = corroborate_with_variant(verdict, _second_attempt)
    return RateLimitResult(
        confirmed=result.corroborated,
        attempts_completed=completed,
        evidence_ref=evidence_ref,
        corroborated=result.corroborated,
    )
