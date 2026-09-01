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
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from reachagent.detection.oracle_gateway import OracleRunner, registry_runner
from reachagent.oracles import OracleMechanism
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence

# Small, fixed, never brute-force-scale. Matches the plan's own "bounded,
# small, fixed-N probe" requirement.
_BURST_SIZE = 6

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
    """

    fire_attempt: Callable[[int], RateLimitProbe]
    oracle_runner: OracleRunner = registry_runner


@dataclass(frozen=True)
class RateLimitResult:
    """Outcome of a rate-limit-absence detection attempt."""

    confirmed: bool
    attempts_completed: int = 0
    evidence_ref: str = ""


def detect_rate_limit_absence(
    prober: RateLimitProber,
    *,
    evidence_ref: str = "",
) -> RateLimitResult:
    """Fire the bounded burst and reconfirm through the STRUCTURAL oracle.

    Stops early (without penalty — the burst simply completed) the moment a
    lockout signal is observed; a network/transport failure mid-burst is
    reported as an incomplete burst (INCONCLUSIVE, never a manufactured
    violation).
    """
    completed = 0
    lockout_observed = False
    for i in range(_BURST_SIZE):
        try:
            probe = prober.fire_attempt(i)
        except Exception:  # noqa: BLE001 — a transport failure ends the burst early
            break
        completed += 1
        if has_lockout_signal(probe.status, probe.body):
            lockout_observed = True
            break
    # A lockout observed before the full burst ran is still a complete,
    # decisive answer ("rate limiting works") — stopping early is not an
    # incomplete burst, so attempts_completed reads as the full plan in that
    # case; only a transport failure with no lockout signal is incomplete.
    evidence = StructuralEvidence(
        check_type=StructuralCheckType.RATE_LIMIT_ABSENT,
        attempts_planned=_BURST_SIZE,
        attempts_completed=_BURST_SIZE if lockout_observed else completed,
        lockout_signal_observed=lockout_observed,
        evidence_ref=evidence_ref,
    )
    verdict = prober.oracle_runner(OracleMechanism.STRUCTURAL, evidence)
    return RateLimitResult(
        confirmed=verdict.is_violation, attempts_completed=completed, evidence_ref=evidence_ref
    )
