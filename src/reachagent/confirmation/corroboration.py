"""Multi-shot corroboration (Build Order 5).

The oracle stays necessary: nothing here creates a Finding by itself, and
every individual attempt this module drives is still gated behind its own
real ``run_oracle`` call — corroboration only decides whether to trust the
aggregate result of several independent, already-oracle-gated attempts
instead of just one. Scoped deliberately narrow, per this session's own
precision review: signal-noisy oracle families (TIMING_STATISTICAL above
all — network jitter or transient system load can tip one paired-trial
measurement) are where a single confirmed attempt is the weakest evidence;
sentinel-in-body STRUCTURAL/DIFFERENTIAL checks that either see an exact
marker or don't have no comparable flakiness to correct for, so corroborating
them adds cost without adding trustworthiness. A caller decides per-class
whether corroboration is worth the extra requests, not this module.

``_MAX_ATTEMPTS`` is a hard, explicit cap — corroboration exists to catch a
one-off flaky signal, never to let an ambiguous candidate be probed
indefinitely until it happens to agree.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

_MAX_ATTEMPTS = 3


@dataclass(frozen=True)
class CorroborationResult:
    """Outcome of a bounded multi-shot corroboration attempt."""

    corroborated: bool
    agreements: int
    attempts: int


def corroborate(
    attempt: Callable[[], bool],
    *,
    required_agreements: int = 2,
    max_attempts: int = _MAX_ATTEMPTS,
) -> CorroborationResult:
    """Call ``attempt`` up to ``max_attempts`` times; stop once agreement is reached.

    ``attempt`` performs one full, independent, already-oracle-gated
    detection attempt and returns whether IT ALSO confirmed the violation.
    This never replaces the original oracle confirmation that got a
    candidate here in the first place — it strengthens (or, if the signal
    doesn't reproduce, withdraws confidence in) a result that already
    passed the oracle once, for oracle families known to carry residual
    noise. Stops as soon as ``required_agreements`` is reached (no wasted
    extra requests once the answer is already decided); never exceeds
    ``max_attempts`` regardless of how the attempts land.
    """
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")
    if required_agreements < 1 or required_agreements > max_attempts:
        raise ValueError("required_agreements must be between 1 and max_attempts")
    agreements = 0
    for attempt_number in range(1, max_attempts + 1):
        if attempt():
            agreements += 1
            if agreements >= required_agreements:
                return CorroborationResult(
                    corroborated=True, agreements=agreements, attempts=attempt_number
                )
    return CorroborationResult(corroborated=False, agreements=agreements, attempts=max_attempts)
