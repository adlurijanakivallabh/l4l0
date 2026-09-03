"""Multi-shot corroboration (Build Order 5; extended v3 V3).

The oracle stays necessary: nothing here creates a Finding by itself, and
every individual attempt this module drives is still gated behind its own
real ``run_oracle``/``judge()`` call — corroboration only decides whether to
trust the aggregate result of several independent, already-oracle-gated
attempts instead of just one. A caller decides per-class whether
corroboration is worth the extra requests, not this module.

Three complementary mechanisms live here, for three different failure modes:

- :func:`corroborate` — REPEAT-and-vote. Re-runs the IDENTICAL measurement N
  times and requires majority agreement. Scoped deliberately narrow, per
  this session's own precision review: signal-noisy oracle families
  (TIMING_STATISTICAL above all — network jitter or transient system load
  can tip one paired-trial measurement) are where a single confirmed
  attempt is the weakest evidence; a deterministic sentinel-in-body
  STRUCTURAL/DIFFERENTIAL check either sees the exact marker or doesn't —
  no comparable flakiness to correct for, so repeating it adds cost without
  adding trustworthiness.
- :func:`corroborate_with_variant` (v3 V3) — VARY-and-confirm. Fires ONE
  genuinely DIFFERENT probe of the same hypothesis (a second file, a second
  credential pair, a second parameter) to rule out a coincidental
  single-signal false positive — the mechanism CLAUDE.md's own worked
  example describes ("read a target file... try additional files to
  corroborate"). This is exactly the case :func:`corroborate` explicitly
  does NOT help with (varying the technique, not repeating it), so the two
  are complementary, not competing — an oracle family could in principle
  use both.
- :func:`corroborate_by_refutation` (v3 V3) — INVERTED-polarity control
  probe. For a class where different POSITIVE variants are independent
  probes of a filter/allowlist rather than symptoms of one shared flaw (a
  target may have exactly one working default-credential pair, or one
  un-sanitized operator among several tried), demanding a SECOND positive
  also succeed would suppress the realistic single-variant-found case —
  this is the exact AUTH_BYPASS mistake this project made and reverted.
  Instead, fires ONE control probe DELIBERATELY constructed to be expected
  to fail (a never-allowlisted credential pair, e.g.), and treats that
  expected refusal — not another success — as what corroborates the
  primary. A control probe that unexpectedly also "succeeds" means the
  underlying check can't actually discriminate, so the primary is not
  trusted.

``_MAX_ATTEMPTS`` is a hard, explicit cap on :func:`corroborate` —
corroboration exists to catch a one-off flaky signal, never to let an
ambiguous candidate be probed indefinitely until it happens to agree.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

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


class _HasIsViolation(Protocol):
    """Structural type both `OracleVerdict` and `OracleOutcome` satisfy."""

    @property
    def is_violation(self) -> bool: ...


@dataclass(frozen=True)
class VariantCorroborationResult:
    """Outcome of confirming a primary verdict with one DIFFERENT real probe
    (a second file/credential/param/technique — never a repeat of the
    identical request) rather than a repeat-and-vote measurement.

    ``secondary_verdict`` is ``None`` when the primary never confirmed in the
    first place (no second probe was worth firing).
    """

    corroborated: bool
    primary_verdict: _HasIsViolation
    secondary_verdict: _HasIsViolation | None


def corroborate_with_variant(
    primary_verdict: _HasIsViolation,
    second_attempt: Callable[[], _HasIsViolation],
) -> VariantCorroborationResult:
    """Technique-diversity corroboration — the complementary mechanism to
    :func:`corroborate` above, for a DIFFERENT failure mode.

    :func:`corroborate` repeats the IDENTICAL measurement to rule out
    transient noise (network jitter, system load) in signal-noisy oracle
    families like TIMING_STATISTICAL — appropriate there because a
    deterministic sentinel-in-body check has no such noise to rule out
    (see this module's own docstring). This function instead fires ONE
    genuinely DIFFERENT probe of the same underlying hypothesis — a second
    file for path traversal, a second credential pair for default creds, a
    second redirect-shaped parameter — to rule out a DIFFERENT failure mode:
    a coincidental single-signal match (the target happens to echo content
    that looks like proof for an unrelated reason). This is the mechanism
    CLAUDE.md's own worked example describes ("read a target file... try
    additional files to corroborate"), and the two are meant to compose,
    not compete: an oracle family could in principle use both.

    ``second_attempt`` is called ONLY if ``primary_verdict.is_violation`` —
    a primary that never confirmed has nothing to corroborate, so no second
    request is fired (never wastes a probe confirming a negative). A
    primary that confirms but whose corroborating probe does NOT also
    confirm fails closed (``corroborated=False``) — a contradicted
    corroboration means the pipeline doesn't confirm, the same fail-closed
    posture ``oracles/llm_judgment.py::judge`` already uses at every seam.
    """
    if not primary_verdict.is_violation:
        return VariantCorroborationResult(
            corroborated=False, primary_verdict=primary_verdict, secondary_verdict=None
        )
    secondary_verdict = second_attempt()
    return VariantCorroborationResult(
        corroborated=secondary_verdict.is_violation,
        primary_verdict=primary_verdict,
        secondary_verdict=secondary_verdict,
    )


@dataclass(frozen=True)
class RefutationCorroborationResult:
    """Outcome of corroborating a primary verdict by attempting to REFUTE it
    with a control probe expected to fail — the inverted-polarity sibling of
    :func:`corroborate_with_variant`.

    ``refutation_verdict`` is ``None`` when the primary never confirmed in
    the first place (no control probe was worth firing).
    """

    corroborated: bool
    primary_verdict: _HasIsViolation
    refutation_verdict: _HasIsViolation | None


def corroborate_by_refutation(
    primary_verdict: _HasIsViolation,
    refutation_attempt: Callable[[], _HasIsViolation],
) -> RefutationCorroborationResult:
    """Inverted-polarity corroboration — see this module's own docstring.

    ``refutation_attempt`` is called ONLY if ``primary_verdict.is_violation``
    (mirrors :func:`corroborate_with_variant` — never wastes a probe
    confirming a negative). ``refutation_attempt`` must itself already
    encode "ambiguous/uncertain" as ``is_violation=True`` (e.g. a transport
    failure during the control probe) — this function has no visibility into
    why the control probe reports what it does, only what it reports.
    ``corroborated`` is True only when the control probe's own verdict is
    NOT a violation (a confirmed refusal); any other outcome — an
    unexpected success, or an ambiguous/errored attempt — fails closed,
    mirroring the same fail-closed posture ``oracles/llm_judgment.py::judge``
    already uses at every seam.
    """
    if not primary_verdict.is_violation:
        return RefutationCorroborationResult(
            corroborated=False, primary_verdict=primary_verdict, refutation_verdict=None
        )
    refutation_verdict = refutation_attempt()
    return RefutationCorroborationResult(
        corroborated=not refutation_verdict.is_violation,
        primary_verdict=primary_verdict,
        refutation_verdict=refutation_verdict,
    )
