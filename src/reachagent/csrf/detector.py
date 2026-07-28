"""CSRF missing-protection — structural precondition, not a confirmed exploit (§5/§7, v1.5).

Uses the STRUCTURAL oracle's CSRF_MISSING_PROTECTION branch. One read-only probe:

  Fire a normal read request and read its ``Set-Cookie`` header back, plus
  whether the app exposes an anti-CSRF token mechanism. A violation is a
  session cookie sent cross-site (``SameSite=None``) with no token mechanism —
  the deterministic structural precondition that leaves the app open to
  forgery. A token present, or ``SameSite=Lax``/``Strict``, means the
  precondition does not hold. An absent ``SameSite`` attribute is inconclusive
  (browsers default to ``Lax``).

This class is a **Partial** support level on purpose: it confirms a
*precondition*, NOT a confirmed CSRF exploit. Confirming a real CSRF would
require firing a forged cross-origin state-change, which violates
read-only-first (§10) — we do not do that. The probe only READS headers/body
from a normal read request, so read-only-first (§10) is satisfied by the nature
of the class.

Prober-injection seam: ``CsrfProber`` holds one callback; tests supply
in-memory fakes; the live path supplies firer-backed implementations. The
detector never imports ``reachagent.tools.validator`` — confirmation crosses
the oracle seam (§13, CLAUDE.md non-negotiable).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from reachagent.detection.oracle_gateway import OracleRunner, registry_runner
from reachagent.oracles import OracleMechanism
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence


@dataclass(frozen=True)
class CsrfSignals:
    """The signals read from one read-only probe."""

    set_cookie: str = ""
    csrf_token_present: bool = False


@dataclass
class CsrfProber:
    """Injectable probe callback — keeps detection hermetic and ordering testable.

    ``fire_probe``: fire the read-only request and return the ``Set-Cookie``
    value the server sent plus whether an anti-CSRF token mechanism is in play.
    ``oracle_runner``: injectable oracle seam; defaults to registry (no validator import).
    """

    fire_probe: Callable[[], CsrfSignals]
    oracle_runner: OracleRunner = registry_runner


@dataclass(frozen=True)
class CsrfResult:
    """Outcome of a CSRF missing-protection detection attempt."""

    confirmed: bool
    evidence_ref: str = ""


def detect_csrf_missing_protection(
    prober: CsrfProber,
    *,
    evidence_ref: str = "",
) -> CsrfResult:
    """Detect the CSRF missing-protection precondition (§5/§7) — Partial.

    Fires the read-only probe and routes the ``Set-Cookie`` / token signals
    through the STRUCTURAL oracle's CSRF_MISSING_PROTECTION branch. Confirms a
    structural precondition only — no forged state-change is fired, so
    read-only-first (§10) holds.
    """
    probe = prober.fire_probe()
    evidence = StructuralEvidence(
        check_type=StructuralCheckType.CSRF_MISSING_PROTECTION,
        set_cookie=probe.set_cookie,
        csrf_token_present=probe.csrf_token_present,
        evidence_ref=evidence_ref,
    )
    verdict = prober.oracle_runner(OracleMechanism.STRUCTURAL, evidence)
    return CsrfResult(confirmed=verdict.is_violation, evidence_ref=evidence_ref)
