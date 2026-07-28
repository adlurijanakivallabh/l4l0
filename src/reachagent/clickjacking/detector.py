"""Clickjacking — missing framing defenses (§5/§7, v1.5).

Uses the STRUCTURAL oracle's CLICKJACKING branch. One read-only probe:

  Fetch the page and read two response headers — ``X-Frame-Options`` and
  ``Content-Security-Policy``. A framing defense is effective if XFO is
  present (any value) OR the CSP carries a ``frame-ancestors`` directive.
  Both absent → the page is framable → violation.

Read-only-first (§10): the probe is a header-reading GET, not a write. No
state-changing request is needed; the read-only-first constraint is satisfied
by the nature of the class.

Prober-injection seam: ``ClickjackingProber`` holds one callback; tests supply
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
class FramingHeaders:
    """The two framing-defense header values read from one probe."""

    x_frame_options: str = ""
    csp: str = ""


@dataclass
class ClickjackingProber:
    """Injectable probe callback — keeps detection hermetic and ordering testable.

    ``fire_probe``: fire the header-reading GET and return the two framing-defense
    header values.
    ``oracle_runner``: injectable oracle seam; defaults to registry (no validator import).
    """

    fire_probe: Callable[[], FramingHeaders]
    oracle_runner: OracleRunner = registry_runner


@dataclass(frozen=True)
class ClickjackingResult:
    """Outcome of a clickjacking detection attempt."""

    confirmed: bool
    evidence_ref: str = ""


def detect_clickjacking(
    prober: ClickjackingProber,
    *,
    evidence_ref: str = "",
) -> ClickjackingResult:
    """Detect clickjacking — both framing defenses absent (§5/§7).

    Fires the header-reading probe and routes the two header values through the
    STRUCTURAL oracle's CLICKJACKING branch. Read-only GET (§10).
    """
    probe = prober.fire_probe()
    evidence = StructuralEvidence(
        check_type=StructuralCheckType.CLICKJACKING,
        x_frame_options=probe.x_frame_options,
        csp=probe.csp,
        evidence_ref=evidence_ref,
    )
    verdict = prober.oracle_runner(OracleMechanism.STRUCTURAL, evidence)
    return ClickjackingResult(confirmed=verdict.is_violation, evidence_ref=evidence_ref)
