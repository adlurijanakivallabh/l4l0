"""Open redirect — attacker URL echoed into the Location header (§7).

Uses the STRUCTURAL oracle's OPEN_REDIRECT branch. One read-only probe:

  Send a GET with a redirect-shaped query parameter (``redirect``, ``next``,
  ``returnUrl``, ...) set to an attacker-controlled URL, and read the
  response's ``Location`` header back. A violation is a 3xx response whose
  ``Location`` contains the injected URL verbatim — the server sent the
  browser straight to it without validating the destination stays in-scope.

Read-only-first (§10): the probe is a GET and the firer never follows the
redirect, so the attacker destination is never actually visited.

Prober-injection seam: ``OpenRedirectProber`` holds one callback and the
probe target; tests supply in-memory fakes; the live path supplies
firer-backed implementations. The detector never imports
``reachagent.tools.validator`` — confirmation crosses the oracle seam (§13,
CLAUDE.md non-negotiable).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from reachagent.detection.oracle_gateway import OracleRunner, registry_runner
from reachagent.oracles import OracleMechanism
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence


@dataclass(frozen=True)
class RedirectProbe:
    """The status and ``Location`` header observed from one probe."""

    status: int = 0
    location: str = ""


@dataclass
class OpenRedirectProber:
    """Injectable probe callback — keeps detection hermetic and ordering testable.

    ``fire_probe``: fire the GET carrying the attacker-controlled redirect
    target and return the response's status + ``Location`` header.
    ``probe_target``: the exact attacker URL injected — reflection is judged
    against this.
    ``oracle_runner``: injectable oracle seam; defaults to registry (no validator import).
    """

    fire_probe: Callable[[], RedirectProbe]
    probe_target: str
    oracle_runner: OracleRunner = registry_runner


@dataclass(frozen=True)
class OpenRedirectResult:
    """Outcome of an open-redirect detection attempt."""

    confirmed: bool
    evidence_ref: str = ""


def detect_open_redirect(
    prober: OpenRedirectProber,
    *,
    evidence_ref: str = "",
) -> OpenRedirectResult:
    """Detect an open redirect — attacker URL echoed into ``Location`` (§7).

    Fires the read-only probe and routes the status/Location through the
    STRUCTURAL oracle's OPEN_REDIRECT branch.
    """
    probe = prober.fire_probe()
    evidence = StructuralEvidence(
        check_type=StructuralCheckType.OPEN_REDIRECT,
        probe_status=probe.status,
        location=probe.location,
        sentinel=prober.probe_target,
        evidence_ref=evidence_ref,
    )
    verdict = prober.oracle_runner(OracleMechanism.STRUCTURAL, evidence)
    return OpenRedirectResult(confirmed=verdict.is_violation, evidence_ref=evidence_ref)
