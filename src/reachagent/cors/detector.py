"""CORS misconfiguration — credentialed origin reflection (§5/§7, v1.5).

Uses the STRUCTURAL oracle's CORS_MISCONFIG branch. One read-only probe:

  Send a request carrying an attacker ``Origin`` header and read two response
  headers back — ``Access-Control-Allow-Origin`` (acao) and
  ``Access-Control-Allow-Credentials`` (acac). A violation is an
  origin-reflected ACAO (``acao == probe_origin``) combined with credentials on
  (``acac`` lower-cases to ``true``). A bare ``ACAO: *`` with credentials is not
  exploitable — browsers reject the pair — so it is never a violation.

Read-only-first (§10): the probe is a header-reading GET, not a write. No
state-changing request is needed; the read-only-first constraint is satisfied
by the nature of the class.

Prober-injection seam: ``CorsProber`` holds one callback and the probe origin;
tests supply in-memory fakes; the live path supplies firer-backed
implementations. The detector never imports ``reachagent.tools.validator`` —
confirmation crosses the oracle seam (§13, CLAUDE.md non-negotiable).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from reachagent.detection.oracle_gateway import OracleRunner, registry_runner
from reachagent.oracles import OracleMechanism
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence


@dataclass(frozen=True)
class CorsHeaders:
    """The two CORS header values read from one probe."""

    acao: str = ""
    acac: str = ""


@dataclass
class CorsProber:
    """Injectable probe callback — keeps detection hermetic and ordering testable.

    ``fire_probe``: fire the request carrying the attacker ``Origin`` and return
    the ACAO/ACAC header values the server sent back.
    ``probe_origin``: the attacker ``Origin`` value the probe sent — reflection is
    judged against this.
    ``oracle_runner``: injectable oracle seam; defaults to registry (no validator import).
    """

    fire_probe: Callable[[], CorsHeaders]
    probe_origin: str
    oracle_runner: OracleRunner = registry_runner


@dataclass(frozen=True)
class CorsResult:
    """Outcome of a CORS misconfiguration detection attempt."""

    confirmed: bool
    evidence_ref: str = ""


def detect_cors_misconfig(
    prober: CorsProber,
    *,
    evidence_ref: str = "",
) -> CorsResult:
    """Detect CORS misconfiguration — credentialed origin reflection (§5/§7).

    Fires the header-reading probe with the attacker ``Origin`` and routes the
    ACAO/ACAC values through the STRUCTURAL oracle's CORS_MISCONFIG branch.
    Read-only GET (§10).
    """
    probe = prober.fire_probe()
    evidence = StructuralEvidence(
        check_type=StructuralCheckType.CORS_MISCONFIG,
        acao=probe.acao,
        acac=probe.acac,
        probe_origin=prober.probe_origin,
        evidence_ref=evidence_ref,
    )
    verdict = prober.oracle_runner(OracleMechanism.STRUCTURAL, evidence)
    return CorsResult(confirmed=verdict.is_violation, evidence_ref=evidence_ref)
