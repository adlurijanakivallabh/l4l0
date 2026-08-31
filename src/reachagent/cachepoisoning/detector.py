"""Web cache poisoning — unkeyed-header reflection replayed from a shared cache (§7).

Uses the STRUCTURAL oracle's WEB_CACHE_POISONING branch. Two read-only GETs to
the same run-unique, cache-busted URL:

  1. The poisoning probe carries a commonly-unkeyed header (``X-Forwarded-Host``
     etc.) set to a run-unique marker.
  2. The re-read probe repeats the exact same URL with no special headers.

A violation is the marker surviving into the re-read's response body — the
only way an unrelated, header-free request could see it is a shared cache
having stored and replayed the first response. A marker present only in the
poisoning probe's own response proves per-request reflection with no cache
involved — not exploitable, denied.

Every probe URL carries a run-unique cache-buster (§10 spirit): a genuinely
poisoned cache entry only ever exists at a URL this run itself minted, so no
other visitor can ever request it — this technique never puts poisoned
content in front of real traffic.

Prober-injection seam: ``CachePoisoningProber`` holds one callback and the
injected marker; tests supply in-memory fakes; the live path supplies
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
class CachePoisoningProbe:
    """The status/body pair from both probes against the same cache-busted URL."""

    poisoned_status: int = 0
    poisoned_body: str = ""
    reread_body: str = ""


@dataclass
class CachePoisoningProber:
    """Injectable probe callback — keeps detection hermetic and ordering testable.

    ``fire_probe``: fire the poisoning GET (marker in an unkeyed header) and the
    clean re-read GET against the same cache-busted URL; return both bodies.
    ``marker``: the run-unique value injected — reflection is judged against it.
    ``oracle_runner``: injectable oracle seam; defaults to registry (no validator import).
    """

    fire_probe: Callable[[], CachePoisoningProbe]
    marker: str
    oracle_runner: OracleRunner = registry_runner


@dataclass(frozen=True)
class CachePoisoningResult:
    """Outcome of a web cache poisoning detection attempt."""

    confirmed: bool
    evidence_ref: str = ""


def detect_cache_poisoning(
    prober: CachePoisoningProber,
    *,
    evidence_ref: str = "",
) -> CachePoisoningResult:
    """Detect web cache poisoning — unkeyed header replayed from a shared cache (§7).

    Fires both probes and routes their bodies through the STRUCTURAL oracle's
    WEB_CACHE_POISONING branch. Read-only GETs (§10); no state is changed.
    """
    probe = prober.fire_probe()
    evidence = StructuralEvidence(
        check_type=StructuralCheckType.WEB_CACHE_POISONING,
        probe_status=probe.poisoned_status,
        sentinel=prober.marker,
        response_body=probe.poisoned_body,
        reread_response_body=probe.reread_body,
        evidence_ref=evidence_ref,
    )
    verdict = prober.oracle_runner(OracleMechanism.STRUCTURAL, evidence)
    return CachePoisoningResult(confirmed=verdict.is_violation, evidence_ref=evidence_ref)
