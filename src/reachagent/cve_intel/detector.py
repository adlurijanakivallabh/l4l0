"""Known-vulnerable-version structural check (§7 Build Order 4).

Maps onto the existing STRUCTURAL oracle family unchanged — no new
mechanism, reusing the same sentinel-in-response shape as
``path_traversal``/``subdomain_takeover``/``cloud_bucket_exposure``. The
NVD/EPSS lookup (``cve_intel.nvd_client``) is a deterministic pre-check,
same role as ``default_credentials``'s login attempt or
``cloud_bucket_exposure``'s bucket-name generation: it decides which
candidate is even worth an oracle call. The oracle itself confirms only
one honest structural fact — the exact fingerprinted version string is
genuinely present in the CURRENT live response, not stale graph data from
an earlier recon pass. No status-code gate: unlike a traversal payload, a
version banner is just as real on a 403/404/500 error page as on a 2xx.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from reachagent.cve_intel.nvd_client import CveMatch
from reachagent.detection.oracle_gateway import OracleRunner, registry_runner
from reachagent.oracles import OracleMechanism
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class VersionProbe:
    """One live re-probe's outcome — headers and body both searched, since
    a version banner may live in either (e.g. a ``Server`` header vs an
    error page's rendered footer)."""

    status: int
    haystack: str


@dataclass
class VersionProber:
    """Injectable probe callback — keeps detection hermetic and testable.

    ``fire_probe``: fire one read-only GET against the target and return its
    status/searchable text. ``oracle_runner``: injectable oracle seam;
    defaults to registry (no validator import).
    """

    fire_probe: Callable[[], VersionProbe]
    oracle_runner: OracleRunner = registry_runner


@dataclass(frozen=True)
class KnownVulnerableVersionResult:
    """Outcome of a known-vulnerable-version detection attempt."""

    confirmed: bool
    matches: tuple[CveMatch, ...] = field(default_factory=tuple)
    evidence_ref: str = ""


def detect_known_vulnerable_version(
    prober: VersionProber,
    *,
    version_string: str,
    cve_matches: tuple[CveMatch, ...],
    evidence_ref: str = "",
) -> KnownVulnerableVersionResult:
    """Confirm ``version_string`` is genuinely present in the live response.

    Only called by the driver when ``cve_matches`` is already non-empty —
    a version banner with no known CVEs is informational at most, not
    worth an oracle call (mirrors ``cloud_bucket_exposure``'s
    "generate candidates, ask the oracle only about ones already worth
    it" shape).
    """
    if not version_string or not cve_matches:
        return KnownVulnerableVersionResult(confirmed=False, evidence_ref=evidence_ref)
    try:
        probe = prober.fire_probe()
    except Exception as exc:  # noqa: BLE001 — a refused/errored probe is not a violation
        _log.debug("known-vulnerable-version probe failed: %s", exc)
        return KnownVulnerableVersionResult(confirmed=False, evidence_ref=evidence_ref)
    evidence = StructuralEvidence(
        check_type=StructuralCheckType.KNOWN_VULNERABLE_VERSION,
        probe_status=probe.status,
        sentinel=version_string,
        response_body=probe.haystack,
        evidence_ref=evidence_ref,
    )
    verdict = prober.oracle_runner(OracleMechanism.STRUCTURAL, evidence)
    if verdict.is_violation:
        return KnownVulnerableVersionResult(
            confirmed=True, matches=cve_matches, evidence_ref=evidence_ref
        )
    return KnownVulnerableVersionResult(confirmed=False, evidence_ref=evidence_ref)
