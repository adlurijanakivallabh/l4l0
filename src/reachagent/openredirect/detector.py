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

Optional technique-diversity corroboration (v3 V3): when the endpoint has a
SECOND, genuinely different redirect-shaped parameter, ``fire_second_probe``
lets the caller wire it in — a confirmed first probe is only trusted once a
second, independent parameter on the SAME endpoint also reflects the
attacker URL, ruling out one parameter's own quirk (e.g. a coincidental
substring match) rather than a systemic unsanitized-redirect issue. Optional
and additive: when omitted (the default), behavior is byte-for-byte
unchanged from before this was added.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from reachagent.confirmation.corroboration import corroborate_with_variant
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
    ``fire_second_probe``/``second_param_name`` (v3 V3, optional): a SECOND
    redirect-shaped parameter on the same endpoint, fired only if the first
    probe already confirmed — see module docstring.
    """

    fire_probe: Callable[[], RedirectProbe]
    probe_target: str
    oracle_runner: OracleRunner = registry_runner
    fire_second_probe: Callable[[], RedirectProbe] | None = None
    second_param_name: str = ""


@dataclass(frozen=True)
class OpenRedirectResult:
    """Outcome of an open-redirect detection attempt."""

    confirmed: bool
    evidence_ref: str = ""
    corroborated: bool = False


def detect_open_redirect(
    prober: OpenRedirectProber,
    *,
    evidence_ref: str = "",
) -> OpenRedirectResult:
    """Detect an open redirect — attacker URL echoed into ``Location`` (§7).

    Fires the read-only probe and routes the status/Location through the
    STRUCTURAL oracle's OPEN_REDIRECT branch. When ``prober.fire_second_probe``
    is set, a confirmed first probe is corroborated against a second,
    different parameter before being trusted (v3 V3) — a contradicted
    corroboration fails closed to not-confirmed, never falls back to the
    uncorroborated first result.
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
    if prober.fire_second_probe is None:
        return OpenRedirectResult(confirmed=verdict.is_violation, evidence_ref=evidence_ref)

    def _second_attempt() -> object:
        second_probe = prober.fire_second_probe()  # type: ignore[misc]
        second_evidence = StructuralEvidence(
            check_type=StructuralCheckType.OPEN_REDIRECT,
            probe_status=second_probe.status,
            location=second_probe.location,
            sentinel=prober.probe_target,
            evidence_ref=evidence_ref,
        )
        return prober.oracle_runner(OracleMechanism.STRUCTURAL, second_evidence)

    result = corroborate_with_variant(verdict, _second_attempt)
    return OpenRedirectResult(
        confirmed=result.corroborated, evidence_ref=evidence_ref, corroborated=result.corroborated
    )
