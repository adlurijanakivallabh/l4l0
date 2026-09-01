"""Verbose-error / stack-trace information disclosure (§7, Build Order 0).

A response body containing a framework's own default stack-trace or debug
page proves the app leaked implementation detail (server/framework version,
internal file paths, code structure) to an unauthenticated caller — the
testfire benchmark's own example: an Apache Tomcat JSP exception page
revealing ``Apache Tomcat/7.0.92`` in an HTTP 500 body. This module holds a
small, fixed marker table (same disclosed-limit shape as
``subdomain_takeover.detector.FINGERPRINTS`` — a handful of well-known
frameworks, not every possible stack trace) plus a single sentinel-in-body
check.

Maps onto the existing STRUCTURAL oracle family unchanged (§7,
``StructuralCheckType.INFO_DISCLOSURE``) — no new mechanism. Every oracle
call goes through the Validator's ``run_oracle`` (CLAUDE.md non-negotiable);
this module never mints a verdict itself.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from reachagent.detection.oracle_gateway import OracleRunner, registry_runner
from reachagent.oracles import OracleMechanism
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence

# Known framework/language stack-trace or debug-page markers. Deliberately
# narrow and specific to actual error/debug output — never a routine banner
# (e.g. a footer reading "Powered by X") — to keep the false-positive rate at
# zero: each string below only appears on that framework's own generated
# error page, never on a normal successful response. Disclosed limit, same
# as subdomain_takeover's ~8-service table: a framework outside this list, or
# one that changed its default error-page text, is undetected.
MARKERS: tuple[str, ...] = (
    "org.apache.jasper.JasperException",  # Java/JSP (the testfire example)
    "Whitelabel Error Page",  # Spring Boot default error page
    "Fatal error: Uncaught",  # PHP uncaught-exception page
    "Traceback (most recent call last):",  # Python unhandled-exception page
    "System.Web.HttpException",  # ASP.NET (.NET Framework)
    "A PHP Error was encountered",  # CodeIgniter debug page
    "You're seeing this error because you have DEBUG = True",  # Django
    "Apache Tomcat/",  # Tomcat's own default error-page footer
)


def match_marker(response_body: str) -> str | None:
    """Return the first known disclosure marker present in ``response_body``, if any."""
    for marker in MARKERS:
        if marker in response_body:
            return marker
    return None


@dataclass(frozen=True)
class InfoDisclosureProbe:
    """One read-only probe's outcome."""

    status: int
    body: str


@dataclass
class InfoDisclosureProber:
    """Injectable probe callback — keeps detection hermetic and ordering testable.

    ``fire_probe``: fire the read-only request and return its status/body.
    ``oracle_runner``: injectable oracle seam; defaults to registry (no validator import).
    """

    fire_probe: Callable[[], InfoDisclosureProbe]
    oracle_runner: OracleRunner = registry_runner


@dataclass(frozen=True)
class InfoDisclosureResult:
    """Outcome of an information-disclosure detection attempt."""

    confirmed: bool
    evidence_ref: str = ""


def detect_info_disclosure(
    prober: InfoDisclosureProber,
    *,
    evidence_ref: str = "",
) -> InfoDisclosureResult:
    """Detect verbose-error/stack-trace disclosure (§7).

    Fires the probe, checks the response body against the fixed marker
    table, and routes a match through the existing STRUCTURAL oracle's
    INFO_DISCLOSURE decision. No marker found → the oracle is still called
    with an empty sentinel so the outcome is always a real verdict
    (INCONCLUSIVE), never a silent skip.
    """
    probe = prober.fire_probe()
    marker = match_marker(probe.body) or ""
    evidence = StructuralEvidence(
        check_type=StructuralCheckType.INFO_DISCLOSURE,
        sentinel=marker,
        probe_status=probe.status,
        response_body=probe.body,
        evidence_ref=evidence_ref,
    )
    verdict = prober.oracle_runner(OracleMechanism.STRUCTURAL, evidence)
    return InfoDisclosureResult(confirmed=verdict.is_violation, evidence_ref=evidence_ref)
