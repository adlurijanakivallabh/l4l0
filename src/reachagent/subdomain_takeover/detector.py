"""Subdomain takeover — dangling-CNAME detection (plan §7).

A subdomain's CNAME pointing at a third-party service (S3, GitHub Pages,
Heroku, ...) that no longer has anything claiming that name is a takeover
surface: registering the name on the third-party service makes the dangling
subdomain serve attacker content. The recon tier (``dnsx``) already asserts
the CNAME as a ``Host`` fact (§9); this module only needs a small fingerprint
table of known "unclaimed service" body markers plus a single read-only GET
to the CNAME target.

Maps onto the existing STRUCTURAL oracle family unchanged (§7,
``StructuralCheckType.SUBDOMAIN_TAKEOVER``) — no new mechanism. Every oracle
call goes through the Validator's ``run_oracle`` (CLAUDE.md non-negotiable);
this module never mints a verdict itself.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from reachagent.detection.oracle_gateway import OracleRunner, registry_runner
from reachagent.oracles import OracleMechanism
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence

# (CNAME target suffix, unclaimed-service body marker). Suffix match is
# case-insensitive and anchors on the end of the CNAME target, since these
# are third-party service domains a discovered subdomain points *at*.
FINGERPRINTS: tuple[tuple[str, str], ...] = (
    (".s3.amazonaws.com", "The specified bucket does not exist"),
    (".github.io", "There isn't a GitHub Pages site here"),
    (".herokuapp.com", "No such app"),
    (".azurewebsites.net", "404 Web Site not found"),
    (".readthedocs.io", "unknown to Read the Docs"),
    (".surge.sh", "project not found"),
    (".fastly.net", "Fastly error: unknown domain"),
    (".ghost.io", "The thing you were looking for is no longer here"),
)


def match_fingerprint(cname: str) -> str | None:
    """Return the known unclaimed-service marker for a CNAME target, if any."""
    target = cname.lower()
    for suffix, sentinel in FINGERPRINTS:
        if target.endswith(suffix):
            return sentinel
    return None


@dataclass(frozen=True)
class SubdomainTakeoverProbe:
    """One read-only GET's outcome against a CNAME target."""

    status: int
    body: str


@dataclass
class SubdomainTakeoverProber:
    """Injectable probe callback — keeps detection hermetic and ordering testable.

    ``fire_probe``: fire the single read-only GET against the CNAME target and
    return its status/body. ``oracle_runner``: injectable oracle seam; defaults
    to registry (no validator import).
    """

    fire_probe: Callable[[], SubdomainTakeoverProbe]
    oracle_runner: OracleRunner = registry_runner


@dataclass(frozen=True)
class SubdomainTakeoverResult:
    """Outcome of a subdomain-takeover detection attempt."""

    confirmed: bool
    evidence_ref: str = ""


def detect_subdomain_takeover(
    prober: SubdomainTakeoverProber,
    *,
    sentinel: str,
    evidence_ref: str = "",
) -> SubdomainTakeoverResult:
    """Detect a dangling-CNAME takeover (§7).

    Fires the single probe and routes it through the existing STRUCTURAL
    oracle's SUBDOMAIN_TAKEOVER decision — a 2xx response containing the
    service's own "unclaimed" marker is the only confirming shape.
    """
    probe = prober.fire_probe()
    evidence = StructuralEvidence(
        check_type=StructuralCheckType.SUBDOMAIN_TAKEOVER,
        probe_status=probe.status,
        sentinel=sentinel,
        response_body=probe.body,
        evidence_ref=evidence_ref,
    )
    verdict = prober.oracle_runner(OracleMechanism.STRUCTURAL, evidence)
    return SubdomainTakeoverResult(confirmed=verdict.is_violation, evidence_ref=evidence_ref)
