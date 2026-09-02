"""Cloud storage bucket exposure (§7, Build Order 4).

Generates a small, bounded set of plausible bucket names from the target's
own hostname (a naming-convention guess, never a real brute force — see
``BUCKET_NAME_SUFFIXES``) and checks each candidate URL across the
S3/GCS/Azure naming conventions for a provider's own "this is a real,
publicly-listable bucket" body marker. Same sentinel-in-body shape as
``subdomain_takeover.detector`` — the audit that named this class corrected
an earlier framing that treated it as architecturally out of reach: a
bucket-listing check is just an HTTP GET to a guessed hostname plus a
body/status check, no different from the existing structural checks.

Maps onto the existing STRUCTURAL oracle family unchanged (§7,
``StructuralCheckType.CLOUD_BUCKET_EXPOSURE``) — no new mechanism. Every
probe is a read-only GET to a THIRD-PARTY cloud-storage host (S3/GCS/
Azure), never the scanned target itself — the same reasoning that gives
``subdomain_takeover`` its own dedicated transport outside ``RequestFirer``:
the guessed bucket host is, by construction, outside the scanned target's
own ScopeGuard allowlist.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable
from dataclasses import dataclass

from reachagent.detection.oracle_gateway import OracleRunner, registry_runner
from reachagent.oracles import OracleMechanism
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence

_log = logging.getLogger(__name__)

# Small, bounded naming-convention guesses — never exhaustive enumeration.
# Disclosed limit: a bucket named outside this small convention set (or a
# provider outside S3/GCS/Azure) is undetected, same shape as
# subdomain_takeover's ~8-service fingerprint table.
BUCKET_NAME_SUFFIXES: tuple[str, ...] = (
    "",
    "-backup",
    "-backups",
    "-assets",
    "-data",
    "-files",
    "-uploads",
    "-static",
    "-media",
    "-dev",
)

# S3 and GCS's XML API both use the same S3-compatible listing response
# shape; Azure Blob containers use a distinct XML shape.
_S3_STYLE_MARKER = "<ListBucketResult"
_AZURE_MARKER = "<EnumerationResults"

# (URL template, exposure marker). {name} is substituted per candidate.
_PROVIDER_TEMPLATES: tuple[tuple[str, str], ...] = (
    ("https://{name}.s3.amazonaws.com/", _S3_STYLE_MARKER),
    ("https://{name}.storage.googleapis.com/", _S3_STYLE_MARKER),
    ("https://{name}.blob.core.windows.net/{name}?restype=container&comp=list", _AZURE_MARKER),
)


def derive_seed_names(hostname: str) -> tuple[str, ...]:
    """Bounded naming seeds from a hostname — the labels most likely reused as a bucket name.

    For ``demo.testfire.net`` this yields ``("testfire", "demo")``: the
    registrable-domain label (most common real-world bucket-naming choice)
    and the leading subdomain label, deduplicated and lowercased.

    A bare IP address (``127.0.0.1``, a common local-eval-target hostname)
    yields no seeds at all: its dotted octets aren't an organization name a
    real bucket would ever be named after, and guessing short numeric names
    like ``"127"``/``"0"`` risks hitting a real, unrelated, coincidentally-
    public bucket somewhere on S3/GCS/Azure — reported as a "high severity"
    finding against a target it has nothing to do with. Caught live: VAmPI
    (target ``127.0.0.1``) confirmed a cloud_bucket_exposure finding despite
    having no cloud-storage component in its own documented vulnerabilities.

    A ``host:port`` hostname (crAPI's own ``127.0.0.1:8888``, e.g.) is
    stripped to its host part first — ``ipaddress.ip_address`` raises on a
    string carrying a port, which silently defeated the IP guard above for
    any target whose Host fact happens to include one (caught live: the very
    next run still produced the same false positive with the port attached).
    Only a single, unambiguous ``:port`` suffix is stripped (a bare IPv6
    address has multiple colons and is left untouched) — a bracketed
    ``[::1]:port`` literal has its brackets stripped too.
    """
    unbracketed = hostname[1:].split("]", 1)[0] if hostname.startswith("[") else hostname
    if unbracketed.count(":") == 1:
        unbracketed = unbracketed.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(unbracketed)
    except ValueError:
        pass
    else:
        return ()
    labels = [label for label in unbracketed.lower().split(".") if label]
    seeds: list[str] = []
    if len(labels) >= 2:
        seeds.append(labels[-2])
    if labels and labels[0] not in seeds:
        seeds.append(labels[0])
    return tuple(dict.fromkeys(seeds))


def candidate_bucket_probes(hostname: str) -> tuple[tuple[str, str], ...]:
    """Bounded (probe_url, exposure_marker) pairs generated from ``hostname``.

    Every valid bucket-name character set is respected (S3/GCS/Azure all
    require lowercase alphanumeric + hyphen); a seed containing anything
    else is skipped rather than producing a malformed probe URL.
    """
    probes: list[tuple[str, str]] = []
    for seed in derive_seed_names(hostname):
        if not seed.replace("-", "").isalnum():
            continue
        for suffix in BUCKET_NAME_SUFFIXES:
            name = f"{seed}{suffix}"
            for template, marker in _PROVIDER_TEMPLATES:
                probes.append((template.format(name=name), marker))
    return tuple(probes)


@dataclass(frozen=True)
class BucketProbe:
    """One read-only probe's outcome."""

    status: int
    body: str


@dataclass
class BucketProber:
    """Injectable probe callback — keeps detection hermetic and ordering testable.

    ``fire_probe``: fire the read-only GET against one candidate bucket URL
    and return its status/body. ``oracle_runner``: injectable oracle seam;
    defaults to registry (no validator import).
    """

    fire_probe: Callable[[str], BucketProbe]
    oracle_runner: OracleRunner = registry_runner


@dataclass(frozen=True)
class BucketExposureResult:
    """Outcome of a cloud-bucket-exposure detection attempt."""

    confirmed: bool
    exposed_url: str = ""
    evidence_ref: str = ""


def detect_cloud_bucket_exposure(
    prober: BucketProber,
    *,
    probes: tuple[tuple[str, str], ...],
    evidence_ref: str = "",
) -> BucketExposureResult:
    """Try each candidate bucket URL; stop at the first confirmed exposure.

    Every candidate is independently reconfirmed through the STRUCTURAL
    oracle's CLOUD_BUCKET_EXPOSURE decision — the marker match here only
    selects a candidate worth asking the oracle about, exactly like
    subdomain_takeover's fingerprint match gates its own probe.
    """
    for url, marker in probes:
        try:
            probe = prober.fire_probe(url)
        except Exception as exc:  # noqa: BLE001 — one candidate's transport failure skips it
            _log.debug("cloud bucket probe failed for %s: %s", url, exc)
            continue
        evidence = StructuralEvidence(
            check_type=StructuralCheckType.CLOUD_BUCKET_EXPOSURE,
            probe_status=probe.status,
            sentinel=marker,
            response_body=probe.body,
            evidence_ref=evidence_ref,
        )
        verdict = prober.oracle_runner(OracleMechanism.STRUCTURAL, evidence)
        if verdict.is_violation:
            return BucketExposureResult(confirmed=True, exposed_url=url, evidence_ref=evidence_ref)
    return BucketExposureResult(confirmed=False, evidence_ref=evidence_ref)
