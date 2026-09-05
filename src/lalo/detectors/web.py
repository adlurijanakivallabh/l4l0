"""Web vulnerability detectors — pure functions over captured data.

Each returns typed Evidence (or None). ``fire_ref`` lets the confidence scorer
verify the ``observed`` text against the real captured response.
"""

from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import urlsplit

from ..confirmation.diff import semantic_diff
from ..models import Evidence, EvidenceKind
from .signatures import (
    ARITHMETIC,
    ID_OUTPUT,
    METADATA_MARKERS,
    NOSQL_ERRORS,
    PASSWD_MARKER,
    SQL_ERRORS,
)


def sqli_error(body: str, *, fire_ref: str | None = None) -> Evidence | None:
    lowered = body.lower()
    for fragment in SQL_ERRORS:
        if fragment in lowered:
            idx = lowered.find(fragment)
            snippet = body[idx : idx + len(fragment)]
            return Evidence(
                kind=EvidenceKind.STRUCTURAL,
                summary="database error signature in response",
                fire_ref=fire_ref,
                observed=snippet,
                metadata={"signature": fragment, "diff_magnitude": 0.7},
            )
    return None


def sqli_time(
    elapsed_ms: float,
    baseline_ms: float,
    *,
    threshold_ms: float = 4000.0,
    fire_ref: str | None = None,
) -> Evidence | None:
    if elapsed_ms - baseline_ms >= threshold_ms:
        return Evidence(
            kind=EvidenceKind.TIMING,
            summary=f"time-based delay: {elapsed_ms:.0f}ms vs baseline {baseline_ms:.0f}ms",
            fire_ref=fire_ref,
            metadata={"elapsed_ms": elapsed_ms, "baseline_ms": baseline_ms},
        )
    return None


def sqli_boolean(
    true_body: str, false_body: str, *, min_divergence: float = 0.15, fire_ref: str | None = None
) -> Evidence | None:
    diff = semantic_diff(false_body, true_body)
    if diff.magnitude >= min_divergence:
        return Evidence(
            kind=EvidenceKind.DIFFERENTIAL,
            summary="boolean-based divergence between true/false conditions",
            fire_ref=fire_ref,
            metadata={"diff_magnitude": diff.magnitude},
        )
    return None


def xss_reflection(
    payload: str, body: str, *, content_type: str = "text/html", fire_ref: str | None = None
) -> Evidence | None:
    if "html" in content_type.lower() and payload and payload in body:
        return Evidence(
            kind=EvidenceKind.STRUCTURAL,
            summary="payload reflected unencoded in an HTML response",
            fire_ref=fire_ref,
            observed=payload,
            metadata={"content_type": content_type, "diff_magnitude": 0.6},
        )
    return None


def path_traversal_read(body: str, *, fire_ref: str | None = None) -> Evidence | None:
    match = PASSWD_MARKER.search(body)
    if match:
        return Evidence(
            kind=EvidenceKind.EXECUTION,
            summary="sensitive file content (/etc/passwd) returned",
            fire_ref=fire_ref,
            observed=match.group(0),
            metadata={"diff_magnitude": 0.9, "succeeded": True},
        )
    return None


def nosqli_error(body: str, *, fire_ref: str | None = None) -> Evidence | None:
    lowered = body.lower()
    for fragment in NOSQL_ERRORS:
        if fragment in lowered:
            return Evidence(
                kind=EvidenceKind.STRUCTURAL,
                summary="NoSQL error/operator signature in response",
                fire_ref=fire_ref,
                observed=fragment,
                metadata={"signature": fragment, "diff_magnitude": 0.6},
            )
    return None


def ssrf_metadata(body: str, *, fire_ref: str | None = None) -> Evidence | None:
    """In-band SSRF: the response contains cloud-metadata content (IMDS reached)."""
    lowered = body.lower()
    hits = [m for m in METADATA_MARKERS if m in lowered]
    if hits:
        return Evidence(
            kind=EvidenceKind.EXECUTION,
            summary="cloud-metadata content returned via SSRF",
            fire_ref=fire_ref,
            observed=hits[0],
            metadata={"markers": hits, "diff_magnitude": 0.95, "succeeded": True},
        )
    return None


def cmdi_output(body: str, *, fire_ref: str | None = None) -> Evidence | None:
    match = ID_OUTPUT.search(body)
    if match:
        return Evidence(
            kind=EvidenceKind.EXECUTION,
            summary="command output (id) in response — RCE proven",
            fire_ref=fire_ref,
            observed=match.group(0),
            metadata={"diff_magnitude": 1.0, "succeeded": True},
        )
    return None


def ssti_eval(payload: str, body: str, *, fire_ref: str | None = None) -> Evidence | None:
    match = ARITHMETIC.search(payload)
    if not match:
        return None
    product = str(int(match.group(1)) * int(match.group(2)))
    if match.group(0).replace(" ", "") not in body and product in body:
        return Evidence(
            kind=EvidenceKind.EXECUTION,
            summary=f"template expression evaluated ({match.group(0)} -> {product})",
            fire_ref=fire_ref,
            observed=product,
            metadata={"diff_magnitude": 0.9, "succeeded": True},
        )
    return None


def open_redirect(location: str, payload: str, *, fire_ref: str | None = None) -> Evidence | None:
    if not location:
        return None
    host = urlsplit(location).hostname or ""
    tainted = payload.lower().strip("/")
    # An open redirect requires the Location to carry an external host that the
    # payload controls; a relative Location (no host) is not a redirect finding.
    if host and (host in payload.lower() or (tainted and tainted in location.lower())):
        return Evidence(
            kind=EvidenceKind.STRUCTURAL,
            summary="redirect Location points at attacker-controlled destination",
            fire_ref=fire_ref,
            observed=location,
            metadata={"diff_magnitude": 0.7},
        )
    return None


def oob_interaction(
    interactions: Sequence[object], *, summary: str = "out-of-band interaction received"
) -> Evidence | None:
    if interactions:
        return Evidence(
            kind=EvidenceKind.OOB_CALLBACK,
            summary=summary,
            metadata={"count": len(interactions), "diff_magnitude": 1.0, "succeeded": True},
        )
    return None
