"""Live NVD (+ EPSS) CVE intelligence (§7 Build Order 4, reference-agent audit refinement).

Enriches an already-fingerprinted ``Host.technology``/``detected_version``
(a live, black-box, network-observable recon fact — no source access
needed) with known-CVE data from NVD's public CVE API, and an EPSS
exploitation-likelihood score from FIRST.org for any CVE found. This is
threat-intelligence *enrichment* of a deterministic fact, not a scanner
import (CLAUDE.md §9): the STRUCTURAL oracle (``cve_intel/detector.py``)
still does the only thing that decides a Finding — confirming the version
string is genuinely present in the LIVE response, not stale graph data.

A reference-agent audit named the concrete failure mode this module is
built to avoid: no rate limiting/backoff/caching, degrading under real
load and risking an IP ban from the upstream API. Both NVD (~5 req/30s
without an API key) and FIRST.org get their own small sliding-window
limiter; either budget being exhausted fails OPEN (skip enrichment for
this lookup, never sleep/stall the scan) rather than blocking.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Protocol

import httpx

_log = logging.getLogger(__name__)

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_EPSS_URL = "https://api.first.org/data/v1/epss"
_TIMEOUT = 5.0
_MAX_RETRIES = 2
_BACKOFF: tuple[float, ...] = (1.0, 3.0)
_RETRY_STATUSES = frozenset({403, 429, 500, 502, 503, 504})
_MAX_MATCHES = 5
_MAX_TEXT = 300
_CACHE_TTL_SECONDS = 3_600.0  # a fingerprinted version doesn't change mid-scan


@dataclass(frozen=True)
class CveMatch:
    """One known-CVE correlation for a fingerprinted product/version."""

    cve_id: str
    cvss_score: float | None
    severity: str
    summary: str
    epss_score: float | None = None


class HttpClient(Protocol):
    """Thin swappable HTTP boundary — real client is httpx, tests inject a fake."""

    def get(self, url: str, *, params: dict[str, str]) -> httpx.Response: ...


class HttpxNvdClient:
    """Default HTTP boundary: a short-timeout httpx.Client per call."""

    def get(self, url: str, *, params: dict[str, str]) -> httpx.Response:
        with httpx.Client(timeout=_TIMEOUT) as client:
            return client.get(url, params=params)


class _RateLimiter:
    """Sliding-window request cap. Never blocks — ``allow()`` just reports
    whether a call fits the budget right now, so a caller can fail open
    instead of stalling the scan waiting out the window."""

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._timestamps: deque[float] = deque()

    def allow(self) -> bool:
        now = time.monotonic()
        while self._timestamps and now - self._timestamps[0] > self._window_seconds:
            self._timestamps.popleft()
        if len(self._timestamps) >= self._max_requests:
            return False
        self._timestamps.append(now)
        return True


_nvd_limiter = _RateLimiter(max_requests=5, window_seconds=30.0)
_epss_limiter = _RateLimiter(max_requests=10, window_seconds=30.0)
_nvd_cache: dict[str, tuple[float, list[CveMatch]]] = {}
_epss_cache: dict[str, tuple[float, float | None]] = {}


def _get_with_retry(client: HttpClient, url: str, params: dict[str, str]) -> httpx.Response | None:
    for attempt in range(_MAX_RETRIES + 1):
        try:
            response = client.get(url, params=params)
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            if attempt < _MAX_RETRIES:
                time.sleep(_BACKOFF[attempt])
                continue
            _log.debug("cve intel request failed (%s): %s", url, exc)
            return None
        if response.status_code in _RETRY_STATUSES and attempt < _MAX_RETRIES:
            time.sleep(_BACKOFF[attempt])
            continue
        return response
    return None  # pragma: no cover — loop always returns above


def _cvss_from_metrics(metrics: dict[str, object]) -> tuple[float | None, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if isinstance(entries, list) and entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = str(entries[0].get("baseSeverity") or data.get("baseSeverity") or "").lower()
            if isinstance(score, (int, float)):
                return float(score), severity
    return None, ""


def lookup_cves(product: str, version: str, *, client: HttpClient | None = None) -> list[CveMatch]:
    """Known CVEs for a fingerprinted product/version. Fails open to ``[]``
    on any network error, malformed response, disabled/rate-limited lookup,
    or blank input — this must never break or stall a scan."""
    product = product.strip()
    version = version.strip()
    if not product or not version:
        return []
    cache_key = f"{product.lower()}:{version}"
    cached = _nvd_cache.get(cache_key)
    if cached is not None and time.monotonic() - cached[0] < _CACHE_TTL_SECONDS:
        return list(cached[1])
    if not _nvd_limiter.allow():
        _log.debug("NVD lookup skipped (rate-limit budget exhausted): %s", cache_key)
        return []
    http = client or HttpxNvdClient()
    try:
        response = _get_with_retry(
            http, _NVD_URL, {"keywordSearch": f"{product} {version}", "resultsPerPage": "10"}
        )
        if response is None or response.status_code != 200:
            return []
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        matches: list[CveMatch] = []
        for item in vulnerabilities[:_MAX_MATCHES]:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not isinstance(cve_id, str) or not cve_id:
                continue
            score, severity = _cvss_from_metrics(cve.get("metrics", {}))
            descriptions = cve.get("descriptions", [])
            summary = ""
            for entry in descriptions:
                if entry.get("lang") == "en":
                    summary = str(entry.get("value", ""))[:_MAX_TEXT]
                    break
            matches.append(
                CveMatch(cve_id=cve_id, cvss_score=score, severity=severity, summary=summary)
            )
    except Exception as exc:  # noqa: BLE001 — CVE enrichment is best-effort, never required
        _log.debug("NVD lookup failed for %s: %s", cache_key, exc)
        return []
    _nvd_cache[cache_key] = (time.monotonic(), matches)
    return list(matches)


def lookup_epss(cve_id: str, *, client: HttpClient | None = None) -> float | None:
    """EPSS exploitation-likelihood score (0.0-1.0) for a CVE, or ``None``
    if unavailable — fails open the same way ``lookup_cves`` does."""
    cve_id = cve_id.strip().upper()
    if not cve_id:
        return None
    cached = _epss_cache.get(cve_id)
    if cached is not None and time.monotonic() - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]
    if not _epss_limiter.allow():
        _log.debug("EPSS lookup skipped (rate-limit budget exhausted): %s", cve_id)
        return None
    http = client or HttpxNvdClient()
    try:
        response = _get_with_retry(http, _EPSS_URL, {"cve": cve_id})
        if response is None or response.status_code != 200:
            return None
        rows = response.json().get("data", [])
        score = float(rows[0]["epss"]) if rows else None
    except Exception as exc:  # noqa: BLE001 — EPSS enrichment is best-effort, never required
        _log.debug("EPSS lookup failed for %s: %s", cve_id, exc)
        return None
    _epss_cache[cve_id] = (time.monotonic(), score)
    return score


def enrich_with_epss(
    matches: list[CveMatch], *, client: HttpClient | None = None
) -> list[CveMatch]:
    """Attach an EPSS score to each match, in place of returning bare CVEs."""
    return [
        CveMatch(
            cve_id=match.cve_id,
            cvss_score=match.cvss_score,
            severity=match.severity,
            summary=match.summary,
            epss_score=lookup_epss(match.cve_id, client=client),
        )
        for match in matches
    ]
