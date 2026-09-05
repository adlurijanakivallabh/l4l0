"""HTTP(S) firer — scope-checked AND pinned-IP-dialing, with full capture and a
per-host transport circuit breaker.

The pinned-dial mechanism is read directly from a reference recon tool's actual
SSRF guard: resolve a host once, then literally dial that resolved IP for the
real connection (URL rewritten to the IP, original ``Host`` header preserved,
TLS SNI still validated against the real hostname via httpx's
``sni_hostname`` request extension) — a naive design that checks the hostname
via :meth:`ScopeGuard.check` and then lets httpx independently re-resolve the
same hostname when it actually connects has a real TOCTOU gap between the two
resolutions; this closes it by construction; the scope check and the dial use
the exact same cached resolution.

Redirects are followed manually (:meth:`fire_redirects`), re-checking scope
(and re-pinning) on every hop — the concrete defense against a reference
proxy tool's own gap (a scope filter that only narrows what's *displayed*,
never something that blocks an out-of-scope replay from actually firing).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from ..core.logging import get_logger
from .scope import ScopeGuard

_log = get_logger("lalo.firer")


@dataclass
class FireResult:
    method: str
    url: str
    fired: bool
    scope_reason: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed_ms: float | None = None
    error: str | None = None
    http_version: str | None = None


@dataclass
class _Breaker:
    threshold: int = 5
    failures: int = 0
    is_open: bool = False


def _pinned_url_and_host_header(url: str, pinned_ip: str) -> tuple[str, str]:
    """Rewrite ``url`` to dial ``pinned_ip`` literally.

    Returns ``(pinned_url, original_host_header)``.
    """
    parts = urlsplit(url)
    original_host = parts.hostname or ""
    if original_host.lower() == pinned_ip.lower():
        return url, parts.netloc  # already a literal IP; nothing to rewrite
    ip_for_netloc = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    netloc = f"{ip_for_netloc}:{parts.port}" if parts.port else ip_for_netloc
    pinned = urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, parts.fragment))
    return pinned, parts.netloc


class HttpFirer:
    """Fires scope-checked, pinned-IP-dialed HTTP requests and captures full responses."""

    def __init__(
        self,
        scope: ScopeGuard,
        client: httpx.Client | None = None,
        *,
        breaker_threshold: int = 5,
    ) -> None:
        self.scope = scope
        self._client = client or httpx.Client(http2=True, timeout=20.0, follow_redirects=False)
        self._breaker_threshold = breaker_threshold
        self._breakers: dict[str, _Breaker] = {}

    def _breaker(self, host: str) -> _Breaker:
        return self._breakers.setdefault(host, _Breaker(threshold=self._breaker_threshold))

    def fire(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> FireResult:
        decision = self.scope.check(url)
        if not decision.allowed:
            _log.info("scope %s: %s %s", decision.reason, method, url)
            return FireResult(method=method, url=url, fired=False, scope_reason=decision.reason)

        parts = urlsplit(url)
        host = parts.hostname or ""
        breaker = self._breaker(host)
        if breaker.is_open:
            return FireResult(method=method, url=url, fired=False, scope_reason="circuit_open")

        pinned_ip = self.scope.pin_for_connect(host)
        if pinned_ip is None:
            return FireResult(
                method=method,
                url=url,
                fired=False,
                scope_reason=decision.reason,
                error="dns_resolution_failed",
            )
        pinned_url, host_header = _pinned_url_and_host_header(url, pinned_ip)
        request_headers = dict(headers or {})
        request_headers.setdefault("Host", host_header)

        start = time.monotonic()
        try:
            request = self._client.build_request(
                method, pinned_url, headers=request_headers, content=content
            )
            if parts.scheme == "https" and parts.hostname:
                # Dial the pinned IP, but still validate TLS against the real name.
                request.extensions["sni_hostname"] = parts.hostname
            resp = self._client.send(request)
        except httpx.HTTPError as exc:
            breaker.failures += 1
            if breaker.failures >= breaker.threshold:
                breaker.is_open = True
                _log.warning("circuit opened for host %s after %d failures", host, breaker.failures)
            return FireResult(
                method=method,
                url=url,
                fired=True,
                scope_reason=decision.reason,
                error=type(exc).__name__,
                elapsed_ms=(time.monotonic() - start) * 1000.0,
            )

        breaker.failures = 0
        return FireResult(
            method=method,
            url=url,
            fired=True,
            scope_reason=decision.reason,
            status=resp.status_code,
            headers=dict(resp.headers),
            body=resp.content,
            elapsed_ms=(time.monotonic() - start) * 1000.0,
            http_version=resp.http_version,
        )

    def fire_redirects(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        max_redirects: int = 5,
    ) -> list[FireResult]:
        """Follow redirects MANUALLY, re-checking scope AND re-pinning on every hop.

        Each hop goes through :meth:`fire` (hence scope + pin), so a redirect
        to an out-of-engagement or metadata host is skipped/denied, not
        followed. Returns the full chain; the last entry is the final response
        (or the refused hop).
        """
        chain: list[FireResult] = []
        current, verb, body = url, method, content
        for _ in range(max_redirects + 1):
            result = self.fire(verb, current, headers=headers, content=body)
            chain.append(result)
            if not result.fired or result.status is None or not 300 <= result.status < 400:
                break
            location = result.headers.get("location")
            if not location:
                break
            current = urljoin(current, location)  # next hop re-checked + re-pinned by fire()
            verb, body = "GET", None  # browsers downgrade to GET on 301/302/303
        return chain

    def close(self) -> None:
        self._client.close()
