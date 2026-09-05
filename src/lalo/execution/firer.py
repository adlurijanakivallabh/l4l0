"""HTTP(S) firer — HTTP/1.1 + HTTP/2 via httpx, scope-checked, with full capture
and a per-host transport circuit breaker.

Redirects are NOT auto-followed (``follow_redirects=False``) so a caller can
re-check scope on each hop before continuing a chain. WebSocket / gRPC / HTTP-3
are added when their phases need them; this covers the HTTP surface.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

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


class HttpFirer:
    """Fires scope-checked HTTP requests and captures full responses."""

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

        host = urlsplit(url).hostname or ""
        breaker = self._breaker(host)
        if breaker.is_open:
            return FireResult(method=method, url=url, fired=False, scope_reason="circuit_open")

        start = time.monotonic()
        try:
            resp = self._client.request(method, url, headers=headers, content=content)
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
        """Follow redirects MANUALLY, re-checking scope on every hop.

        Each hop goes through ``fire`` (hence ``ScopeGuard.check``), so a redirect
        to an out-of-engagement or metadata host is skipped, not followed — the
        defense against redirect-based SSRF/scope escape. Returns the full chain;
        the last entry is the final response (or the refused hop).
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
            current = urljoin(current, location)  # next hop re-checked by fire()
            verb, body = "GET", None  # browsers downgrade to GET on 301/302/303
        return chain

    def close(self) -> None:
        self._client.close()
