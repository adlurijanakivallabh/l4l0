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

Phase 3, a studied reference agent's own pass: that same reference's own
fetch tool (read in full, not just its comparison-doc summary) streams the
response body and stops reading
once a configurable byte ceiling is hit, rather than reading an unbounded
body into memory. This firer's ``fire()`` had no such cap at all — a large or
adversarial in-engagement target response (a deliberate memory-exhaustion
attempt, or just a large file legitimately being served) would be read to
completion unconditionally. Adopted here as ``max_response_bytes`` (a firer-
wide default, not per-call, since every ``fire()`` caller shares the same
memory-safety concern); a capped response sets ``FireResult.truncated`` so a
cut-off body is never silently mistaken for a complete capture — evidence
grounding and reporting both need to know the difference.

Phase 4, another studied reference agent's own pass: :func:`probe_reachability`
is informed by that reference's own preflight-check module (read in full), which runs
cheap-to-expensive checks before any pipeline agent executes, including a
target-URL reachability probe with the SAME resolve-once-pin-IP/metadata-
denylist hardening this module already implements for real traffic — reusing
:class:`HttpFirer` here means the probe gets that hardening for free, no
second, unvetted HTTP client to keep in sync. Deliberately NOT adopted as a
hard precondition the way that reference treats it: its own scans are always
plain-HTTP-reachable web targets by definition, but L4L0's own engagements
cover network/infra and raw-TCP services too (per this project's own stated
scope), where an HTTP HEAD probe reporting "unreachable" would be a false
alarm, not a real misconfiguration. This stays advisory — surfaced to the
operator, never used to abort a scan whose actual target may simply not
speak HTTP at all.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from ..core.logging import get_logger
from .scope import ScopeGuard
from .target import Engagement

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
    # True when `body` was cut off at max_response_bytes -- a real, complete
    # response is never silently indistinguishable from a truncated one.
    truncated: bool = False


_DEFAULT_MAX_RESPONSE_BYTES = 10_485_760  # 10 MiB


@dataclass
class _Breaker:
    """A per-host circuit breaker with a real open -> half-open -> closed cycle.

    Nothing reset ``is_open`` before this: once tripped, a host was refused
    for the rest of the ``HttpFirer`` instance's lifetime regardless of
    whether it recovered seconds later. ``should_probe`` allows exactly one
    request through once ``reset_after_s`` has elapsed since the trip — a
    success closes the breaker, a failure re-arms the cooldown.
    """

    threshold: int = 5
    reset_after_s: float = 30.0
    failures: int = 0
    is_open: bool = False
    opened_at: float = 0.0

    def should_probe(self) -> bool:
        return (time.monotonic() - self.opened_at) >= self.reset_after_s


def _pinned_url_and_host_header(url: str, pinned_ip: str) -> tuple[str, str]:
    """Rewrite ``url`` to dial ``pinned_ip`` literally.

    Returns ``(pinned_url, original_host_header)``.
    """
    parts = urlsplit(url)
    original_host = parts.hostname or ""
    if original_host.lower() == pinned_ip.lower():
        # Already a literal IP -- still round-trip through urlunsplit rather
        # than returning the raw url string verbatim: urlsplit/urlunsplit
        # strips embedded control characters (CPython's own bpo-43882
        # mitigation), which the FQDN branch below gets for free but a
        # verbatim passthrough here would not, letting a target-influenced
        # newline/CR reach httpx unchecked and raise an uncaught InvalidURL.
        pinned = urlunsplit(
            (parts.scheme, parts.netloc, parts.path or "/", parts.query, parts.fragment)
        )
        return pinned, parts.netloc
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
        breaker_reset_after_s: float = 30.0,
        max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self.scope = scope
        self._client = client or httpx.Client(http2=True, timeout=20.0, follow_redirects=False)
        self._breaker_threshold = breaker_threshold
        self._breaker_reset_after_s = breaker_reset_after_s
        self._max_response_bytes = max_response_bytes
        self._breakers: dict[str, _Breaker] = {}
        # Guards ONLY the breaker-state check/update below (never the network
        # I/O in fire()) - fire_concurrent fires up to 50 requests to the same
        # host through one shared HttpFirer instance at once, and spawn_agents
        # does the same for the whole firer across concurrent agents, so the
        # pre-request is_open/should_probe check and the post-request
        # failures/is_open/opened_at mutation are each an unlocked
        # read-modify-write that concurrent callers can race on, corrupting
        # the failure count or tripping the breaker inconsistently. Locking
        # the whole fire() call instead would serialize every concurrent
        # request and defeat fire_concurrent's entire purpose (simultaneity
        # for race-condition testing) - same coarse-lock pattern already used
        # for Budget/Tracer/access_control_matrix's shared state.
        self._breaker_lock = threading.Lock()

    def _breaker(self, host: str) -> _Breaker:
        with self._breaker_lock:
            return self._breakers.setdefault(
                host,
                _Breaker(
                    threshold=self._breaker_threshold, reset_after_s=self._breaker_reset_after_s
                ),
            )

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
        with self._breaker_lock:
            if breaker.is_open and not breaker.should_probe():
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
            # Streamed, not `send(request)` -- a naive full-body read has no
            # ceiling at all, so an adversarial or just-large in-engagement
            # response can exhaust memory. Read is capped at
            # max_response_bytes; anything beyond that is never pulled off
            # the wire, not just discarded after the fact.
            resp = self._client.send(request, stream=True)
            try:
                chunks: list[bytes] = []
                received = 0
                truncated = False
                for chunk in resp.iter_bytes():
                    chunks.append(chunk)
                    received += len(chunk)
                    if received >= self._max_response_bytes:
                        truncated = True
                        break
                # A single chunk (e.g. a mocked transport, or just a generous
                # read-buffer size) can overshoot the cap on its own -- stopping
                # further reads isn't enough; the joined result must be sliced
                # too, or `truncated=True` would be paired with a body that's
                # actually larger than max_response_bytes.
                body = b"".join(chunks)[: self._max_response_bytes]
            finally:
                resp.close()
        except httpx.InvalidURL as exc:
            # Raised by build_request() itself, before any network I/O --
            # httpx.InvalidURL is NOT a subclass of httpx.HTTPError, so this
            # needs its own clause or it propagates and crashes the caller. No
            # bytes were ever sent, so fired=False (unlike the HTTPError branch
            # below, where send() genuinely attempted the request).
            return FireResult(
                method=method,
                url=url,
                fired=False,
                scope_reason=decision.reason,
                error=type(exc).__name__,
                elapsed_ms=(time.monotonic() - start) * 1000.0,
            )
        except httpx.HTTPError as exc:
            with self._breaker_lock:
                breaker.failures += 1
                if breaker.failures >= breaker.threshold:
                    breaker.is_open = True
                    # (re)arm the cooldown on every trip/re-trip
                    breaker.opened_at = time.monotonic()
                    _log.warning(
                        "circuit opened for host %s after %d failures", host, breaker.failures
                    )
            return FireResult(
                method=method,
                url=url,
                fired=True,
                scope_reason=decision.reason,
                error=type(exc).__name__,
                elapsed_ms=(time.monotonic() - start) * 1000.0,
            )
        else:
            with self._breaker_lock:
                breaker.failures = 0
                breaker.is_open = False  # a successful request (a half-open probe too) closes it
            return FireResult(
                method=method,
                url=url,
                fired=True,
                scope_reason=decision.reason,
                truncated=truncated,
                status=resp.status_code,
                headers=dict(resp.headers),
                body=body,
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


_GLOB_CHARS = frozenset("*?[")


def probe_reachability(engagement: Engagement, firer: HttpFirer) -> dict[str, tuple[bool, str]]:
    """Best-effort HEAD-request reachability probe for every CONCRETE
    (non-glob) host declared in ``engagement``, via ``firer`` — so the probe
    gets the exact same scope/pin/metadata hardening real traffic gets, not a
    second, separately-maintained HTTP client. A ``*.example.com``-style rule
    has no single host to probe and is skipped.

    Returns ``{host: (reachable, reason)}``. Advisory only — see the module
    docstring's Phase 4 reference-pass note for why an "unreachable" result is
    never treated as fatal: an in-engagement network/infra or raw-TCP target
    may simply not speak HTTP at all, which isn't a misconfiguration.
    """
    results: dict[str, tuple[bool, str]] = {}
    for rule in engagement.rules:
        if rule.host in results or any(char in rule.host for char in _GLOB_CHARS):
            continue
        scheme = next(iter(rule.schemes)) if rule.schemes else "https"
        port = next(iter(rule.ports)) if rule.ports else None
        netloc = rule.host if port is None else f"{rule.host}:{port}"
        result = firer.fire("HEAD", f"{scheme}://{netloc}/")
        # `fired` alone isn't "got a response" -- it's also True for a
        # transport-level failure (e.g. ConnectError) that never produced a
        # status code, so `status is not None` is the only reliable signal
        # that something on the other end actually answered.
        if result.status is not None:
            results[rule.host] = (True, f"responded {result.status}")
            continue
        if scheme == "https" and not rule.schemes:
            # The operator didn't restrict this rule to https specifically --
            # try http once before reporting unreachable (a plain-http-only
            # internal service is a routine, legitimate shape).
            fallback = firer.fire("HEAD", f"http://{netloc}/")
            if fallback.status is not None:
                results[rule.host] = (True, f"responded {fallback.status} (http)")
                continue
            results[rule.host] = (False, fallback.error or fallback.scope_reason)
            continue
        results[rule.host] = (False, result.error or result.scope_reason)
    return results
