"""Request firer (plan §10, §12).

Executes requests via HTTPX (Playwright MCP / Burp-or-Caido MCP proxy back the
same tool later, §13) and enforces the §10 safety controls at call time, before
any packet leaves the process:

  * **scope** — every request is checked against the :class:`ScopeGuard`
    allowlist; out-of-scope targets raise before any I/O (§10).
  * **read-only-first** — a state-changing request (POST/PUT/PATCH/DELETE, or a
    GET the caller flags as mutating) does not fire until the read-only case for
    that endpoint has been confirmed safe (§10).
  * **audit** — every attempt, whether fired, refused, or errored, is recorded
    (§10).

Backs the Explorer's ``fire_request`` tool (§13).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass

import httpx

from reachagent.execution.audit import AuditLog
from reachagent.execution.scope import OutOfScopeError, ScopeGuard

# Methods that cannot change server state. Anything outside this set is treated
# as state-changing and gated behind read-only-first (§10).
_READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Transient-retry policy (D5): read-only requests are retried up to _RETRY_LIMIT
# times on a transient server error or a transport error, with this backoff
# (seconds) between attempts. Only 502/503/504 (Bad Gateway / Service
# Unavailable / Gateway Timeout — proxy/overload, transient by design) count as
# retryable; a plain 500 is an application-level *response* that carries meaning
# (e.g. the SQL-error fingerprint canary or an oracle baseline), so it is
# returned immediately — retrying it would triple probe traffic and distort
# fingerprint/oracle semantics. A state-changing request is NEVER retried — a
# retried mutation could double-apply a side effect (§10). Total retry budget is
# bounded (~1.5s sleep + bounded request time), so a flapping gateway cannot
# stall the firer.
_RETRY_LIMIT = 2
_RETRY_BACKOFF: tuple[float, ...] = (0.5, 1.0)
_RETRY_STATUSES = frozenset({502, 503, 504})


class ReadOnlyFirstError(RuntimeError):
    """Raised when a state-changing request is attempted before the read-only

    case for its endpoint has been confirmed safe (§10). Raised before any I/O.
    """


@dataclass(frozen=True)
class FireResult:
    """Outcome of a fired request — the raw signal ``classify_response`` reads (§13)."""

    status_code: int
    elapsed_seconds: float
    body: bytes
    headers: httpx.Headers
    # Transport metadata is evidence, never a verdict.  HTTPX returns the
    # final response without following redirects in the normal path; browser
    # and proxy adapters fill the same projection for a uniform oracle seam.
    final_url: str = ""
    redirects: tuple[str, ...] = ()
    transport: str = "http"


class RequestFirer:
    """Fires a request for an identity against an in-scope endpoint (§10, §13).

    Ordering of the gates is the safety contract: scope is enforced first, then
    read-only-first, then the packet is sent. A failure at any gate is audited
    and no packet leaves the process.
    """

    def __init__(
        self,
        client: httpx.Client,
        scope: ScopeGuard,
        audit: AuditLog | None = None,
        identity_headers: Mapping[str, Mapping[str, str]] | None = None,
        identity_stores: object | None = None,
    ) -> None:
        self._client = client
        self._scope = scope
        self._audit = audit or AuditLog()
        # Optional per-identity auth material. Values are kept in this runtime
        # collaborator, never copied into graph nodes or audit entries.
        self._identity_headers = {
            str(name): dict(headers) for name, headers in (identity_headers or {}).items()
        }
        # Optional live stores let bearer tokens/cookie jars refresh or expire
        # per identity.  Values stay in the store and are copied only into the
        # in-memory request kwargs immediately before the packet is sent.
        self._identity_stores: dict[str, object] = {}
        if identity_stores is not None:
            names = getattr(identity_stores, "names", None)
            token_store = getattr(identity_stores, "token_store", None)
            if callable(names) and callable(token_store):
                for name in names():
                    self._identity_stores[str(name)] = token_store(name)
            elif isinstance(identity_stores, Mapping):
                self._identity_stores = {
                    str(name): store for name, store in identity_stores.items()
                }
        # Endpoints whose read-only case has been confirmed safe, keyed by
        # identity plus scheme://host[:port]/path. Clearance cannot transfer
        # between test identities.
        self._read_only_cleared: set[tuple[str, str]] = set()
        self._clearance_lock = threading.Lock()

    @property
    def scope(self) -> ScopeGuard:
        """Scope allowlist used for every request."""
        return self._scope

    @property
    def audit(self) -> AuditLog:
        """The audit log recording every action (§10)."""
        return self._audit

    @property
    def http2_enabled(self) -> bool:
        """Whether underlying HTTPX transport is configured for HTTP/2."""
        transport = getattr(self._client, "_transport", None)
        pool = getattr(transport, "_pool", None)
        return bool(getattr(pool, "_http2", False))

    @staticmethod
    def _endpoint_key(url: httpx.URL) -> str:
        # Query/userinfo excluded — clearance is per network endpoint and path.
        # Non-default ports remain distinct so clearing :8443 cannot authorize :9443.
        port = f":{url.port}" if url.port is not None else ""
        return f"{url.scheme}://{url.host}{port}{url.path}"

    def _is_read_only(self, method: str, *, state_changing: bool) -> bool:
        return method.upper() in _READ_ONLY_METHODS and not state_changing

    def _headers_for_identity(self, identity: str) -> dict[str, str]:
        key = identity.split(":", 1)[1] if identity.startswith("identity:") else identity
        store = self._identity_stores.get(key)
        if store is not None:
            headers = getattr(store, "headers", None)
            if callable(headers):
                return {str(k): str(v) for k, v in headers().items()}
        configured = self._identity_headers.get(identity)
        if configured is None:
            configured = self._identity_headers.get(key, {})
        return dict(configured)

    def _read_only_clears(self, method: str, status_code: int) -> bool:
        """Whether read-only response proves endpoint can be safely probed.

        Only a successful GET/HEAD/OPTIONS response clears. An OPTIONS response
        is a safe preflight, but a 404/405 does not establish that the POST route
        itself is safe, so it must not bypass read-only-first.
        """
        return 200 <= status_code < 300

    def _send_once(
        self,
        method: str,
        parsed: httpx.URL,
        kwargs: dict[str, object],
        *,
        client: httpx.Client | None = None,
    ) -> FireResult:
        """Send one request and time it — a single transport attempt (§12).

        The timeout is monotonic and load-bearing for the §7 timing-statistical
        oracle, so it is measured here (not via httpx's internal elapsed state).
        """
        started = time.monotonic()
        # Redirects are returned to the caller rather than followed. A client
        # redirect hop would bypass this execution-layer scope check.
        kwargs.pop("follow_redirects", None)
        response = (client or self._client).request(
            method,
            parsed,
            follow_redirects=False,
            **kwargs,  # type: ignore[arg-type]
        )
        return FireResult(
            status_code=response.status_code,
            elapsed_seconds=time.monotonic() - started,
            body=response.content,
            headers=response.headers,
            final_url=str(response.url),
            redirects=tuple(str(item.url) for item in response.history),
        )

    def _send_with_retry(
        self,
        identity: str,
        method: str,
        target: str,
        parsed: httpx.URL,
        kwargs: dict[str, object],
        *,
        client: httpx.Client | None = None,
        transport: str = "http",
    ) -> tuple[FireResult, bool]:
        """Send a read-only request with bounded transient retry (D5).

        Returns ``(result, recovered)``. ``recovered`` is True when the final
        response arrived after at least one retry — so a downstream reader sees
        honest recovery, not a false clean success. Each intermediate attempt is
        audited as ``fired:<status>`` (a real 5xx response) or
        ``error:<Type>`` (a transport error). Final outcomes:
        ``fired:<status>`` clean, ``fired:<status>:recovered`` after a retry,
        ``error:<Type>:unrecoverable`` after retries exhausted.
        """
        for attempt in range(_RETRY_LIMIT + 1):
            try:
                result = self._send_once(method, parsed, kwargs, client=client)
            except Exception as exc:  # noqa: BLE001 — transport failure, audited per attempt
                if attempt < _RETRY_LIMIT:
                    outcome = f"error:{type(exc).__name__}"
                    if transport != "http":
                        outcome = f"{transport}:{outcome}"
                    self._audit.record(identity, method, target, outcome)
                    time.sleep(_RETRY_BACKOFF[attempt])
                    continue
                outcome = f"error:{type(exc).__name__}:unrecoverable"
                if transport != "http":
                    outcome = f"{transport}:{outcome}"
                self._audit.record(identity, method, target, outcome)
                raise
            if result.status_code not in _RETRY_STATUSES:
                # A non-transient response (2xx/3xx/4xx, or a meaningful 500) is
                # final — retried only 502/503/504 gateway errors are retried.
                return result, attempt > 0
            if attempt < _RETRY_LIMIT:
                # Transient gateway error — retry; audit the real response.
                outcome = f"fired:{result.status_code}"
                if transport != "http":
                    outcome = f"{transport}:{outcome}"
                self._audit.record(identity, method, target, outcome)
                time.sleep(_RETRY_BACKOFF[attempt])
                continue
            # Last attempt still a transient gateway error — that IS the answer.
            return result, False
        raise RuntimeError("unreachable")  # pragma: no cover — loop always returns/raises

    def fire(
        self,
        identity: str,
        method: str,
        url: str,
        *,
        state_changing: bool = False,
        **kwargs: object,
    ) -> FireResult:
        """Fire one request, enforcing scope → read-only-first → send (§10).

        ``state_changing`` lets the caller flag a nominally read-only method
        (e.g. a GET that triggers a side effect) as mutating, so it too is gated.

        Raises :class:`OutOfScopeError` or :class:`ReadOnlyFirstError` before any
        network I/O if a gate fails.

        ``authentication=True`` is reserved for the detected login endpoint.  A
        login POST creates a session rather than changing target data, but still
        remains an explicit, audited exception to read-only-first.  All other
        state-changing requests retain the normal gate.
        """
        method = method.upper()
        proxy_value = kwargs.pop("proxy_url", None)
        proxy_url = str(proxy_value) if proxy_value is not None else None
        transport = str(kwargs.pop("transport", "http"))
        if transport not in {"http", "browser", "proxy"}:
            raise ValueError(f"unsupported firing transport: {transport!r}")
        if transport == "browser":
            raise ValueError("browser transport must run through the browser dispatcher")
        if transport == "proxy" and not proxy_url:
            raise ValueError("proxy transport requires a configured proxy URL")
        parsed = httpx.URL(url)
        target = self._endpoint_key(parsed)
        authentication = bool(kwargs.pop("authentication", False))
        # A proxy is selected by the LLM-facing transport layer, but all safety
        # gates below still run in this method.  The proxy client is created only
        # after those gates pass and is short-lived per request.
        proxy_client: httpx.Client | None = None

        # Merge configured identity headers first, allowing an explicit probe
        # header (for example Origin) to override one value for this request.
        configured = self._headers_for_identity(identity)
        if configured:
            explicit = kwargs.get("headers")
            merged = dict(configured)
            if isinstance(explicit, Mapping):
                merged.update({str(k): str(v) for k, v in explicit.items()})
            kwargs["headers"] = merged

        # Gate 1: scope, before anything else touches the network (§10).
        try:
            self._scope.enforce(parsed)
        except OutOfScopeError:
            self._audit.record(identity, method, target, "refused_out_of_scope")
            raise

        read_only = self._is_read_only(method, state_changing=state_changing)

        # Gate 2: read-only-first. A state-changing request may not fire until the
        # read-only case for this endpoint has been confirmed safe (§10).
        key = (identity, target)
        with self._clearance_lock:
            cleared = key in self._read_only_cleared
        if not read_only and not cleared and not authentication:
            self._audit.record(identity, method, target, "refused_read_only_first")
            raise ReadOnlyFirstError(
                f"read-only case not yet confirmed for {target}; fire a read-only request first"
            )
        if authentication and method != "POST":
            self._audit.record(identity, method, target, "refused_invalid_auth_setup")
            raise ReadOnlyFirstError("authentication setup is limited to POST login requests")

        if proxy_url:
            proxy_client = httpx.Client(
                proxy=proxy_url,
                timeout=self._client.timeout,
                follow_redirects=False,
                trust_env=False,
            )

        # Gate passed — send the packet. A state-changing request is NEVER
        # retried (a retried mutation could double-apply a side effect); a
        # read-only request gets bounded transient retry on 5xx/transport error
        # (§10 D5). Scope and read-only-first gates ran once, above, before any
        # attempt — retries do not re-run them.
        if not read_only:
            try:
                result = self._send_once(method, parsed, kwargs, client=proxy_client)
            except Exception as exc:  # noqa: BLE001 — every failed attempt must be audited
                self._audit.record(identity, method, target, f"error:{type(exc).__name__}")
                raise
            finally:
                if proxy_client is not None:
                    proxy_client.close()
            result = FireResult(
                status_code=result.status_code,
                elapsed_seconds=result.elapsed_seconds,
                body=result.body,
                headers=result.headers,
                final_url=result.final_url,
                redirects=result.redirects,
                transport=transport,
            )
            outcome = (
                f"fired:{result.status_code}"
                if transport == "http"
                else f"{transport}:fired:{result.status_code}"
            )
            self._audit.record(identity, method, target, outcome)
            return result

        try:
            result, recovered = self._send_with_retry(
                identity,
                method,
                target,
                parsed,
                kwargs,
                client=proxy_client,
                transport=transport,
            )
        finally:
            if proxy_client is not None:
                proxy_client.close()

        # A successful read-only request clears this endpoint for later mutation.
        if self._read_only_clears(method, result.status_code):
            with self._clearance_lock:
                self._read_only_cleared.add(key)

        suffix = ":recovered" if recovered else ""
        result = FireResult(
            status_code=result.status_code,
            elapsed_seconds=result.elapsed_seconds,
            body=result.body,
            headers=result.headers,
            final_url=result.final_url,
            redirects=result.redirects,
            transport=transport,
        )
        outcome = (
            f"fired:{result.status_code}{suffix}"
            if transport == "http"
            else f"{transport}:fired:{result.status_code}{suffix}"
        )
        self._audit.record(identity, method, target, outcome)
        return result

    def record_transport_result(
        self,
        identity: str,
        method: str,
        url: str,
        status_code: int | None,
        *,
        transport: str,
        error: str | None = None,
    ) -> None:
        """Audit an already-fired browser/proxy response without judging it.

        Browser navigation happens inside Playwright, so it cannot be sent by
        HTTPX.  This method records the result after the caller performed the
        same scope/read-only-first preflight through :meth:`fire`.
        """
        parsed = httpx.URL(url)
        target = self._endpoint_key(parsed)
        try:
            self._scope.enforce(parsed)
        except OutOfScopeError:
            self._audit.record(identity, method.upper(), target, "refused_out_of_scope")
            raise
        outcome = (
            f"{transport}:error:{error[:80]}"
            if error
            else f"{transport}:fired:{status_code or 0}"
        )
        self._audit.record(identity, method.upper(), target, outcome)

    def authorize_external(
        self,
        identity: str,
        method: str,
        url: str,
        *,
        state_changing: bool = False,
        authentication: bool = False,
    ) -> None:
        """Check an external transport request without sending it.

        Browser contexts and proxy SDKs own their socket, so they call this
        execution-layer gate before continuing a request.  The actual response
        is still recorded separately and remains inert until the Validator
        oracle evaluates it.
        """
        normalized = method.upper()
        parsed = httpx.URL(url)
        target = self._endpoint_key(parsed)
        try:
            self._scope.enforce(parsed)
        except OutOfScopeError:
            self._audit.record(identity, normalized, target, "refused_out_of_scope")
            raise
        read_only = self._is_read_only(normalized, state_changing=state_changing)
        key = (identity, target)
        with self._clearance_lock:
            cleared = key in self._read_only_cleared
        if not read_only and not cleared and not authentication:
            self._audit.record(identity, normalized, target, "refused_read_only_first")
            raise ReadOnlyFirstError(
                f"read-only case not yet confirmed for {target}; external transport refused"
            )
        if authentication and normalized != "POST":
            self._audit.record(identity, normalized, target, "refused_invalid_auth_setup")
            raise ReadOnlyFirstError("authentication setup is limited to POST login requests")
