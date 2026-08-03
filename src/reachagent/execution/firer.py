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
from dataclasses import dataclass

import httpx

from reachagent.execution.audit import AuditLog
from reachagent.execution.scope import OutOfScopeError, ScopeGuard

# Methods that cannot change server state. Anything outside this set is treated
# as state-changing and gated behind read-only-first (§10).
_READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


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
    ) -> None:
        self._client = client
        self._scope = scope
        self._audit = audit or AuditLog()
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

    def _read_only_clears(self, method: str, status_code: int) -> bool:
        """Whether read-only response proves endpoint can be safely probed.

        Only a successful GET/HEAD/OPTIONS response clears. An OPTIONS response
        is a safe preflight, but a 404/405 does not establish that the POST route
        itself is safe, so it must not bypass read-only-first.
        """
        return 200 <= status_code < 300

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
        """
        method = method.upper()
        parsed = httpx.URL(url)
        target = self._endpoint_key(parsed)

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
        if not read_only and not cleared:
            self._audit.record(identity, method, target, "refused_read_only_first")
            raise ReadOnlyFirstError(
                f"read-only case not yet confirmed for {target}; fire a read-only request first"
            )

        # Gate passed — send the packet. Time it ourselves with a monotonic
        # clock: timing is load-bearing for the §7 timing-statistical oracle, and
        # we don't want it depending on httpx's internal ``.elapsed`` state.
        started = time.monotonic()
        try:
            # Redirects are returned to the caller rather than followed. A client
            # redirect hop would bypass this execution-layer scope check.
            kwargs.pop("follow_redirects", None)
            response = self._client.request(method, parsed, follow_redirects=False, **kwargs)  # type: ignore[arg-type]
            elapsed_seconds = time.monotonic() - started
            result = FireResult(
                status_code=response.status_code,
                elapsed_seconds=elapsed_seconds,
                body=response.content,
                headers=response.headers,
            )
        except Exception as exc:  # noqa: BLE001 — every failed attempt must be audited
            self._audit.record(identity, method, target, f"error:{type(exc).__name__}")
            raise

        # A successful read-only request clears this endpoint for later mutation.
        if read_only and self._read_only_clears(method, result.status_code):
            with self._clearance_lock:
                self._read_only_cleared.add(key)

        self._audit.record(identity, method, target, f"fired:{result.status_code}")
        return result
