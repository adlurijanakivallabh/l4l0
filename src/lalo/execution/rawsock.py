"""Scoped, pinned-IP raw-TCP send/recv for non-web service interaction.

Goes through the same :class:`ScopeGuard` as HTTP: the host must be in the
declared engagement (checked as ``tcp://host:port``) or the probe is skipped.
Also dials the SAME pinned IP the scope check resolved — extending the HTTP
firer's DNS-rebinding defense to the raw-TCP path too (the reference SSRF guard
this pattern is modeled on only covers HTTP; closing the same TOCTOU class here
for network-service interaction is an L4L0 addition, not present upstream).
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from ..core.logging import get_logger
from .scope import ScopeGuard

_log = get_logger("lalo.rawsock")


@dataclass
class RawResult:
    host: str
    port: int
    fired: bool
    scope_reason: str
    data: bytes = b""
    elapsed_ms: float | None = None
    error: str | None = None


def tcp_send_recv(
    scope: ScopeGuard,
    host: str,
    port: int,
    payload: bytes = b"",
    *,
    timeout: float = 5.0,
    recv_bytes: int = 65535,
) -> RawResult:
    """Open a TCP connection to an in-engagement service, optionally send
    ``payload``, and return what it responds with."""
    decision = scope.check(f"tcp://{host}:{port}")
    if not decision.allowed:
        _log.info("scope %s: tcp %s:%d", decision.reason, host, port)
        return RawResult(host=host, port=port, fired=False, scope_reason=decision.reason)

    pinned_ip = scope.pin_for_connect(host)
    if pinned_ip is None:
        return RawResult(
            host=host,
            port=port,
            fired=False,
            scope_reason=decision.reason,
            error="dns_resolution_failed",
        )

    start = time.monotonic()
    # Declared before the try so a non-timeout OSError (caught below) can
    # still return whatever was already received, rather than discarding it
    # - see that branch's own comment.
    chunks: list[bytes] = []
    try:
        with socket.create_connection((pinned_ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if payload:
                sock.sendall(payload)
            received = 0
            while received < recv_bytes:
                try:
                    chunk = sock.recv(min(4096, recv_bytes - received))
                except TimeoutError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                received += len(chunk)
    except OSError as exc:
        # A service that accepted the connection and streamed a partial
        # banner/response before resetting (ConnectionResetError et al. are
        # OSError subclasses, not caught by the TimeoutError handling above)
        # - discarding what was already received would silently lose real
        # partial evidence (proving the crash/reset was reachable and what
        # the service returned first). `chunks` is empty when the failure
        # happened before any bytes were ever read.
        return RawResult(
            host=host,
            port=port,
            fired=True,
            scope_reason=decision.reason,
            data=b"".join(chunks),
            error=type(exc).__name__,
            elapsed_ms=(time.monotonic() - start) * 1000.0,
        )

    return RawResult(
        host=host,
        port=port,
        fired=True,
        scope_reason=decision.reason,
        data=b"".join(chunks),
        elapsed_ms=(time.monotonic() - start) * 1000.0,
    )
