"""Scoped raw-TCP send/recv for non-web service interaction (network pentest).

Goes through the same :class:`ScopeGuard` as HTTP: the host must be in the
declared engagement (checked as ``tcp://host:port``) or the probe is skipped.
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

    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if payload:
                sock.sendall(payload)
            chunks: list[bytes] = []
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
        return RawResult(
            host=host,
            port=port,
            fired=True,
            scope_reason=decision.reason,
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
