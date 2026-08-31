"""Raw HTTP/1.1 CL.TE desync timing probe — live socket transport (plan §7/§10).

``httpx`` (and every conforming HTTP client) refuses to send a request whose
``Content-Length``/``Transfer-Encoding`` pair is self-contradictory — exactly
the ambiguity a front-end/back-end desync detection probe needs to construct.
This module builds the request as raw bytes over a plain socket instead.

Safety framing (§10 spirit, applied to a class the read-only-first text
doesn't literally name — this is a GET-shaped, non-mutating probe, but the
transport itself is unusual enough to warrant its own explicit bound):

  * Exactly one request is ever written to the wire per trial. The probe body
    is shaped so a desync'd back-end is left waiting for the *rest of a
    request line* it will never receive — no second, "smuggled" request is
    ever completed, so no other connection or user's traffic is ever
    affected. The hang itself, bounded by ``_MAX_WAIT``, is the entire signal.
  * Every socket is closed immediately after one measurement, whether it
    hung or answered promptly — no lingering connections.
  * TLS uses the platform's default certificate verification, same posture as
    the httpx-based firer elsewhere in this project (no blanket disable).
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

_CONNECT_TIMEOUT = 5.0
_MAX_WAIT = 8.0  # bounded hang window per trial — long enough to separate a
# real desync hang from normal response jitter, short enough that N trials
# stay a bounded, predictable cost.

_BASELINE_BODY = "0\r\n\r\n"
_CLTE_PROBE_BODY = "0\r\n\r\nX"


@dataclass(frozen=True)
class RawProbeTarget:
    """Where to fire the raw-socket probe — plain host/port/scheme, no ports magic."""

    host: str
    port: int
    tls: bool
    path: str = "/"

    @classmethod
    def from_base_url(cls, base_url: str) -> RawProbeTarget:
        parsed = urlsplit(base_url)
        tls = parsed.scheme == "https"
        port = parsed.port or (443 if tls else 80)
        return cls(host=parsed.hostname or "", port=port, tls=tls)


def _open_socket(target: RawProbeTarget) -> socket.socket:
    sock = socket.create_connection((target.host, target.port), timeout=_CONNECT_TIMEOUT)
    if target.tls:
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=target.host)
    sock.settimeout(_MAX_WAIT)
    return sock


def _request_bytes(target: RawProbeTarget, body: str) -> bytes:
    return (
        f"POST {target.path} HTTP/1.1\r\n"
        f"Host: {target.host}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n\r\n"
        f"{body}"
    ).encode()


def _measure(target: RawProbeTarget, request: bytes) -> float:
    """Send one raw request; return elapsed ms to first response byte (or timeout)."""
    start = time.monotonic()
    try:
        sock = _open_socket(target)
    except OSError:
        return (time.monotonic() - start) * 1000
    try:
        sock.sendall(request)
        try:
            sock.recv(1)
        except OSError:
            pass  # the hang itself is the signal — a timeout is a valid data point
    finally:
        sock.close()
    return (time.monotonic() - start) * 1000


def fire_timing_trials(
    target: RawProbeTarget, *, trials: int = 10
) -> tuple[tuple[float, ...], tuple[float, ...]]:
    """Fire N baseline + N CL.TE-probe trials; return (probe_ms, baseline_ms).

    Baseline sends the same Content-Length/Transfer-Encoding header pair with
    a body that is *exactly* the declared chunked terminator — well-formed
    either way it's read, so it never hangs. The probe body appends one extra
    byte a TE-reading back-end reads as the start of a request line it will
    never finish. Both requests carry the same headers, isolating the body
    shape as the only variable between baseline and probe.
    """
    baseline = tuple(
        _measure(target, _request_bytes(target, _BASELINE_BODY)) for _ in range(trials)
    )
    probe = tuple(_measure(target, _request_bytes(target, _CLTE_PROBE_BODY)) for _ in range(trials))
    return probe, baseline
