"""Real-socket proof for the CL.TE raw probe (Phase 3).

Raw HTTP byte construction is exactly the kind of logic a hermetic fake-latency
test gives zero protection against — a broken Content-Length or an off-by-one
in the chunked terminator would still "pass" a test that only fakes the
resulting numbers. These tests run a real local TCP server (loopback, no
network) that plays two roles:

  * "safe": reads exactly ``Content-Length`` bytes, answers immediately either
    way — a back-end that isn't confused by the ambiguity.
  * "confused": mimics a back-end that reads via ``Transfer-Encoding`` instead
    — stops at the chunked terminator, and if any byte the client sent is
    still unread past that point (the probe's stray extra byte), waits a
    short bounded window for "the rest of a pipelined request line" that
    never arrives before finally answering. The baseline body has no stray
    byte, so a confused reader is never kept waiting for it.

Proves the actual bytes ``raw_probe.py`` puts on the wire produce a real,
measurable timing gap against a genuinely confused reader, and no gap at all
against a correct one — not just that the oracle can compare two lists of
numbers someone already computed by hand.
"""

from __future__ import annotations

import socket
import threading

from reachagent.smuggling.raw_probe import RawProbeTarget, fire_timing_trials

_CONFUSED_DELAY = 0.3  # seconds — short enough to keep the suite fast


def _read_headers_and_declared_length(conn: socket.socket) -> tuple[bytes, int]:
    """Read past the header/body blank line; return (buffered body bytes, Content-Length)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    return rest, length


def _serve_one(sock: socket.socket, mode: str) -> None:
    conn, _ = sock.accept()
    try:
        conn.settimeout(5.0)
        body_so_far, declared_length = _read_headers_and_declared_length(conn)
        while len(body_so_far) < declared_length:
            more = conn.recv(4096)
            if not more:
                break
            body_so_far += more

        if mode == "safe":
            pass  # a Content-Length-respecting reader already has the whole body
        else:
            # "confused": stop at the chunked terminator, not the declared length.
            terminator = b"0\r\n\r\n"
            idx = body_so_far.find(terminator)
            consumed = idx + len(terminator) if idx != -1 else len(body_so_far)
            stray = body_so_far[consumed:]
            if stray:
                # A real confused back-end would now block on the network
                # waiting for the rest of what it thinks is a new request
                # line. Nothing more ever arrives — that wait, bounded here
                # for test speed, is exactly what raw_probe.py measures live.
                threading.Event().wait(_CONFUSED_DELAY)

        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    finally:
        conn.close()


def _start_server(mode: str) -> tuple[socket.socket, int, list[threading.Thread]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(20)
    port = sock.getsockname()[1]
    threads: list[threading.Thread] = []
    stop = threading.Event()

    def _accept_loop() -> None:
        sock.settimeout(0.5)
        while not stop.is_set():
            try:
                _serve_one(sock, mode)
            except TimeoutError:
                continue  # no connection yet — keep listening, not a shutdown
            except OSError:
                return  # the listening socket itself was closed — done

    t = threading.Thread(target=_accept_loop, daemon=True)
    t.start()
    threads.append(t)
    return sock, port, threads


def test_confused_backend_shows_a_real_measurable_timing_gap() -> None:
    sock, port, _ = _start_server("confused")
    try:
        target = RawProbeTarget(host="127.0.0.1", port=port, tls=False)
        probe_ms, baseline_ms = fire_timing_trials(target, trials=3)
    finally:
        sock.close()

    assert min(probe_ms) > max(baseline_ms)
    assert min(probe_ms) >= _CONFUSED_DELAY * 1000 * 0.8  # real elapsed time, not a stub


def test_safe_backend_shows_no_timing_gap() -> None:
    sock, port, _ = _start_server("safe")
    try:
        target = RawProbeTarget(host="127.0.0.1", port=port, tls=False)
        probe_ms, baseline_ms = fire_timing_trials(target, trials=3)
    finally:
        sock.close()

    # Both bodies are read to their declared Content-Length either way —
    # no stray byte ever confuses this reader, so latencies stay comparable.
    assert max(probe_ms) < 200
    assert max(baseline_ms) < 200


def test_from_base_url_parses_host_port_and_scheme() -> None:
    https = RawProbeTarget.from_base_url("https://example.test")
    assert https.host == "example.test"
    assert https.port == 443
    assert https.tls is True

    http_with_port = RawProbeTarget.from_base_url("http://example.test:8080")
    assert http_with_port.port == 8080
    assert http_with_port.tls is False
