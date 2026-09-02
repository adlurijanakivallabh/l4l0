"""Hermetic-ish E2E for the request-smuggling driver: base_url -> raw-socket
timing probe -> finding, against a real local TCP server (loopback only).

Mirrors the confused/safe simulated backend in
tests/phase3/test_smuggling_raw_probe.py (duplicated here, not imported --
this project's test files are each self-contained, no shared conftest).
Proves run_request_smuggling wires base_url through RawProbeTarget correctly
and writes a finding only when the oracle actually confirms a timing
violation.
"""

from __future__ import annotations

import socket
import threading

from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.orchestrator import _ValidatorSeam, run_request_smuggling
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient

_CONFUSED_DELAY = 0.3


def _read_headers_and_declared_length(conn: socket.socket) -> tuple[bytes, int]:
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

        if mode != "safe":
            terminator = b"0\r\n\r\n"
            idx = body_so_far.find(terminator)
            consumed = idx + len(terminator) if idx != -1 else len(body_so_far)
            if body_so_far[consumed:]:
                threading.Event().wait(_CONFUSED_DELAY)

        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    finally:
        conn.close()


def _start_server(mode: str) -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(20)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def _accept_loop() -> None:
        sock.settimeout(0.5)
        while not stop.is_set():
            try:
                _serve_one(sock, mode)
            except TimeoutError:
                continue
            except OSError:
                return

    threading.Thread(target=_accept_loop, daemon=True).start()
    return sock, port


def test_confirms_a_finding_against_a_confused_backend(monkeypatch) -> None:  # noqa: ANN001
    # v3 (CLAUDE.md): confirmation is now an LLM judgment, not the removed
    # decide() logic, and run_request_smuggling has no client= seam to inject
    # through (only tools.validator.run_oracle's direct callers do). Fix the
    # LLM provider factory that reachagent.oracles.llm_judgment.judge() falls
    # back to, so this test asserts WIRING -- does a confirmed verdict flow
    # from the real timing probe through corroboration to write_finding --
    # not judgment itself. The confused backend still produces a real timing
    # delay; only the oracle's verdict is made deterministic.
    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )
    sock, port = _start_server("confused")
    try:
        graph = ReachabilityGraph()
        seam = _ValidatorSeam(graph)
        found = run_request_smuggling(base_url=f"http://127.0.0.1:{port}", seam=seam, events=[])
    finally:
        sock.close()

    assert found
    classes = {f.vuln_class for _fid, f in graph.findings()}
    assert "request_smuggling" in classes


def test_no_finding_against_a_safe_backend() -> None:
    sock, port = _start_server("safe")
    try:
        graph = ReachabilityGraph()
        seam = _ValidatorSeam(graph)
        found = run_request_smuggling(base_url=f"http://127.0.0.1:{port}", seam=seam, events=[])
    finally:
        sock.close()

    assert found == []
    assert graph.findings() == []


def test_unresolvable_host_is_not_applicable_not_a_crash() -> None:
    graph = ReachabilityGraph()
    seam = _ValidatorSeam(graph)
    found = run_request_smuggling(base_url="not-a-url", seam=seam, events=[])
    assert found == []


def test_corroboration_catches_a_one_off_flaky_confirmation(monkeypatch) -> None:  # noqa: ANN001
    """Build Order 5: reproduces this session's own live false positive —
    request_smuggling confirmed once under heavy system load, then passed
    cleanly (no signal) in isolation. A single confirmed attempt must no
    longer be enough to write a finding.
    """
    import reachagent.smuggling.detector as _smuggling_detector

    # First call confirms (the flaky signal), every subsequent call does
    # not (the signal doesn't reproduce) — exactly the observed live shape.
    calls = {"n": 0}

    class _FlakyResult:
        def __init__(self, confirmed: bool) -> None:
            self.confirmed = confirmed

    def _flaky_detect(prober, *, evidence_ref="") -> object:  # noqa: ANN001, ARG001
        calls["n"] += 1
        return _FlakyResult(confirmed=calls["n"] == 1)

    monkeypatch.setattr(_smuggling_detector, "detect_request_smuggling", _flaky_detect)

    graph = ReachabilityGraph()
    seam = _ValidatorSeam(graph)
    found = run_request_smuggling(base_url="http://127.0.0.1:1", seam=seam, events=[])
    assert found == []
    assert graph.findings() == []
    # Corroboration actually ran (more than the single original attempt).
    assert calls["n"] > 1
