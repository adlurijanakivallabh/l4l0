"""Path traversal detection tests (plan §7, §9; Phase 3 Task 8).

Covers the Task 8 DoD:
  * Detector unit tests: confirmed, clean (sentinel absent), empty sentinel.
  * Integration test: real local HTTP server with a ?file= param that reads
    from a base directory but fails to sanitize ../, letting the probe retrieve
    a sentinel file outside root — real filesystem traversal, not a mock.
  * Clean integration test: a safe path inside root returns content without
    the sentinel — no false positive.
"""

from __future__ import annotations

import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from reachagent.pathtraversal.detector import (
    PathTraversalProber,
    TraversalProbeResult,
    detect_path_traversal,
)

# === Detector unit tests ======================================================


def _prober(body: str, sentinel: str) -> PathTraversalProber:
    return PathTraversalProber(
        fire_probe=lambda: TraversalProbeResult(body=body),
        sentinel=sentinel,
    )


def test_detector_confirms_when_sentinel_in_body() -> None:
    result = detect_path_traversal(
        _prober("root:x:0:0:root:/root:/bin/bash\n", "root:x:0:0"),
        evidence_ref="traversal/1",
    )
    assert result.confirmed is True


def test_detector_clean_sentinel_absent() -> None:
    result = detect_path_traversal(
        _prober("<html>not found</html>", "root:x:0:0"),
        evidence_ref="traversal/clean",
    )
    assert result.confirmed is False


def test_detector_empty_sentinel_never_confirms() -> None:
    result = detect_path_traversal(
        _prober("root:x:0:0", ""),
        evidence_ref="traversal/empty-sentinel",
    )
    assert result.confirmed is False


# === Integration test: real traversal-vulnerable HTTP server ==================


class _TraversalHandler(BaseHTTPRequestHandler):
    """Serves files from ``base_dir`` via ?file=; does NOT sanitize ../."""

    base_dir: str  # set on the class before use

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        file_param = params.get("file", [""])[0]
        if not file_param:
            self.send_response(400)
            self.end_headers()
            return
        # Vulnerable: joins without sanitising ../ sequences.
        target = os.path.join(self.base_dir, file_param)
        try:
            with open(target, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            self.send_response(404)
            self.end_headers()


@pytest.fixture(scope="module")
def traversal_server() -> tuple[str, str]:
    """Start the traversal server; return (base_url, sentinel_content)."""
    # Create a temp directory tree:
    #   tmpdir/
    #     serve/          ← server's base_dir
    #       public.txt    ← safe file inside root
    #     secret.txt      ← out-of-scope sentinel file
    tmpdir = tempfile.mkdtemp()
    serve_dir = os.path.join(tmpdir, "serve")
    os.makedirs(serve_dir)

    sentinel = "REACHAGENT_SENTINEL_7f3a9b"
    secret_path = os.path.join(tmpdir, "secret.txt")
    with open(secret_path, "w") as f:
        f.write(f"{sentinel}\nout-of-scope content\n")

    public_path = os.path.join(serve_dir, "public.txt")
    with open(public_path, "w") as f:
        f.write("safe public content\n")

    _TraversalHandler.base_dir = serve_dir

    server = HTTPServer(("127.0.0.1", 0), _TraversalHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", sentinel
    server.shutdown()


def _fetch(base_url: str, file_param: str) -> str:
    import http.client
    from urllib.parse import quote, urlparse

    parsed = urlparse(base_url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port)
    conn.request("GET", f"/?file={quote(file_param, safe='/')}")
    resp = conn.getresponse()
    body = resp.read().decode(errors="replace")
    conn.close()
    return body


@pytest.mark.integration
def test_real_server_traversal_retrieves_out_of_scope_file(
    traversal_server: tuple[str, str],
) -> None:
    """Positive: ../secret.txt traverses outside serve/ and returns the sentinel."""
    base_url, sentinel = traversal_server
    prober = PathTraversalProber(
        fire_probe=lambda: TraversalProbeResult(_fetch(base_url, "../secret.txt")),
        sentinel=sentinel,
    )
    result = detect_path_traversal(prober, evidence_ref="traversal/integration/positive")
    assert result.confirmed is True


@pytest.mark.integration
def test_real_server_safe_path_finds_no_sentinel(
    traversal_server: tuple[str, str],
) -> None:
    """Negative: public.txt is inside root and does not contain the sentinel."""
    base_url, sentinel = traversal_server
    prober = PathTraversalProber(
        fire_probe=lambda: TraversalProbeResult(_fetch(base_url, "public.txt")),
        sentinel=sentinel,
    )
    result = detect_path_traversal(prober, evidence_ref="traversal/integration/negative")
    assert result.confirmed is False
