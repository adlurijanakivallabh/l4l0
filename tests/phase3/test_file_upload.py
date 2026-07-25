"""File upload bypass detection tests (plan §7, §9; Phase 3 Task 7).

Covers the Task 7 DoD:
  * STRUCTURAL oracle is now registered — all six §7 families built.
  * Oracle unit tests: FILE_UPLOAD_BYPASS, PATH_TRAVERSAL, JWT_FORGERY decision paths.
  * Detector: bypass confirmed, correctly rejected, baseline-failed inconclusive.
  * Integration test: real local HTTP server enforcing an extension allowlist
    (only .jpg accepted); disguised .php file with .jpg extension bypasses it.
  * Clean integration test: legitimately rejected file → CONFIRMED_DENIED, not bypass.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from reachagent.fileupload.detector import (
    FileUploadProber,
    UploadProbeResult,
    detect_file_upload_bypass,
)
from reachagent.graph.nodes import FindingStatus
from reachagent.oracles import OracleMechanism
from reachagent.oracles.registry import get_oracle
from reachagent.oracles.structural import (
    StructuralCheckType,
    StructuralEvidence,
    StructuralOracle,
    decide,
)

# === Oracle registration ======================================================


def test_structural_oracle_registered() -> None:
    oracle = get_oracle(OracleMechanism.STRUCTURAL)
    assert isinstance(oracle, StructuralOracle)


def test_all_six_families_now_registered() -> None:
    for mech in OracleMechanism:
        oracle = get_oracle(mech)
        assert oracle.mechanism is mech


# === FILE_UPLOAD_BYPASS decision table ========================================


def test_bypass_confirmed_when_probe_accepted() -> None:
    ev = StructuralEvidence(
        check_type=StructuralCheckType.FILE_UPLOAD_BYPASS,
        baseline_status=200,
        probe_status=200,
    )
    assert decide(ev) is FindingStatus.CONFIRMED_VIOLATION


def test_bypass_denied_when_probe_rejected() -> None:
    ev = StructuralEvidence(
        check_type=StructuralCheckType.FILE_UPLOAD_BYPASS,
        baseline_status=200,
        probe_status=400,
    )
    assert decide(ev) is FindingStatus.CONFIRMED_DENIED


def test_bypass_inconclusive_when_baseline_failed() -> None:
    ev = StructuralEvidence(
        check_type=StructuralCheckType.FILE_UPLOAD_BYPASS,
        baseline_status=500,
        probe_status=200,
    )
    assert decide(ev) is FindingStatus.INCONCLUSIVE


# === PATH_TRAVERSAL decision table ============================================


def test_traversal_confirmed_when_sentinel_in_body() -> None:
    ev = StructuralEvidence(
        check_type=StructuralCheckType.PATH_TRAVERSAL,
        sentinel="root:x:0:0",
        response_body="root:x:0:0:root:/root:/bin/bash\n",
    )
    assert decide(ev) is FindingStatus.CONFIRMED_VIOLATION


def test_traversal_inconclusive_when_sentinel_absent() -> None:
    ev = StructuralEvidence(
        check_type=StructuralCheckType.PATH_TRAVERSAL,
        sentinel="root:x:0:0",
        response_body="<html>not found</html>",
    )
    assert decide(ev) is FindingStatus.INCONCLUSIVE


def test_traversal_inconclusive_when_no_sentinel() -> None:
    ev = StructuralEvidence(
        check_type=StructuralCheckType.PATH_TRAVERSAL,
        sentinel="",
        response_body="root:x:0:0",
    )
    assert decide(ev) is FindingStatus.INCONCLUSIVE


# === JWT_FORGERY decision table ===============================================


def test_jwt_forgery_confirmed() -> None:
    ev = StructuralEvidence(
        check_type=StructuralCheckType.JWT_FORGERY,
        baseline_status=200,
        probe_status=200,
    )
    assert decide(ev) is FindingStatus.CONFIRMED_VIOLATION


def test_jwt_forgery_denied() -> None:
    ev = StructuralEvidence(
        check_type=StructuralCheckType.JWT_FORGERY,
        baseline_status=200,
        probe_status=401,
    )
    assert decide(ev) is FindingStatus.CONFIRMED_DENIED


def test_jwt_forgery_inconclusive_bad_baseline() -> None:
    ev = StructuralEvidence(
        check_type=StructuralCheckType.JWT_FORGERY,
        baseline_status=401,
        probe_status=200,
    )
    assert decide(ev) is FindingStatus.INCONCLUSIVE


# === Oracle type guard ========================================================


def test_structural_oracle_wrong_type_raises() -> None:
    oracle = StructuralOracle()
    with pytest.raises(TypeError):
        oracle.run({"check_type": "file_upload_bypass"})


# === Detector unit tests ======================================================


def _prober(baseline: int, probe: int) -> FileUploadProber:
    return FileUploadProber(
        fire_baseline=lambda: UploadProbeResult(status_code=baseline),
        fire_probe=lambda: UploadProbeResult(status_code=probe),
    )


def test_detector_confirms_bypass() -> None:
    result = detect_file_upload_bypass(_prober(200, 200), evidence_ref="upload/bypass/1")
    assert result.confirmed is True


def test_detector_clean_correctly_rejected() -> None:
    result = detect_file_upload_bypass(_prober(200, 400), evidence_ref="upload/clean/1")
    assert result.confirmed is False


def test_detector_inconclusive_when_baseline_fails() -> None:
    result = detect_file_upload_bypass(_prober(500, 200), evidence_ref="upload/broken/1")
    assert result.confirmed is False


# === Integration test: real HTTP server with extension allowlist ==============

_ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif"}


class _UploadHandler(BaseHTTPRequestHandler):
    """Minimal multipart upload endpoint enforcing an extension allowlist."""

    def log_message(self, *args: object) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/upload":
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode(errors="replace")

        # Extract filename from Content-Disposition in the multipart body.
        filename = ""
        for line in body.splitlines():
            if "filename=" in line:
                filename = line.split("filename=")[-1].strip().strip('"')
                break

        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext in _ALLOWED_EXTENSIONS:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error":"extension not allowed"}')


@pytest.fixture(scope="module")
def upload_server() -> str:
    server = HTTPServer(("127.0.0.1", 0), _UploadHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def _upload(base_url: str, filename: str, content: bytes = b"data") -> int:
    import http.client
    import urllib.parse

    parsed = urllib.parse.urlparse(base_url)
    boundary = "----ReachAgentBoundary"
    body = (
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + content
        + f"\r\n--{boundary}--\r\n".encode()
    )

    conn = http.client.HTTPConnection(parsed.hostname, parsed.port)
    conn.request(
        "POST",
        "/upload",
        body=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        },
    )
    resp = conn.getresponse()
    conn.close()
    return resp.status


@pytest.mark.integration
def test_real_server_bypass_disguised_php_as_jpg(upload_server: str) -> None:
    """Positive: .php file renamed to .php.jpg bypasses the extension allowlist."""
    prober = FileUploadProber(
        fire_baseline=lambda: UploadProbeResult(_upload(upload_server, "photo.jpg")),
        fire_probe=lambda: UploadProbeResult(_upload(upload_server, "shell.php.jpg")),
    )
    result = detect_file_upload_bypass(prober, evidence_ref="upload/bypass/integration")
    # Both .jpg and .php.jpg end in .jpg — the allowlist is bypassed.
    assert result.confirmed is True


@pytest.mark.integration
def test_real_server_clean_php_rejected(upload_server: str) -> None:
    """Negative: bare .php file is correctly rejected — no bypass."""
    prober = FileUploadProber(
        fire_baseline=lambda: UploadProbeResult(_upload(upload_server, "photo.jpg")),
        fire_probe=lambda: UploadProbeResult(_upload(upload_server, "shell.php")),
    )
    result = detect_file_upload_bypass(prober, evidence_ref="upload/clean/integration")
    assert result.confirmed is False
