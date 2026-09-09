"""Tests for scripts/ci-scan.py - a standalone, package-external CI/CD
wrapper around L4L0's existing GUI HTTP API. Loaded by file path (not a
normal package import) since it deliberately lives outside src/lalo/ -
automation glue for a DIFFERENT tool's pipeline, never L4L0's own product
surface.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import httpx

_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "ci-scan.py"


def _load_ci_scan() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ci_scan", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ci_scan = _load_ci_scan()


def _sarif_doc(results: list[dict[str, object]]) -> dict[str, object]:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "L4L0", "rules": []}}, "results": results}],
    }


def _result(*, verdict: str | None, cvss_score: float) -> dict[str, object]:
    return {
        "ruleId": "sql-injection",
        "level": "error",
        "message": {"text": "SQLi"},
        "locations": [],
        "properties": {
            "security-severity": f"{cvss_score:.1f}",
            "lalo": {"review_verdict": verdict},
        },
    }


def _mock_transport(sarif_doc: dict[str, object]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/scan" and request.method == "POST":
            return httpx.Response(200, json={"run_id": "abc123"})
        if request.url.path == "/runs" and request.method == "GET":
            return httpx.Response(200, json={"runs": [{"run_id": "abc123", "running": False}]})
        if request.url.path == "/runs/abc123/report/sarif":
            return httpx.Response(200, content=json.dumps(sarif_doc).encode("utf-8"))
        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handler)


def test_ci_scan_exits_zero_when_no_confirmed_finding_meets_the_threshold(
    tmp_path: Path,
) -> None:
    sarif_doc = _sarif_doc([_result(verdict="open_proof_gap", cvss_score=9.5)])
    client = httpx.Client(transport=_mock_transport(sarif_doc), base_url="http://testserver")
    exit_code = ci_scan.main(
        [
            "--target",
            "https://x.example.com",
            "--fail-on-severity",
            "critical",
            "--sarif-out",
            str(tmp_path / "out.sarif"),
        ],
        client=client,
    )
    assert exit_code == 0


def test_ci_scan_never_fails_on_an_unconfirmed_finding_regardless_of_severity(
    tmp_path: Path,
) -> None:
    """A confirmed critical finding would fail the build (see the test
    below) - the same finding, un-reviewed or open-proof-gap, must not,
    matching CLAUDE.md's own "neither layer ever removes a finding, but a
    build gate must never fire on an unconfirmed one" stance."""
    sarif_doc = _sarif_doc(
        [
            _result(verdict="open_proof_gap", cvss_score=9.8),
            _result(verdict=None, cvss_score=9.8),
        ]
    )
    client = httpx.Client(transport=_mock_transport(sarif_doc), base_url="http://testserver")
    exit_code = ci_scan.main(
        [
            "--target",
            "https://x.example.com",
            "--fail-on-severity",
            "low",
            "--sarif-out",
            str(tmp_path / "out.sarif"),
        ],
        client=client,
    )
    assert exit_code == 0


def test_ci_scan_fails_the_build_on_a_confirmed_finding_meeting_the_threshold(
    tmp_path: Path,
) -> None:
    sarif_doc = _sarif_doc([_result(verdict="confirmed", cvss_score=7.5)])  # -> "high"
    client = httpx.Client(transport=_mock_transport(sarif_doc), base_url="http://testserver")
    exit_code = ci_scan.main(
        [
            "--target",
            "https://x.example.com",
            "--fail-on-severity",
            "high",
            "--sarif-out",
            str(tmp_path / "out.sarif"),
        ],
        client=client,
    )
    assert exit_code == 1


def test_ci_scan_does_not_fail_when_the_confirmed_finding_is_below_threshold(
    tmp_path: Path,
) -> None:
    sarif_doc = _sarif_doc([_result(verdict="confirmed", cvss_score=5.0)])  # -> "medium"
    client = httpx.Client(transport=_mock_transport(sarif_doc), base_url="http://testserver")
    exit_code = ci_scan.main(
        [
            "--target",
            "https://x.example.com",
            "--fail-on-severity",
            "high",
            "--sarif-out",
            str(tmp_path / "out.sarif"),
        ],
        client=client,
    )
    assert exit_code == 0


def test_ci_scan_with_no_fail_on_severity_never_fails_regardless_of_findings(
    tmp_path: Path,
) -> None:
    sarif_doc = _sarif_doc([_result(verdict="confirmed", cvss_score=9.9)])
    client = httpx.Client(transport=_mock_transport(sarif_doc), base_url="http://testserver")
    exit_code = ci_scan.main(
        ["--target", "https://x.example.com", "--sarif-out", str(tmp_path / "out.sarif")],
        client=client,
    )
    assert exit_code == 0


def test_ci_scan_writes_the_sarif_output_to_the_given_path(tmp_path: Path) -> None:
    sarif_doc = _sarif_doc([])
    client = httpx.Client(transport=_mock_transport(sarif_doc), base_url="http://testserver")
    out_path = tmp_path / "l4l0.sarif"
    ci_scan.main(["--target", "https://x.example.com", "--sarif-out", str(out_path)], client=client)
    assert json.loads(out_path.read_text(encoding="utf-8")) == sarif_doc


def test_ci_scan_times_out_if_the_scan_never_finishes(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/scan":
            return httpx.Response(200, json={"run_id": "abc123"})
        if request.url.path == "/runs":
            return httpx.Response(200, json={"runs": [{"run_id": "abc123", "running": True}]})
        return httpx.Response(404, json={"error": "not found"})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    exit_code = ci_scan.main(
        [
            "--target",
            "https://x.example.com",
            "--sarif-out",
            str(tmp_path / "out.sarif"),
            "--poll-interval-s",
            "0",
            "--timeout-s",
            "0",
        ],
        client=client,
    )
    assert exit_code == 2
