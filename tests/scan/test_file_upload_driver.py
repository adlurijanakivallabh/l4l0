"""Hermetic E2E for the file-upload driver's catch-all canary.

Mirrors test_cache_poisoning_driver.py's harness. Caught live: Juice Shop's
server clears an OPTIONS preflight and returns 2xx to a POST on a completely
made-up, guaranteed-nonexistent path — a generic permissive-CORS + catch-all
route shape common to SPA backends. Since FILE_UPLOAD_BYPASS is a pure
status-code check, every guessed path in _UPLOAD_PATHS "confirmed" on such a
target regardless of whether any of them are real upload endpoints. The
canary probes one guaranteed-fake path first and skips the whole guessed-path
list when the target answers it just as permissively.
"""

from __future__ import annotations

import httpx

from reachagent.execution import RequestFirer, ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.orchestrator import _ValidatorSeam, run_file_upload

_BASE = "http://upload.test"


def _firer(handler: object) -> RequestFirer:
    client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return RequestFirer(client, ScopeGuard.from_hosts(["upload.test"]))


def _run(handler: object) -> list:
    graph = ReachabilityGraph()
    seam = _ValidatorSeam(graph)
    run_file_upload(
        graph=graph,
        firer=_firer(handler),
        base_url=_BASE,
        identity="anon",
        auth_headers={},
        seam=seam,
        events=[],
    )
    return graph.findings()


def test_catch_all_backend_yields_no_findings_via_the_canary() -> None:
    """A permissive-CORS + catch-all-route backend clears OPTIONS and returns
    2xx to a POST on ANY path, including one that is guaranteed not to be a
    real endpoint — the canary must catch this and skip every guessed path."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(204)
        return httpx.Response(200, text="ok")

    assert _run(handler) == []


def test_real_upload_endpoint_still_confirms_when_no_catch_all_exists() -> None:
    """A real server: the canary's made-up path gets a genuine 404, but the
    real /upload endpoint (first in _UPLOAD_PATHS) accepts both files —
    the canary must never suppress a real, distinguishing finding."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/upload":
            return httpx.Response(204 if request.method == "OPTIONS" else 200)
        return httpx.Response(404)

    findings = _run(handler)
    classes = {f.vuln_class for _fid, f in findings}
    assert "file_upload" in classes
    assert all(f.status.value == "confirmed_violation" for _fid, f in findings)


def test_no_endpoint_at_all_yields_no_findings() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    assert _run(handler) == []
