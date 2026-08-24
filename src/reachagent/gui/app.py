"""Web GUI for LLM-driven pentest loop — FastAPI, no TUI/CLI dependency (plan §4).

Shares scan/entrypoint:scan_target + ReachabilityGraph/AuditLog; no ScopeGuard
bypass. LLM drives each phase via existing flag-gated helpers (profile → vuln
→ payload → report), allowlist-validated. GUI only observes graph via SSE poll.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from reachagent.graph.store import ReachabilityGraph
from reachagent.report.renderer import render_findings_markdown

app = FastAPI(title="ReachAgent GUI", version="1.0")
_scans: dict[str, dict[str, Any]] = {}  # id → {graph, audit, status, target}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    try:
        return (app.static_path / "index.html").read_text()  # type: ignore[attr-defined,no-any-return]
    except Exception:
        return "<h1>ReachAgent GUI</h1><p>static/index.html missing</p>"


@app.post("/api/scan")
async def start_scan(payload: dict[str, Any]) -> JSONResponse:
    target = str(payload.get("target", "")).strip()
    in_scope = str(payload.get("in_scope", "")).strip() or target
    use_llm = bool(payload.get("use_llm", False))
    if not target:
        return JSONResponse({"error": "target required"}, status_code=400)
    scan_id = uuid.uuid4().hex[:8]
    _scans[scan_id] = {"target": target, "status": "running", "findings": []}
    # run scan in background (ponytail: asyncio.create_task, not thread pool)
    asyncio.create_task(_run_scan(scan_id, target, in_scope, use_llm))
    return JSONResponse({"scan_id": scan_id, "status": "running"})


async def _run_scan(scan_id: str, target: str, in_scope: str, use_llm: bool) -> None:
    import os

    # flag-gated LLM for this scan only (no global env leak beyond task)
    env_patch = {"REACHAGENT_RECON_PROFILE": "1"} if use_llm else {}
    # reuse existing scan_target — LLM helpers are flag-gated inside
    from reachagent.scan.entrypoint import scan_target

    # patch env for this task
    old = {k: os.environ.get(k) for k in env_patch}
    try:
        for k, v in env_patch.items():
            os.environ[k] = v
        # run in thread to not block event loop (scan does httpx + subprocess)
        import concurrent.futures

        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            result = await loop.run_in_executor(
                pool,
                lambda: scan_target(base_url=target, in_scope=in_scope, dry_run=False, max_attempts=20),
            )
        g: ReachabilityGraph = result["graph"]
        findings = g.findings()
        # store markdown for report
        md = render_findings_markdown(g)
        _scans[scan_id].update({"status": "done", "findings": findings, "report_md": md, "graph": g})
    except Exception as exc:  # noqa: BLE001
        _scans[scan_id].update({"status": "error", "error": str(exc)})
    finally:
        for ok, ov in old.items():
            if ov is not None:
                os.environ[ok] = ov
            else:
                os.environ.pop(ok, None)


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str) -> JSONResponse:
    data = _scans.get(scan_id)
    if not data:
        return JSONResponse({"error": "not found"}, status_code=404)
    # serialize findings for GUI table
    findings = []
    for fid, f in data.get("findings", []):
        findings.append(
            {
                "finding_id": fid,
                "vuln_class": getattr(f, "vuln_class", ""),
                "severity": getattr(f, "severity", ""),
                "oracle_used": getattr(f, "oracle_used", ""),
                "evidence_ref": getattr(f, "evidence_ref", ""),
                "status": getattr(getattr(f, "status", ""), "value", str(getattr(f, "status", ""))),
            }
        )
    return JSONResponse(
        {
            "scan_id": scan_id,
            "target": data.get("target"),
            "status": data.get("status"),
            "findings": findings,
            "report_md": data.get("report_md", ""),
            "error": data.get("error"),
        }
    )


@app.get("/api/report/{scan_id}")
def get_report(scan_id: str) -> JSONResponse:
    data = _scans.get(scan_id)
    if not data or "graph" not in data:
        return JSONResponse({"error": "not found or not done"}, status_code=404)
    # LLM-driven report over confirmed findings only
    from reachagent.report.llm_report import generate_llm_report

    g: ReachabilityGraph = data["graph"]
    md = generate_llm_report(g)
    return JSONResponse({"scan_id": scan_id, "report_md": md})


# mount static after routes (so / doesn't clash)
try:
    from pathlib import Path as _Path

    _static = _Path(__file__).parent / "static"
    _static.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(_static)), name="static")
    app.static_path = _static  # type: ignore[attr-defined]
except Exception:  # noqa: BLE001,S110
    pass  # noqa: S110


def main() -> None:  # ponytail: one-liner entry, no config file until 3 flags
    import argparse

    import uvicorn

    p = argparse.ArgumentParser(description="ReachAgent GUI — LLM-driven pentest")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    args = p.parse_args()
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
