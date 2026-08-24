"""Web GUI for the full LLM-driven pentest loop — FastAPI, no CLI/TUI (plan v2).

The GUI drives ``scan/orchestrator.scan_all_classes`` — the four-phase loop that
covers all 22 attack classes — and streams its phase events back over a poll.
LLM usage is proposal-only (recon profile / vuln-class priority / payload choice /
report narrative), every finding is ``run_oracle → is_violation → write_finding``,
and the orchestrator shares ``ReachabilityGraph`` / ``AuditLog`` / ``ScopeGuard``
(the same engine the headless entrypoint uses — no ScopeGuard bypass).
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import uuid
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from reachagent.execution.audit import AuditLog
from reachagent.graph.store import ReachabilityGraph
from reachagent.report.renderer import render_findings_markdown
from reachagent.scan.orchestrator import ScanEvent, scan_all_classes

app = FastAPI(title="ReachAgent GUI", version="2.0")
_scans: dict[str, dict[str, Any]] = {}  # id → {status, phase, events, findings, report_md, error}


def _event_dict(e: ScanEvent) -> dict[str, Any]:
    return {"phase": e.phase, "kind": e.kind, "message": e.message, "details": e.details}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    try:
        return (app.static_path / "index.html").read_text()  # type: ignore[attr-defined,no-any-return]
    except Exception:
        return "<h1>ReachAgent GUI</h1><p>static/index.html missing</p>"


def _opt_str(value: Any) -> str | None:
    """Coerce an optional JSON string: ``None``/empty → ``None``, never the literal "None"."""
    return str(value).strip() if value else None


@app.post("/api/scan")
async def start_scan(payload: dict[str, Any]) -> JSONResponse:
    target = str(payload.get("target", "") or "").strip()
    in_scope = str(payload.get("in_scope", "") or "").strip() or target
    out_of_scope = _opt_str(payload.get("out_of_scope"))
    use_llm = bool(payload.get("use_llm", False))
    max_attempts = int(payload.get("max_attempts", 20))
    identities_path = _opt_str(payload.get("identities_path"))
    if not target:
        return JSONResponse({"error": "target required"}, status_code=400)
    scan_id = uuid.uuid4().hex[:8]
    _scans[scan_id] = {
        "target": target,
        "status": "running",
        "phase": "recon",
        "events": [],
        "findings": [],
        "report_md": "",
    }
    asyncio.create_task(
        _run_scan(scan_id, target, in_scope, out_of_scope, use_llm, max_attempts, identities_path)
    )
    return JSONResponse({"scan_id": scan_id, "status": "running"})


def _load_identities(path: str | None) -> tuple[Any | None, str | None]:
    """Seed an IdentityStore from a GUI-provided secrets YAML (or env); ``(None, None)`` if unset."""
    from reachagent.identity.store import IdentityStore

    if path:
        try:
            return IdentityStore.from_secrets_file(path), None
        except Exception as exc:  # noqa: BLE001 — bad identities file must not kill the scan
            return None, f"identities file error: {exc}"
    try:
        return IdentityStore.from_env(), None
    except Exception:  # noqa: BLE001 — no identities configured is a valid unauth scan
        return None, None


async def _run_scan(
    scan_id: str,
    target: str,
    in_scope: str,
    out_of_scope: str | None,
    use_llm: bool,
    max_attempts: int,
    identities_path: str | None,
) -> None:
    # LLM helpers are flag-gated inside the engine; a per-scan env patch (restored in
    # finally) enables ALL the proposal-only proposers — recon profile, vuln-class
    # priority per endpoint, and payload-choice ranking — without leaking beyond this
    # task. Each is allowlist-validated; the deterministic engine still confirms.
    env_patch = (
        {
            "REACHAGENT_RECON_PROFILE": "1",
            "REACHAGENT_VULN_TUNING": "1",
            "REACHAGENT_PAYLOAD_TUNING": "1",
        }
        if use_llm
        else {}
    )
    old = {k: os.environ.get(k) for k in env_patch}
    try:
        for k, v in env_patch.items():
            os.environ[k] = v
        identities, id_error = _load_identities(identities_path)
        if id_error:
            _scans[scan_id].update({"status": "error", "error": id_error})
            return
        # Live references: the GUI polls these SAME objects while the scan writes them,
        # so the live view streams the real audit log + graph state + phase events.
        graph = ReachabilityGraph()
        audit = AuditLog()
        events: list[ScanEvent] = []
        _scans[scan_id].update({"graph": graph, "audit": audit, "events": events})

        def _run() -> dict[str, Any]:
            return scan_all_classes(
                base_url=target,
                in_scope=in_scope,
                out_of_scope=out_of_scope,
                max_attempts=max_attempts,
                identities=identities,
                events=events,
                graph=graph,
                audit=audit,
            )

        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            await loop.run_in_executor(pool, _run)

        md = render_findings_markdown(graph)
        if use_llm:
            from reachagent.report.llm_report import generate_llm_report

            md = generate_llm_report(graph)
        _scans[scan_id].update({"status": "done", "phase": "report", "report_md": md})
    except Exception as exc:  # noqa: BLE001 — a scan failure is surfaced, not swallowed
        _scans[scan_id].update({"status": "error", "error": str(exc)})
    finally:
        for ok, ov in old.items():
            if ov is not None:
                os.environ[ok] = ov
            else:
                os.environ.pop(ok, None)


def _audit_rows(audit: AuditLog | None) -> list[dict[str, Any]]:
    """The live audit tail — one row per execution-layer action (real data)."""
    if audit is None:
        return []
    return [
        {
            "timestamp": e.timestamp.isoformat(timespec="seconds"),
            "identity": e.identity,
            "method": e.method,
            "target": e.target,
            "outcome": e.outcome,
        }
        for e in audit.entries[-200:]
    ]


def _graph_snapshot(graph: ReachabilityGraph | None) -> dict[str, Any]:
    """A live snapshot of the reachability graph the scan is building (real data)."""
    if graph is None:
        return {"counts": {}, "hosts": [], "endpoints": []}
    return {
        "counts": {
            "hosts": len(graph.hosts()),
            "services": len(graph.services()),
            "endpoints": len(graph.endpoints()),
            "parameters": sum(len(graph.parameters_of(ep)) for ep, _ in graph.endpoints()),
            "findings": len(graph.findings()),
        },
        "hosts": [h.address for h_id, h in graph.hosts()[:20]],
        "endpoints": [
            {
                "method": ep.method,
                "path": ep.path,
                "sinks": [
                    p.inferred_sink_type.value if p.inferred_sink_type is not None else ""
                    for _pn, p in graph.parameters_of(ep_id)
                ],
            }
            for ep_id, ep in graph.endpoints()[:40]
        ],
    }


def _chain_label(graph: ReachabilityGraph, node: str) -> str:
    """Short human label for a chain-path node (real graph node ids → class/kind)."""
    if node.startswith("finding:"):
        parts = node.split(":", 2)
        return parts[1] if len(parts) > 1 else node
    if node.startswith("session:"):
        return "session"
    if node.startswith("identity:"):
        return node.split(":", 1)[1] if ":" in node else node
    return node


def _chains_for(graph: ReachabilityGraph, finding_node: str) -> list[dict[str, Any]]:
    """The connected multi-hop paths from ``finding_node`` over chain edges (real data).

    Each path is the ``chain_paths`` result: a run of ``Finding →enables→ Finding`` and
    ``Finding →derived_credential→ Session|Identity`` edges, with the edge kind labelled
    so the frontend can draw the chain (enables vs credential-yield).
    """
    derived = set(graph.derived_credential_edges())
    out: list[dict[str, Any]] = []
    for path in graph.chain_paths(finding_node):
        kinds: list[str] = []
        for i in range(len(path) - 1):
            edge = (path[i], path[i + 1])
            kinds.append("derived_credential" if edge in derived else "enables")
        out.append({"nodes": [_chain_label(graph, n) for n in path], "kinds": kinds})
    return out


def _finding_rows(graph: ReachabilityGraph | None) -> list[dict[str, Any]]:
    if graph is None:
        return []
    rows = []
    for fid, f in graph.findings():
        rows.append(
            {
                "finding_id": fid,
                "vuln_class": getattr(f, "vuln_class", ""),
                "severity": getattr(f, "severity", ""),
                "oracle_used": getattr(f, "oracle_used", ""),
                "evidence_ref": getattr(f, "evidence_ref", ""),
                "status": getattr(getattr(f, "status", ""), "value", str(getattr(f, "status", ""))),
                "metadata": dict(getattr(f, "metadata", {}) or {}),
                "chain_precondition": (getattr(f, "metadata", {}) or {}).get("chain_precondition"),
                "chains": _chains_for(graph, fid),
            }
        )
    return rows


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str) -> JSONResponse:
    data = _scans.get(scan_id)
    if not data:
        return JSONResponse({"error": "not found"}, status_code=404)
    graph: ReachabilityGraph | None = data.get("graph")
    return JSONResponse(
        {
            "scan_id": scan_id,
            "target": data.get("target"),
            "status": data.get("status"),
            "phase": data.get("phase"),
            "events": [_event_dict(e) for e in data.get("events", [])],
            "audit": _audit_rows(data.get("audit")),
            "graph": _graph_snapshot(graph),
            "findings": _finding_rows(graph),
            "report_md": data.get("report_md", ""),
            "error": data.get("error"),
        }
    )


@app.get("/api/report/{scan_id}")
def get_report(scan_id: str) -> JSONResponse:
    data = _scans.get(scan_id)
    if not data or "graph" not in data:
        return JSONResponse({"error": "not found or not done"}, status_code=404)
    from reachagent.report.llm_report import generate_llm_report

    graph: ReachabilityGraph = data["graph"]
    md = generate_llm_report(graph)
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
