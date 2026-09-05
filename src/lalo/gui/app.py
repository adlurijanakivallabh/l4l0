"""L4L0 GUI application: scan launch + live WebSocket event stream + SPA."""

from __future__ import annotations

import asyncio
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from ..core.logging import get_logger

_log = get_logger("lalo.gui")

# The scan function signature: given the manager + scan_id, run the scan and push
# events. Injectable so the GUI is testable without a live LLM.
ScanFn = Callable[["ScanManager", str], None]


@dataclass
class ScanState:
    scan_id: str
    targets: list[str]
    objective: str
    status: str = "pending"
    events: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None


class ScanManager:
    def __init__(self, scan_fn: ScanFn | None = None) -> None:
        self._scans: dict[str, ScanState] = {}
        self._lock = threading.Lock()
        self.scan_fn: ScanFn = scan_fn or _default_scan_fn

    def create(self, targets: list[str], objective: str) -> ScanState:
        scan_id = uuid.uuid4().hex[:12]
        state = ScanState(scan_id=scan_id, targets=targets, objective=objective)
        with self._lock:
            self._scans[scan_id] = state
        return state

    def get(self, scan_id: str) -> ScanState | None:
        with self._lock:
            return self._scans.get(scan_id)

    def push_event(self, scan_id: str, event: dict[str, Any]) -> None:
        with self._lock:
            state = self._scans.get(scan_id)
            if state is None:
                return
            event = {"seq": len(state.events), **event}
            state.events.append(event)

    def add_finding(self, scan_id: str, finding: dict[str, Any]) -> None:
        with self._lock:
            state = self._scans.get(scan_id)
            if state is not None:
                state.findings.append(finding)
        self.push_event(scan_id, {"type": "finding", "finding": finding})

    def set_status(self, scan_id: str, status: str, *, error: str | None = None) -> None:
        with self._lock:
            state = self._scans.get(scan_id)
            if state is not None:
                state.status = status
                state.error = error
        self.push_event(scan_id, {"type": "status", "status": status, "error": error})

    def events_since(self, scan_id: str, cursor: int) -> list[dict[str, Any]]:
        with self._lock:
            state = self._scans.get(scan_id)
            return list(state.events[cursor:]) if state else []

    def start(self, scan_id: str) -> None:
        def _run() -> None:
            self.set_status(scan_id, "running")
            try:
                self.scan_fn(self, scan_id)
            except Exception as exc:  # noqa: BLE001 - surfaced as an error event, never crashes the server
                _log.warning("scan %s failed: %s", scan_id, type(exc).__name__)
                self.set_status(scan_id, "error", error=type(exc).__name__)
                return
            state = self.get(scan_id)
            if state is not None and state.status == "running":
                self.set_status(scan_id, "completed")

        threading.Thread(target=_run, daemon=True).start()


def _default_scan_fn(manager: ScanManager, scan_id: str) -> None:
    """Real scan: build a router from settings and run the agent pipeline."""
    from ..core.config import load_settings
    from ..core.providers import build_router
    from ..scan import run_scan

    state = manager.get(scan_id)
    if state is None:
        return
    router = build_router(load_settings())
    manager.push_event(scan_id, {"type": "log", "line": "starting scan"})
    result = run_scan(targets=state.targets, objective=state.objective, router=router)
    for finding in result.findings:
        manager.add_finding(
            scan_id,
            {
                "id": finding.id,
                "title": finding.title,
                "vuln_class": finding.vuln_class,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "target": finding.target,
            },
        )
    manager.push_event(scan_id, {"type": "log", "line": f"done: {result.stop_reason}"})


_INDEX_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>L4L0</title>
<style>body{font-family:system-ui;margin:0;background:#0b0e14;color:#cdd6f4}
header{padding:12px 16px;background:#11151f;font-weight:700;letter-spacing:2px}
main{padding:16px;display:grid;grid-template-columns:1fr 1fr;gap:16px}
input,button,textarea{background:#1a1f2b;color:#cdd6f4;border:1px solid #2a3040;padding:8px;border-radius:6px}
#log{font-family:ui-monospace,monospace;white-space:pre-wrap;background:#05070a;padding:10px;height:60vh;overflow:auto;border-radius:6px}
.f{border-left:3px solid #f38ba8;padding:6px 10px;margin:6px 0;background:#151a24;border-radius:4px}
.sev-critical{border-color:#f38ba8}.sev-high{border-color:#fab387}.sev-medium{border-color:#f9e2af}.sev-low{border-color:#a6e3a1}</style>
</head><body><header>L4L0</header><main>
<section><h3>Launch</h3>
<div><input id="targets" placeholder="targets (comma-separated)" style="width:100%"></div>
<div style="margin-top:8px"><input id="objective" placeholder="objective" style="width:100%"></div>
<button style="margin-top:8px" onclick="start()">Start scan</button>
<h3>Findings <span id="count"></span></h3><div id="findings"></div></section>
<section><h3>Live</h3><div id="log"></div></section></main>
<script>
let ws;
async function start(){
 const targets=document.getElementById('targets').value.split(',').map(s=>s.trim()).filter(Boolean);
 const objective=document.getElementById('objective').value;
 const r=await fetch('/api/scan',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({targets,objective})});
 const {scan_id}=await r.json(); connect(scan_id);
}
function connect(id){
 const log=document.getElementById('log'), findings=document.getElementById('findings');
 log.textContent=''; findings.innerHTML=''; let n=0;
 ws=new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/ws/'+id);
 ws.onmessage=e=>{const ev=JSON.parse(e.data);
  if(ev.type==='finding'){const f=ev.finding;n++;document.getElementById('count').textContent='('+n+')';
   const d=document.createElement('div');d.className='f sev-'+f.severity;
   d.textContent='['+f.severity.toUpperCase()+' '+(f.confidence??'?')+'] '+f.title+' — '+f.target;findings.appendChild(d);}
  else{log.textContent+=(ev.line||JSON.stringify(ev))+'\\n';log.scrollTop=log.scrollHeight;}
 };
}
</script></body></html>"""


def build_app(manager: ScanManager | None = None) -> FastAPI:
    app = FastAPI(title="L4L0")
    mgr = manager or ScanManager()
    app.state.manager = mgr

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return _INDEX_HTML

    @app.post("/api/scan")
    def start_scan(body: dict[str, Any]) -> dict[str, str]:
        targets = [str(t) for t in body.get("targets", []) if str(t).strip()]
        objective = str(body.get("objective", ""))
        state = mgr.create(targets, objective)
        mgr.start(state.scan_id)
        return {"scan_id": state.scan_id}

    @app.get("/api/scan/{scan_id}")
    def scan_status(scan_id: str) -> dict[str, Any]:
        state = mgr.get(scan_id)
        if state is None:
            return {"error": "not_found"}
        return {
            "scan_id": state.scan_id,
            "status": state.status,
            "findings": state.findings,
            "event_count": len(state.events),
            "error": state.error,
        }

    @app.websocket("/ws/{scan_id}")
    async def stream(websocket: WebSocket, scan_id: str) -> None:
        await websocket.accept()
        cursor = int(websocket.query_params.get("cursor", "0"))
        try:
            while True:
                for event in mgr.events_since(scan_id, cursor):
                    await websocket.send_json(event)
                    cursor += 1
                state = mgr.get(scan_id)
                if state is not None and state.status in ("completed", "error"):
                    if cursor >= len(state.events):
                        break
                await asyncio.sleep(0.05)
        except WebSocketDisconnect:
            return

    return app


def main() -> None:
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(description="L4L0 GUI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    uvicorn.run(build_app(), host=args.host, port=args.port)
