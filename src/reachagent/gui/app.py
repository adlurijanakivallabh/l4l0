"""Web GUI for the full LLM-driven assessment loop — FastAPI, no CLI/TUI.

The GUI drives ``scan/orchestrator.scan_all_classes`` — the validated multi-phase
loop that covers all 23 attack classes — and streams its phase events back over a poll.
LLM usage is proposal-only (recon profile / vuln-class priority / payload choice /
report narrative), every finding is ``run_oracle → is_violation → write_finding``,
and the orchestrator shares ``ReachabilityGraph`` / ``AuditLog`` / ``ScopeGuard``
(the same engine the headless entrypoint uses — no ScopeGuard bypass).
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import uuid
from contextvars import copy_context
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from reachagent.execution.audit import AuditLog
from reachagent.graph.store import ReachabilityGraph
from reachagent.report.renderer import render_findings_markdown
from reachagent.scan.orchestrator import ScanEvent, scan_all_classes

app = FastAPI(title="ReachAgent GUI", version="2.0")
_scans: dict[str, dict[str, Any]] = {}  # id → {status, phase, events, findings, report_md, error}
_providers_path = Path(__file__).resolve().parents[3] / "config" / "providers.json"


def _load_providers() -> list[dict[str, Any]]:
    """Named provider configs for the settings panel."""
    if _providers_path.exists():
        try:
            data = json.loads(_providers_path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except Exception:  # noqa: BLE001 — corrupt file = empty list, never crash
            return []
    return []


def _save_providers(providers: list[dict[str, Any]]) -> None:
    _providers_path.parent.mkdir(parents=True, exist_ok=True)
    _providers_path.write_text(json.dumps(providers, indent=2), encoding="utf-8")


@app.get("/api/providers")
def list_providers() -> JSONResponse:
    """All named provider configurations + the server-default env summary."""
    import os

    env_default = {
        "provider": os.environ.get("REACHAGENT_LLM_PROVIDER", ""),
        "base_url": os.environ.get("REACHAGENT_LLM_BASE_URL", ""),
        "model": os.environ.get("REACHAGENT_LLM_MODEL", ""),
        "api_style": os.environ.get("REACHAGENT_LLM_API_STYLE", "chat_completions"),
        "has_key": bool(os.environ.get("REACHAGENT_LLM_API_KEY", "")),
        "name": "(server default)",
    }
    providers = [
        {k: p.get(k, "") for k in ("id", "name", "provider", "base_url", "model", "api_style")}
        for p in _load_providers()
    ]
    return JSONResponse({"default": env_default, "providers": providers})


@app.post("/api/providers")
async def save_provider(payload: dict[str, Any]) -> JSONResponse:
    """Create or update one named provider config. Key stored server-side only."""
    name = str(payload.get("name", "")).strip()
    provider_type = str(payload.get("provider", "")).strip()
    api_key = str(payload.get("api_key", "")).strip()
    base_url = str(payload.get("base_url", "")).strip()
    model = str(payload.get("model", "")).strip()
    api_style = str(payload.get("api_style", "chat_completions")).strip()
    provider_id = payload.get("id")
    if not name or not provider_type:
        return JSONResponse({"error": "name and provider are required"}, status_code=400)
    if provider_type not in ("openai-compatible", "deepseek", "openai"):
        return JSONResponse(
            {"error": f"unsupported provider type {provider_type!r}"}, status_code=400
        )
    if api_style not in ("chat_completions", "responses"):
        return JSONResponse({"error": f"unsupported api_style {api_style!r}"}, status_code=400)
    if provider_type == "openai-compatible" and (not base_url or not model):
        return JSONResponse(
            {"error": "base_url and model are required for openai-compatible"},
            status_code=400,
        )
    providers = _load_providers()
    entry = {
        "id": provider_id or uuid.uuid4().hex[:8],
        "name": name,
        "provider": provider_type,
        "api_key": api_key,
        "base_url": base_url,
        "model": model,
        "api_style": api_style,
    }
    found = False
    for i, existing in enumerate(providers):
        if existing.get("id") == entry["id"]:
            # Keep old key when the form resubmits the placeholder.
            if not api_key and existing.get("api_key"):
                entry["api_key"] = existing["api_key"]
            providers[i] = entry
            found = True
            break
    if not found:
        providers.append(entry)
    _save_providers(providers)
    return JSONResponse({"ok": True, "id": entry["id"]})


@app.delete("/api/providers/{provider_id}")
def delete_provider(provider_id: str) -> JSONResponse:
    providers = _load_providers()
    remaining = [p for p in providers if p.get("id") != provider_id]
    if len(remaining) == len(providers):
        return JSONResponse({"error": "not found"}, status_code=404)
    _save_providers(remaining)
    return JSONResponse({"ok": True})


@app.post("/api/providers/{provider_id}/test")
def test_provider(provider_id: str) -> JSONResponse:
    """Send a tiny prompt through the saved config (connection test)."""
    from reachagent.llm.client import OpenAICompatibleClient

    entry = next((p for p in _load_providers() if p.get("id") == provider_id), None)
    if entry is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    try:
        client = OpenAICompatibleClient(
            provider=entry["provider"],
            api_key=entry.get("api_key") or None,
            base_url=entry.get("base_url") or None,
            model=entry.get("model") or None,
            api_style=entry.get("api_style") or None,
            timeout=30.0,
        )
    except Exception as exc:  # noqa: BLE001 — config errors surface to the operator
        return JSONResponse({"ok": False, "error": str(exc)})
    try:
        out = client.complete("Reply with exactly: ok", max_tokens=1024)
        return JSONResponse({"ok": True, "reply": out.strip()[:100]})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": str(exc)[:300]})
    finally:
        client.close()


def _event_dict(e: ScanEvent) -> dict[str, Any]:
    """Serialize one orchestrator event for the GUI (reasoning loop included)."""
    return {"phase": e.phase, "kind": e.kind, "message": e.message, "details": e.details}


@app.get("/api/scan/{scan_id}/reasoning")
def get_reasoning(scan_id: str) -> JSONResponse:
    """The LLM reasoning stream: plan rationale, per-phase decisions, transport
    and tool picks — every proposal the loop made and why, in order."""
    data = _scans.get(scan_id)
    if not data:
        return JSONResponse({"error": "not found"}, status_code=404)
    events = data.get("events", [])
    reasoning_events = [
        _event_dict(e)
        for e in events
        if e.kind in ("plan", "step") or "LLM" in e.message or "decision" in e.message.lower()
    ]
    return JSONResponse({"scan_id": scan_id, "reasoning": reasoning_events})


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    try:
        return (app.static_path / "index.html").read_text()  # type: ignore[attr-defined,no-any-return]
    except Exception:
        return "<h1>ReachAgent GUI</h1><p>static/index.html missing</p>"


def _opt_str(value: Any) -> str | None:
    """Coerce an optional JSON string: ``None``/empty → ``None``, never the literal "None"."""
    return str(value).strip() if value else None


def _validate_named_provider(config: dict[str, str]) -> None:
    """Validate a saved provider without sending a request or mutating env."""
    from reachagent.llm.client import OpenAICompatibleClient

    api_key = config.get("REACHAGENT_LLM_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("API key is required for the selected named provider")
    client = OpenAICompatibleClient(
        provider=config.get("REACHAGENT_LLM_PROVIDER", ""),
        api_key=api_key,
        base_url=config.get("REACHAGENT_LLM_BASE_URL", ""),
        model=config.get("REACHAGENT_LLM_MODEL", ""),
        api_style=config.get("REACHAGENT_LLM_API_STYLE", "chat_completions"),
        timeout=30.0,
    )
    client.close()


@app.post("/api/scan")
async def start_scan(payload: dict[str, Any]) -> JSONResponse:
    target = str(payload.get("target", "") or "").strip()
    in_scope = str(payload.get("in_scope", "") or "").strip() or target
    out_of_scope = _opt_str(payload.get("out_of_scope"))
    use_llm = payload.get("use_llm") is True
    llm_provider_raw = _opt_str(payload.get("llm_provider"))
    # A single saved provider is the unambiguous GUI default.  The launch form
    # sends an empty value when the browser still has "Server default" selected;
    # do not route that case through the legacy Anthropic default.
    if not llm_provider_raw:
        from reachagent.llm.runtime import selected_provider

        if not selected_provider():
            saved = [p for p in _load_providers() if str(p.get("id", "")).strip()]
            if len(saved) == 1:
                llm_provider_raw = f"named:{saved[0]['id']}"
    llm_provider: str | None = None
    named_overrides: dict[str, str] | None = None
    if llm_provider_raw and llm_provider_raw.startswith("named:"):
        named_id = llm_provider_raw[len("named:") :]
        entry = next((p for p in _load_providers() if p.get("id") == named_id), None)
        if entry is None:
            return JSONResponse(
                {"error": f"unknown provider id {named_id!r}", "code": "llm_provider_unavailable"},
                status_code=400,
            )
        named_overrides = {
            "REACHAGENT_LLM_PROVIDER": entry["provider"],
            "REACHAGENT_LLM_API_KEY": entry.get("api_key", ""),
            "REACHAGENT_LLM_BASE_URL": entry.get("base_url", ""),
            "REACHAGENT_LLM_MODEL": entry.get("model", ""),
            "REACHAGENT_LLM_API_STYLE": entry.get("api_style", "chat_completions"),
        }
        llm_provider = entry["provider"]
    else:
        llm_provider = llm_provider_raw
    operator_prompt = _opt_str(payload.get("prompt"))
    try:
        max_attempts = max(1, min(int(payload.get("max_attempts", 20)), 200))
    except (TypeError, ValueError):
        return JSONResponse(
            {"error": "max_attempts must be an integer", "code": "invalid_input"}, status_code=400
        )
    identities_path = _opt_str(payload.get("identities_path"))
    if not target:
        return JSONResponse({"error": "target required"}, status_code=400)
    if not use_llm:
        return JSONResponse(
            {
                "error": "LLM execution is required for GUI scans",
                "code": "llm_required",
            },
            status_code=400,
        )
    try:
        from reachagent.llm.client import require_provider_config

        if named_overrides is not None:
            _validate_named_provider(named_overrides)
        else:
            require_provider_config(llm_provider)
    except Exception as exc:  # noqa: BLE001 — fail before creating a scan
        return JSONResponse(
            {"error": str(exc), "code": "llm_provider_unavailable"},
            status_code=400,
        )
    scan_id = uuid.uuid4().hex[:8]
    _scans[scan_id] = {
        "target": target,
        "operator_prompt": operator_prompt,
        "status": "running",
        "phase": "recon",
        "events": [],
        "findings": [],
        "report_md": "",
    }
    asyncio.create_task(
        _run_scan(
            scan_id,
            target,
            in_scope,
            out_of_scope,
            use_llm,
            max_attempts,
            identities_path,
            llm_provider,
            operator_prompt,
            named_overrides,
        )
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
    llm_provider: str | None = None,
    operator_prompt: str | None = None,
    named_overrides: dict[str, str] | None = None,
) -> None:
    import os

    from reachagent.llm.runtime import override

    saved: dict[str, str | None] = {}
    if named_overrides:
        for key, value in named_overrides.items():
            saved[key] = os.environ.get(key)
            os.environ[key] = value
    try:
        with override(enabled=use_llm, provider=llm_provider, required=use_llm):
            await _run_scan_body(
                scan_id,
                target,
                in_scope,
                out_of_scope,
                use_llm,
                max_attempts,
                identities_path,
                operator_prompt,
            )
    finally:
        for key, old_value in saved.items():
            if old_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old_value


async def _run_scan_body(
    scan_id: str,
    target: str,
    in_scope: str,
    out_of_scope: str | None,
    use_llm: bool,
    max_attempts: int,
    identities_path: str | None,
    operator_prompt: str | None,
) -> None:
    try:
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
                operator_prompt=operator_prompt,
                require_llm=use_llm,
                live_recon=True,
            )

        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            await loop.run_in_executor(pool, copy_context().run, _run)

        md = render_findings_markdown(graph)
        if use_llm:
            from reachagent.report.llm_report import generate_llm_report

            md = generate_llm_report(graph, operator_prompt=operator_prompt)
        events.append(
            ScanEvent(
                phase="report",
                kind="step",
                message="phase 4 complete — report generated from confirmed findings",
                details={"findings": len(graph.findings())},
            )
        )
        _scans[scan_id].update({"status": "done", "phase": "report", "report_md": md})
    except Exception as exc:  # noqa: BLE001 — a scan failure is surfaced, not swallowed
        from reachagent.identity.login import LoginError, redact_message

        if isinstance(exc, LoginError):
            _scans[scan_id].update(
                {"status": "blocked", "phase": "auth", "error": redact_message(exc)}
            )
        else:
            _scans[scan_id].update({"status": "error", "error": redact_message(exc)})


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
            "sessions": len(graph.sessions()),
        },
        "hosts": [h.address for h_id, h in graph.hosts()[:20]],
        "sessions": [
            {
                "id": sid,
                "identity": session.identity_ref,
                "auth_kind": session.auth_kind,
                "expires_at": session.expires_at,
                "live": session.live,
            }
            for sid, session in graph.sessions()[:20]
        ],
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


def _surface_snapshot(graph: ReachabilityGraph | None) -> dict[str, Any]:
    """Return the real Host → Service/Endpoint → Parameter surface tree."""
    if graph is None:
        return {"hosts": [], "orphan_endpoints": []}
    endpoint_by_host: dict[str, list[tuple[str, Any]]] = {}
    for host_id, endpoint_id in graph.resolves_to_edges():
        try:
            endpoint_by_host.setdefault(host_id, []).append(
                (endpoint_id, graph.endpoint(endpoint_id))
            )
        except (KeyError, TypeError):
            continue

    def endpoint_row(endpoint_id: str, endpoint: Any) -> dict[str, Any]:
        return {
            "id": endpoint_id,
            "method": endpoint.method,
            "path": endpoint.path,
            "content_type": endpoint.content_type,
            "technology": endpoint.technology,
            "access_restricted": endpoint.access_restricted,
            "parameters": [
                {
                    "id": param_id,
                    "name": param.name,
                    "location": param.location,
                    "inferred_sink_type": (
                        param.inferred_sink_type.value
                        if param.inferred_sink_type is not None
                        else None
                    ),
                }
                for param_id, param in graph.parameters_of(endpoint_id)
            ],
        }

    hosts: list[dict[str, Any]] = []
    for host_id, host in graph.hosts():
        hosts.append(
            {
                "id": host_id,
                "address": host.address,
                "hostname": host.hostname,
                "source": host.source,
                "technology": host.technology,
                "detected_version": host.detected_version,
                "services": [
                    {
                        "id": service_id,
                        "port": service.port,
                        "protocol": service.protocol,
                        "service_name": service.service_name,
                        "banner": service.banner,
                        "detected_version": service.detected_version,
                        "source": service.source,
                    }
                    for service_id, service in graph.services_of(host_id)
                ],
                "endpoints": [
                    endpoint_row(endpoint_id, endpoint)
                    for endpoint_id, endpoint in endpoint_by_host.get(host_id, [])
                ],
            }
        )
    attached = {endpoint_id for values in endpoint_by_host.values() for endpoint_id, _ in values}
    orphan_endpoints = [
        endpoint_row(endpoint_id, endpoint)
        for endpoint_id, endpoint in graph.endpoints()
        if endpoint_id not in attached
    ]
    return {"hosts": hosts, "orphan_endpoints": orphan_endpoints}


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
    events = data.get("events", [])
    phase = data.get("phase")
    if data.get("status") == "running" and events:
        phase = events[-1].phase
    return JSONResponse(
        {
            "scan_id": scan_id,
            "target": data.get("target"),
            "status": data.get("status"),
            "phase": phase,
            "events": [_event_dict(e) for e in events],
            "audit": _audit_rows(data.get("audit")),
            "graph": _graph_snapshot(graph),
            "findings": _finding_rows(graph),
            "report_md": data.get("report_md", ""),
            "error": data.get("error"),
        }
    )


@app.get("/api/scan/{scan_id}/surface")
def get_surface(scan_id: str) -> JSONResponse:
    """Read-only Host/Service/Endpoint/Parameter graph slice for the GUI."""
    data = _scans.get(scan_id)
    if not data or "graph" not in data:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"scan_id": scan_id, **_surface_snapshot(data.get("graph"))})


@app.get("/api/scan/{scan_id}/audit")
def get_audit(scan_id: str, limit: int = 200) -> JSONResponse:
    """Read-only bounded audit tail; the full execution log stays server-side."""
    data = _scans.get(scan_id)
    if not data:
        return JSONResponse({"error": "not found"}, status_code=404)
    limit = max(1, min(limit, 1000))
    return JSONResponse({"scan_id": scan_id, "entries": _audit_rows(data.get("audit"))[-limit:]})


@app.get("/api/scan/{scan_id}/chains")
def get_chains(scan_id: str) -> JSONResponse:
    """Return connected chain paths for the real confirmed findings."""
    data = _scans.get(scan_id)
    if not data or "graph" not in data:
        return JSONResponse({"error": "not found"}, status_code=404)
    graph: ReachabilityGraph = data["graph"]
    return JSONResponse(
        {
            "scan_id": scan_id,
            "chains": [
                {"finding_id": finding_id, "paths": _chains_for(graph, finding_id)}
                for finding_id, finding in graph.findings()
                if getattr(getattr(finding, "status", None), "value", "") == "confirmed_violation"
            ],
        }
    )


@app.get("/api/report/{scan_id}")
def get_report(scan_id: str) -> JSONResponse:
    data = _scans.get(scan_id)
    if not data or "graph" not in data:
        return JSONResponse({"error": "not found or not done"}, status_code=404)
    # Phase 4 generates the report inside the strict scan runtime.  Serve that
    # stored result; do not re-run a provider call (or a deterministic fallback)
    # from a later request outside the scan context.
    report_md = data.get("report_md")
    if not isinstance(report_md, str) or not report_md:
        return JSONResponse({"error": "report not ready"}, status_code=409)
    return JSONResponse({"scan_id": scan_id, "report_md": report_md})


def _report_html(report_md: str) -> str:
    """A minimal self-contained HTML export of the Phase 4 report (narrative + table)."""
    import html as _html

    body = _html.escape(report_md)
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>ReachAgent report</title>"
        "<style>body{font-family:ui-monospace,Menlo,monospace;max-width:880px;margin:2rem auto;"
        "padding:0 1rem;line-height:1.55}table{border-collapse:collapse}th,td{border:1px solid #999;"
        "padding:.35rem .6rem;text-align:left}</style></head>"
        f"<body><h1>ReachAgent report</h1><pre style='white-space:pre-wrap'>{body}</pre></body></html>"
    )


@app.get("/api/scan/{scan_id}/export")
def export_report(scan_id: str, format: str = "markdown") -> Response:
    """Download the report in markdown/json/html — real data from the completed scan."""
    from reachagent.report.renderer import render_findings_json

    data = _scans.get(scan_id)
    if not data or "graph" not in data:
        return JSONResponse({"error": "not found or not done"}, status_code=404)
    graph: ReachabilityGraph = data["graph"]
    if format == "json":
        body, media, ext = render_findings_json(graph), "application/json", "json"
    else:
        report_md = data.get("report_md")
        if not isinstance(report_md, str) or not report_md:
            return JSONResponse({"error": "report not ready"}, status_code=409)
        if format == "html":
            body, media, ext = _report_html(report_md), "text/html", "html"
        else:
            body, media, ext = report_md, "text/markdown", "md"
    return Response(
        content=body,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="reachagent-report.{ext}"'},
    )


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
