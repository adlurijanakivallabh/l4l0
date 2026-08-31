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
import logging
import re
import threading
import uuid
from contextvars import copy_context
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from reachagent.execution.audit import AuditLog
from reachagent.graph.store import ReachabilityGraph
from reachagent.logging_setup import configure_file_logging
from reachagent.report.renderer import (
    build_evidence_index,
    compare_graphs,
    render_evidence_index_json,
    render_evidence_index_markdown,
    render_findings_json,
    render_findings_markdown,
    render_findings_sarif,
    render_report_bundle_json,
    render_report_html,
    sanitize_report_markdown,
)
from reachagent.scan.orchestrator import ScanEvent, scan_all_classes

app = FastAPI(title="ReachAgent GUI", version="2.0")
_log = logging.getLogger(__name__)
LOG_PATH = configure_file_logging()


class _ScanControl:
    """Composite cancel/pause token passed to ``scan_all_classes`` as ``cancel_check``.

    ``check_cancel()`` (agentic_loop.py) already treats anything with an
    ``is_set()`` method as a cancellation checkpoint, called at every phase
    boundary — the same checkpoints a pause needs. Blocking inside
    ``is_set()`` while paused gets pause/resume for free at every one of
    those checkpoints, with zero changes to the orchestrator/agentic-loop
    call sites. The block happens on the scan's own worker thread (run via
    a ThreadPoolExecutor), never the GUI's event loop, so pausing one scan
    never blocks the GUI itself.
    """

    def __init__(self) -> None:
        self.cancel_event = threading.Event()
        self.pause_event = threading.Event()

    def is_set(self) -> bool:
        while self.pause_event.is_set() and not self.cancel_event.is_set():
            self.cancel_event.wait(timeout=0.5)
        return self.cancel_event.is_set()


_scans: dict[str, dict[str, Any]] = {}  # id → {status, phase, events, findings, report_md, error}
_scan_lock = threading.RLock()
_MAX_EVENTS = 4_000
_PUBLIC_SECRET = re.compile(
    r"(?i)(?:bearer\s+[^\s,;}]+|[\"']?(?:password|passwd|secret|token|api[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|cookie|authorization)[\"']?"
    r"\s*[:=]\s*[\"']?(?:bearer\s+)?[^\s,;}\"']+)"
)
_EPHEMERAL_HANDLE = re.compile(r"\b(?:fire|browser|verdict)-[A-Za-z0-9._:-]+\b")
_providers_path = Path(__file__).resolve().parents[3] / "config" / "providers.json"


def _now() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat(timespec="seconds")


def _touch_scan(scan_id: str) -> None:
    with _scan_lock:
        data = _scans.get(scan_id)
        if data is not None:
            data["updated_at"] = _now()


class _EventBuffer(list[ScanEvent]):
    """Bounded event history that updates the owning scan heartbeat."""

    def __init__(self, touch: Any) -> None:
        super().__init__()
        self._touch = touch

    def append(self, event: ScanEvent) -> None:
        super().append(event)
        if len(self) > _MAX_EVENTS:
            del self[: len(self) - _MAX_EVENTS]
        self._touch()


def _scan_update(scan_id: str, **values: Any) -> None:
    with _scan_lock:
        data = _scans.get(scan_id)
        if data is None:
            return
        data.update(values)
        data["updated_at"] = _now()


def _lifecycle(status: object) -> str:
    """Normalize compatibility statuses to the explicit GUI lifecycle."""
    return {
        "queued": "queued",
        "running": "running",
        "paused": "paused",
        "blocked": "blocked",
        "done": "completed",
        "completed": "completed",
        "error": "failed",
        "failed": "failed",
        "cancelling": "running",
        "cancelled": "cancelled",
    }.get(str(status), "queued")


def _public_text(value: object, maximum: int = 500) -> str:
    text = str(value).replace("\x00", "").replace("\n", " ").replace("\r", " ")
    text = _PUBLIC_SECRET.sub("<redacted>", text)
    text = _EPHEMERAL_HANDLE.sub("<opaque-handle>", text)
    return text[:maximum]


def _public_value(value: object, *, key: str = "", depth: int = 0) -> object:
    """Project graph/event metadata without secrets, raw bodies, or handles."""
    if depth > 4:
        return "<truncated>"
    lowered = key.lower()
    if any(
        word in lowered
        for word in (
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "cookie",
            "authorization",
        )
    ):
        return "<redacted>"
    if isinstance(value, dict):
        return {
            _public_text(name, 96): _public_value(item, key=str(name), depth=depth + 1)
            for name, item in list(value.items())[:80]
        }
    if isinstance(value, (list, tuple)):
        return [_public_value(item, key=key, depth=depth + 1) for item in list(value)[:80]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return _public_text(value) if isinstance(value, str) else value
    return _public_text(value)


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
    return {
        "phase": _public_text(e.phase, 64),
        "kind": _public_text(e.kind, 64),
        "message": _public_text(e.message, 800),
        "details": _public_value(e.details, key="details"),
    }


@app.get("/api/scan/{scan_id}/events")
def get_events(scan_id: str, after: int = 0, limit: int = 300) -> JSONResponse:
    """Return a bounded event delta for low-latency polling clients."""
    with _scan_lock:
        data = _scans.get(scan_id)
    if data is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    events = data.get("events", [])
    start = max(0, int(after))
    limit = max(1, min(limit, 1_000))
    selected = list(events[start : start + limit])
    return JSONResponse(
        {
            "scan_id": scan_id,
            "events": [_event_dict(event) for event in selected],
            "next": start + len(selected),
            "event_count": len(events),
            "lifecycle": _lifecycle(data.get("status", "queued")),
        }
    )


_NO_CACHE = {"Cache-Control": "no-store"}


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    # No-store: this file changes across GUI development iterations and a
    # stale cached copy silently diverges from what the server actually
    # serves — confusing to debug from either side. A local dev tool pays
    # nothing for always revalidating a few KB of HTML.
    try:
        content = (app.static_path / "index.html").read_text()  # type: ignore[attr-defined]
    except Exception:
        content = "<h1>ReachAgent GUI</h1><p>static/index.html missing</p>"
    return HTMLResponse(content=content, headers=_NO_CACHE)


@app.get("/static/app.js")
def app_js() -> Response:
    """Serve app.js without caching — same rationale as ``index()`` above."""
    try:
        content = (app.static_path / "app.js").read_text()  # type: ignore[attr-defined]
    except Exception:
        return Response(content="", media_type="application/javascript", status_code=404)
    return Response(
        content=content,
        media_type="application/javascript",
        headers=_NO_CACHE,
    )


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


def _resolve_llm_provider(
    payload: dict[str, Any],
) -> tuple[str | None, dict[str, str] | None, JSONResponse | None]:
    """Resolve which LLM provider config a request should use.

    A single saved provider is the unambiguous GUI default. Callers send an
    empty value when the browser still has "Server default" selected; an
    empty provider is now a clear "no provider configured" error, not a
    silent default, so try the single-saved-provider shortcut first. Returns
    ``(llm_provider, named_overrides, error_response)`` — ``error_response``
    is non-``None`` only for an explicitly-named but unknown provider id.
    """
    llm_provider_raw = _opt_str(payload.get("llm_provider"))
    if not llm_provider_raw:
        from reachagent.llm.runtime import selected_provider

        if not selected_provider():
            saved = [p for p in _load_providers() if str(p.get("id", "")).strip()]
            if len(saved) == 1:
                llm_provider_raw = f"named:{saved[0]['id']}"
    if llm_provider_raw and llm_provider_raw.startswith("named:"):
        named_id = llm_provider_raw[len("named:") :]
        entry = next((p for p in _load_providers() if p.get("id") == named_id), None)
        if entry is None:
            return (
                None,
                None,
                JSONResponse(
                    {
                        "error": f"unknown provider id {named_id!r}",
                        "code": "llm_provider_unavailable",
                    },
                    status_code=400,
                ),
            )
        named_overrides = {
            "REACHAGENT_LLM_PROVIDER": entry["provider"],
            "REACHAGENT_LLM_API_KEY": entry.get("api_key", ""),
            "REACHAGENT_LLM_BASE_URL": entry.get("base_url", ""),
            "REACHAGENT_LLM_MODEL": entry.get("model", ""),
            "REACHAGENT_LLM_API_STYLE": entry.get("api_style", "chat_completions"),
        }
        return entry["provider"], named_overrides, None
    return llm_provider_raw, None, None


def _build_llm_client(llm_provider: str | None, named_overrides: dict[str, str] | None) -> Any:
    """Build a ready-to-use LLM client from a resolved provider selection."""
    from reachagent.llm.client import OpenAICompatibleClient

    if named_overrides is not None:
        return OpenAICompatibleClient(
            provider=named_overrides["REACHAGENT_LLM_PROVIDER"],
            api_key=named_overrides.get("REACHAGENT_LLM_API_KEY") or None,
            base_url=named_overrides.get("REACHAGENT_LLM_BASE_URL") or None,
            model=named_overrides.get("REACHAGENT_LLM_MODEL") or None,
            api_style=named_overrides.get("REACHAGENT_LLM_API_STYLE") or None,
            timeout=30.0,
        )
    return OpenAICompatibleClient(provider=llm_provider, timeout=30.0)


_INTENT_PROMPT = """Extract a penetration-test request from the operator's message into strict JSON.

Message:
\"\"\"
{message}
\"\"\"

Return ONLY a JSON object with exactly these keys, no prose, no markdown fences:
- "target": the base URL or hostname to test, e.g. "https://example.com" (empty string if none mentioned)
- "in_scope": comma-separated additional in-scope hosts beyond target (empty string if none)
- "credentials": a JSON list of objects {{"username": "...", "password": "...", "role": "user" or "admin"}} for every login/credential pair mentioned (empty list if none)
- "goal": one short sentence restating what the operator wants tested, in your own words (empty string if unclear)
"""


@app.post("/api/parse-intent")
def parse_intent(payload: dict[str, Any]) -> JSONResponse:
    """Best-effort free-text → ``{target, in_scope, credentials, goal}`` proposal.

    Never executes anything — this only proposes fields for the operator to
    review/edit in the chat UI before a scan is actually started via
    ``POST /api/scan``. An unconfigured provider or a flaky/malformed LLM
    reply degrades to an unextracted proposal (``extracted: false``), never
    a hard error the chat flow can't recover from.
    """
    message = str(payload.get("message", "") or "").strip()
    if not message:
        return JSONResponse({"error": "message required"}, status_code=400)
    empty = {"target": "", "in_scope": "", "credentials": [], "goal": message, "extracted": False}
    llm_provider, named_overrides, err = _resolve_llm_provider(payload)
    if err is not None:
        return err
    try:
        client = _build_llm_client(llm_provider, named_overrides)
    except Exception:  # noqa: BLE001 — no usable provider → unextracted proposal
        return JSONResponse(empty)
    try:
        result = client.propose_json(_INTENT_PROMPT.format(message=message), max_tokens=600)
    except Exception:  # noqa: BLE001 — a flaky/malformed LLM reply must not break the chat flow
        return JSONResponse(empty)
    finally:
        client.close()
    credentials: list[dict[str, str]] = []
    raw_credentials = result.get("credentials")
    if isinstance(raw_credentials, list):
        for row in raw_credentials[:20]:
            if not isinstance(row, dict):
                continue
            username = str(row.get("username", "") or "").strip()
            password = str(row.get("password", "") or "").strip()
            if not username or not password:
                continue
            role = str(row.get("role", "") or "user").strip().lower()
            credentials.append(
                {
                    "username": username,
                    "password": password,
                    "role": role if role in ("user", "admin") else "user",
                }
            )
    return JSONResponse(
        {
            "target": str(result.get("target", "") or "").strip(),
            "in_scope": str(result.get("in_scope", "") or "").strip(),
            "credentials": credentials,
            "goal": str(result.get("goal", "") or "").strip() or message,
            "extracted": True,
        }
    )


@app.post("/api/scan")
async def start_scan(payload: dict[str, Any]) -> JSONResponse:
    target = str(payload.get("target", "") or "").strip()
    in_scope = str(payload.get("in_scope", "") or "").strip() or target
    out_of_scope = _opt_str(payload.get("out_of_scope"))
    use_llm = payload.get("use_llm") is True
    llm_provider, named_overrides, err = _resolve_llm_provider(payload)
    if err is not None:
        return err
    operator_prompt = _opt_str(payload.get("prompt"))
    try:
        max_attempts = max(1, min(int(payload.get("max_attempts", 20)), 200))
    except (TypeError, ValueError):
        return JSONResponse(
            {"error": "max_attempts must be an integer", "code": "invalid_input"}, status_code=400
        )
    identities_path = _opt_str(payload.get("identities_path"))
    identities_inline_raw = payload.get("identities")
    identities_inline = (
        [row for row in identities_inline_raw if isinstance(row, dict)][:20]
        if isinstance(identities_inline_raw, list)
        else None
    ) or None
    # Opt-in recon tuning layers (surface priority / signal tools / transport) —
    # built and tested, but flag-gated off by default (§9); these three checkboxes
    # are the only place a scan can turn them on, since named_overrides above is
    # LLM-provider-only and there is no CLI/TUI left to export the env var by hand.
    tuning_overrides = {
        env_key: "1"
        for form_key, env_key in (
            ("surface_tuning", "REACHAGENT_SURFACE_TUNING"),
            ("signal_tuning", "REACHAGENT_SIGNAL_TUNING"),
            ("transport_tuning", "REACHAGENT_TRANSPORT_TUNING"),
        )
        if payload.get(form_key) is True
    }
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
    env_overrides = {**(named_overrides or {}), **tuning_overrides} or None
    scan_id = uuid.uuid4().hex[:8]
    with _scan_lock:
        _scans[scan_id] = {
            "target": target,
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
            "operator_prompt": operator_prompt,
            "status": "queued",
            "lifecycle": "queued",
            "phase": "recon",
            "events": [],
            "findings": [],
            "report_md": "",
            "created_at": _now(),
            "updated_at": _now(),
            "finished_at": None,
            "control": _ScanControl(),
            "cancel_requested": False,
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
            env_overrides,
            identities_inline,
        )
    )
    return JSONResponse({"scan_id": scan_id, "status": "queued", "lifecycle": "queued"})


def _scan_summary(scan_id: str, data: dict[str, Any]) -> dict[str, Any]:
    graph = data.get("graph")
    events = data.get("events", [])
    status = str(data.get("status", "queued"))
    latest = _event_dict(events[-1]) if events else None
    return {
        "scan_id": scan_id,
        "target": _public_text(data.get("target", ""), 300),
        "status": status,
        "lifecycle": _lifecycle(status),
        "phase": _public_text(data.get("phase", "recon"), 64),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
        "finished_at": data.get("finished_at"),
        "event_count": len(events) if isinstance(events, list) else 0,
        "latest_event": latest,
        "cancel_requested": bool(data.get("cancel_requested", False)),
        "can_cancel": status in {"queued", "running", "cancelling", "paused"},
        "can_pause": status == "running",
        "can_resume": status == "paused",
        "graph_available": isinstance(graph, ReachabilityGraph),
        "counts": _graph_snapshot(graph).get("counts", {}),
    }


@app.get("/api/scans")
def list_scans(limit: int = 50) -> JSONResponse:
    """Bounded real scan history for the workspace sidebar and refreshes."""
    limit = max(1, min(limit, 100))
    with _scan_lock:
        items = [_scan_summary(scan_id, data) for scan_id, data in _scans.items()]
    items.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return JSONResponse({"scans": items[:limit], "count": len(items)})


@app.post("/api/scan/{scan_id}/cancel")
def cancel_scan(scan_id: str) -> JSONResponse:
    """Request cooperative cancellation; the worker still owns execution gates."""
    with _scan_lock:
        data = _scans.get(scan_id)
        if data is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        status = str(data.get("status", "queued"))
        if status not in {"queued", "running", "cancelling", "paused"}:
            return JSONResponse(
                {"error": "scan is already terminal", "status": status}, status_code=409
            )
        control = data.get("control")
        if not isinstance(control, _ScanControl):
            return JSONResponse({"error": "scan cancellation unavailable"}, status_code=409)
        # A paused scan is blocked inside control.is_set() — clearing pause here
        # lets that wait loop observe the cancel_event on its very next check
        # instead of sleeping for up to another 0.5s.
        control.pause_event.clear()
        control.cancel_event.set()
        data["status"] = "cancelling"
        data["lifecycle"] = "running"
        data["cancel_requested"] = True
        data["updated_at"] = _now()
        events = data.get("events")
        if isinstance(events, list):
            events.append(
                ScanEvent(
                    phase=str(data.get("phase", "recon")),
                    kind="info",
                    message="Cancellation requested by operator",
                )
            )
    return JSONResponse(_scan_summary(scan_id, data))


@app.post("/api/scan/{scan_id}/pause")
def pause_scan(scan_id: str) -> JSONResponse:
    """Pause a running scan at its next phase-boundary checkpoint (resumable)."""
    with _scan_lock:
        data = _scans.get(scan_id)
        if data is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        status = str(data.get("status", "queued"))
        if status != "running":
            return JSONResponse({"error": "scan is not running", "status": status}, status_code=409)
        control = data.get("control")
        if not isinstance(control, _ScanControl):
            return JSONResponse({"error": "scan pause unavailable"}, status_code=409)
        control.pause_event.set()
        data["status"] = "paused"
        data["lifecycle"] = "paused"
        data["updated_at"] = _now()
        events = data.get("events")
        if isinstance(events, list):
            events.append(
                ScanEvent(
                    phase=str(data.get("phase", "recon")),
                    kind="info",
                    message="Paused by operator",
                )
            )
    return JSONResponse(_scan_summary(scan_id, data))


@app.post("/api/scan/{scan_id}/resume")
def resume_scan(scan_id: str) -> JSONResponse:
    """Resume a paused scan — the blocked worker thread picks up immediately."""
    with _scan_lock:
        data = _scans.get(scan_id)
        if data is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        if str(data.get("status", "queued")) != "paused":
            return JSONResponse({"error": "scan is not paused"}, status_code=409)
        control = data.get("control")
        if not isinstance(control, _ScanControl):
            return JSONResponse({"error": "scan resume unavailable"}, status_code=409)
        control.pause_event.clear()
        data["status"] = "running"
        data["lifecycle"] = "running"
        data["updated_at"] = _now()
        events = data.get("events")
        if isinstance(events, list):
            events.append(
                ScanEvent(
                    phase=str(data.get("phase", "recon")),
                    kind="info",
                    message="Resumed by operator",
                )
            )
    return JSONResponse(_scan_summary(scan_id, data))


def _load_identities(
    path: str | None, inline: list[dict[str, Any]] | None = None
) -> tuple[Any | None, str | None]:
    """Seed an IdentityStore from GUI-provided inline rows, a secrets YAML, or env.

    ``(None, None)`` means no identities configured — a valid unauthenticated scan.
    Inline rows (typed straight into the chat, never written to disk) take
    priority over a secrets-file path when both are somehow present.
    """
    from reachagent.identity.store import IdentityStore

    if inline:
        try:
            return IdentityStore.from_identities_list(inline), None
        except Exception as exc:  # noqa: BLE001 — bad inline identities must not kill the scan
            return None, f"identities error: {exc}"
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
    env_overrides: dict[str, str] | None = None,
    identities_inline: list[dict[str, Any]] | None = None,
) -> None:
    """``env_overrides`` merges LLM-provider config and the opt-in tuning-flag
    checkboxes into one plain os.environ save/set/restore for the scan's duration.
    """
    import os

    from reachagent.llm.runtime import override

    _scan_update(scan_id, status="running", lifecycle="running", phase="recon")
    saved: dict[str, str | None] = {}
    if env_overrides:
        for key, value in env_overrides.items():
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
                identities_inline,
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
    identities_inline: list[dict[str, Any]] | None = None,
) -> None:
    try:
        identities, id_error = _load_identities(identities_path, identities_inline)
        if id_error:
            _scan_update(
                scan_id,
                status="error",
                lifecycle="failed",
                error=_public_text(id_error, 500),
                finished_at=_now(),
            )
            return
        # Live references: the GUI polls these SAME objects while the scan writes them,
        # so the live view streams the real audit log + graph state + phase events.
        graph = ReachabilityGraph()
        audit = AuditLog()
        events = _EventBuffer(lambda: _touch_scan(scan_id))
        _scan_update(scan_id, graph=graph, audit=audit, events=events)
        control = _scans.get(scan_id, {}).get("control")

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
                cancel_check=control,
            )

        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            await loop.run_in_executor(pool, copy_context().run, _run)

        md = render_findings_markdown(graph)
        if use_llm:
            from reachagent.report.llm_report import generate_llm_report

            md = generate_llm_report(graph, operator_prompt=operator_prompt)
        md = sanitize_report_markdown(md)
        events.append(
            ScanEvent(
                phase="report",
                kind="step",
                message="phase 4 complete — report generated from confirmed findings",
                details={"findings": len(graph.findings())},
            )
        )
        _scan_update(
            scan_id,
            status="done",
            lifecycle="completed",
            phase="report",
            report_md=md,
            finished_at=_now(),
        )
    except Exception as exc:  # noqa: BLE001 — a scan failure is surfaced, not swallowed
        from reachagent.identity.login import LoginError, redact_message
        from reachagent.scan.agentic_loop import ScanCancelled

        if isinstance(exc, ScanCancelled):
            _scan_update(
                scan_id,
                status="cancelled",
                lifecycle="cancelled",
                error="cancelled by operator",
                finished_at=_now(),
            )
        elif isinstance(exc, LoginError):
            _scan_update(
                scan_id,
                status="blocked",
                lifecycle="blocked",
                phase="auth",
                error=redact_message(exc),
                finished_at=_now(),
            )
        else:
            _log.exception("scan %s crashed", scan_id)
            _scan_update(
                scan_id,
                status="error",
                lifecycle="failed",
                error=redact_message(exc),
                finished_at=_now(),
            )


def _audit_rows(audit: AuditLog | None) -> list[dict[str, Any]]:
    """The live audit tail — one row per execution-layer action (real data)."""
    if audit is None:
        return []
    return [
        {
            "timestamp": e.timestamp.isoformat(timespec="seconds"),
            "identity": _public_text(e.identity, 120),
            "method": _public_text(e.method, 24),
            "target": _public_text(e.target, 300),
            "outcome": _public_text(e.outcome, 300),
        }
        for e in audit.entries[-200:]
    ]


def _graph_snapshot(graph: ReachabilityGraph | None) -> dict[str, Any]:
    """A live snapshot of the reachability graph the scan is building (real data)."""
    if graph is None:
        return {"available": False, "counts": {}, "hosts": [], "endpoints": []}
    return {
        "available": True,
        "counts": {
            "hosts": len(graph.hosts()),
            "services": len(graph.services()),
            "endpoints": len(graph.endpoints()),
            "parameters": sum(len(graph.parameters_of(ep)) for ep, _ in graph.endpoints()),
            "findings": len(graph.findings()),
            "sessions": len(graph.sessions()),
        },
        "hosts": [_public_text(h.address, 180) for h_id, h in graph.hosts()[:20]],
        "sessions": [
            {
                "id": _public_text(sid, 180),
                "identity": _public_text(session.identity_ref, 120),
                "auth_kind": _public_text(session.auth_kind, 40),
                "expires_at": _public_text(session.expires_at, 80) if session.expires_at else None,
                "live": session.live,
            }
            for sid, session in graph.sessions()[:20]
        ],
        "endpoints": [
            {
                "method": _public_text(ep.method, 16),
                "path": _public_text(ep.path, 240),
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
        return {"available": False, "hosts": [], "orphan_endpoints": []}
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
            "id": _public_text(endpoint_id, 180),
            "method": _public_text(endpoint.method, 16),
            "path": _public_text(endpoint.path, 240),
            "content_type": _public_text(endpoint.content_type, 100)
            if endpoint.content_type
            else None,
            "technology": _public_text(endpoint.technology, 120) if endpoint.technology else None,
            "access_restricted": _public_text(endpoint.access_restricted, 40)
            if endpoint.access_restricted
            else None,
            "parameters": [
                {
                    "id": _public_text(param_id, 180),
                    "name": _public_text(param.name, 100),
                    "location": _public_text(param.location, 32),
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
                "id": _public_text(host_id, 180),
                "address": _public_text(host.address, 180),
                "hostname": _public_text(host.hostname, 180),
                "source": _public_text(host.source, 120) if host.source else None,
                "technology": _public_text(host.technology, 120) if host.technology else None,
                "detected_version": _public_text(host.detected_version, 80)
                if host.detected_version
                else None,
                "services": [
                    {
                        "id": _public_text(service_id, 180),
                        "port": service.port,
                        "protocol": _public_text(service.protocol, 32),
                        "service_name": _public_text(service.service_name, 100),
                        "banner": _public_text(service.banner, 160),
                        "detected_version": _public_text(service.detected_version, 80)
                        if service.detected_version
                        else None,
                        "source": _public_text(service.source, 120) if service.source else None,
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
    return {"available": True, "hosts": hosts, "orphan_endpoints": orphan_endpoints}


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
    rows: list[dict[str, Any]] = []
    for fid, f in graph.findings():
        metadata = dict(getattr(f, "metadata", {}) or {})
        rows.append(
            {
                "finding_id": _public_text(fid, 180),
                "vuln_class": _public_text(getattr(f, "vuln_class", ""), 100),
                "severity": _public_text(getattr(f, "severity", ""), 24),
                "oracle_used": _public_text(getattr(f, "oracle_used", ""), 80),
                "evidence_ref": _public_text(getattr(f, "evidence_ref", ""), 180),
                "status": _public_text(
                    getattr(getattr(f, "status", ""), "value", str(getattr(f, "status", ""))),
                    40,
                ),
                "metadata": _public_value(metadata, key="metadata"),
                "chain_precondition": _public_text(metadata.get("chain_precondition", ""), 180)
                if metadata.get("chain_precondition")
                else None,
                "chains": _chains_for(graph, fid),
            }
        )
    return rows


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str) -> JSONResponse:
    with _scan_lock:
        data = _scans.get(scan_id)
        if data is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        # Copy references while holding the lock; graph/audit objects are
        # intentionally shared with the worker for live, real state.
        snapshot = dict(data)
    if not snapshot:
        return JSONResponse({"error": "not found"}, status_code=404)
    graph: ReachabilityGraph | None = snapshot.get("graph")
    events = snapshot.get("events", [])
    phase = snapshot.get("phase")
    if snapshot.get("status") in {"running", "queued", "cancelling", "paused"} and events:
        phase = events[-1].phase
    status = str(snapshot.get("status", "queued"))
    latest = _event_dict(events[-1]) if events else None
    return JSONResponse(
        {
            "scan_id": scan_id,
            "target": _public_text(snapshot.get("target", ""), 300),
            "status": status,
            "lifecycle": _lifecycle(status),
            "phase": _public_text(phase or "recon", 64),
            "events": [_event_dict(e) for e in events[-_MAX_EVENTS:]],
            "event_count": len(events) if isinstance(events, list) else 0,
            "latest_event": latest,
            "audit": _audit_rows(snapshot.get("audit")),
            "graph": _graph_snapshot(graph),
            "findings": _finding_rows(graph),
            "report_md": snapshot.get("report_md", ""),
            "error": _public_text(snapshot.get("error", ""), 500)
            if snapshot.get("error")
            else None,
            "created_at": snapshot.get("created_at"),
            "updated_at": snapshot.get("updated_at"),
            "finished_at": snapshot.get("finished_at"),
            "cancel_requested": bool(snapshot.get("cancel_requested", False)),
            "can_cancel": status in {"queued", "running", "cancelling", "paused"},
            "can_pause": status == "running",
            "can_resume": status == "paused",
            "stale_after_seconds": 20,
        }
    )


@app.get("/api/scan/{scan_id}/surface")
def get_surface(scan_id: str) -> JSONResponse:
    """Read-only Host/Service/Endpoint/Parameter graph slice for the GUI."""
    with _scan_lock:
        data = _scans.get(scan_id)
    if data is None or "graph" not in data:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"scan_id": scan_id, **_surface_snapshot(data.get("graph"))})


@app.get("/api/scan/{scan_id}/audit")
def get_audit(scan_id: str, limit: int = 200) -> JSONResponse:
    """Read-only bounded audit tail; the full execution log stays server-side."""
    with _scan_lock:
        data = _scans.get(scan_id)
    if data is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    limit = max(0, min(limit, 1000))
    return JSONResponse({"scan_id": scan_id, "entries": _audit_rows(data.get("audit"))[-limit:]})


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
    return JSONResponse({"scan_id": scan_id, "report_md": sanitize_report_markdown(report_md)})


@app.get("/api/scan/{scan_id}/evidence")
def get_evidence_index(scan_id: str) -> JSONResponse:
    """Return the bounded evidence index for a scan's confirmed findings."""
    with _scan_lock:
        data = _scans.get(scan_id)
    if data is None or "graph" not in data:
        return JSONResponse({"error": "not found"}, status_code=404)
    graph: ReachabilityGraph = data["graph"]
    context = _report_context(scan_id, data)
    return JSONResponse(build_evidence_index(graph, data.get("audit"), context=context))


@app.get("/api/scans/compare")
def compare_scans(left: str, right: str) -> JSONResponse:
    """Compare two process-local scan snapshots without firing or re-confirming."""
    with _scan_lock:
        left_data = _scans.get(left)
        right_data = _scans.get(right)
    if left_data is None or right_data is None:
        return JSONResponse({"error": "unknown scan"}, status_code=404)
    left_graph = left_data.get("graph")
    right_graph = right_data.get("graph")
    if not isinstance(left_graph, ReachabilityGraph) or not isinstance(
        right_graph, ReachabilityGraph
    ):
        return JSONResponse({"error": "both scans must have graph snapshots"}, status_code=409)
    result = compare_graphs(
        left_graph,
        right_graph,
        left_data.get("audit"),
        right_data.get("audit"),
        left_label=left,
        right_label=right,
    )
    return JSONResponse(result)


@app.get("/api/history/compare")
def compare_history(left: str, right: str) -> JSONResponse:
    """Compare persisted snapshots confined to ``REACHAGENT_HISTORY_DIR``."""
    import os

    from reachagent.report.renderer import compare_persisted_snapshots

    raw_root = os.environ.get("REACHAGENT_HISTORY_DIR", "").strip()
    if not raw_root:
        return JSONResponse(
            {"error": "persisted history is disabled", "code": "history_unconfigured"},
            status_code=400,
        )
    root = Path(raw_root).expanduser().resolve()

    def resolve(name: str) -> Path | None:
        candidate = (root / name).resolve()
        if candidate.suffix != ".json" or (candidate != root and root not in candidate.parents):
            return None
        return candidate if candidate.is_file() else None

    left_path, right_path = resolve(left), resolve(right)
    if left_path is None or right_path is None:
        return JSONResponse({"error": "unknown persisted snapshot"}, status_code=404)
    try:
        return JSONResponse(compare_persisted_snapshots(left_path, right_path))
    except Exception as exc:  # noqa: BLE001 — malformed history fails loudly
        return JSONResponse(
            {"error": f"history comparison failed: {type(exc).__name__}"}, status_code=422
        )


def _report_context(scan_id: str, data: dict[str, Any]) -> dict[str, object]:
    """Return safe run metadata for report/evidence projections."""
    return {
        "run_id": scan_id,
        "target": data.get("target", ""),
        "scope": data.get("in_scope", ""),
        "out_of_scope": data.get("out_of_scope", ""),
    }


def _report_html(
    report_md: str,
    graph: ReachabilityGraph,
    audit: object | None = None,
    *,
    context: dict[str, object] | None = None,
) -> str:
    """Self-contained report + evidence index; both are redaction-safe."""
    return render_report_html(report_md, graph, audit, context=context)


@app.get("/api/scan/{scan_id}/export")
def export_report(scan_id: str, format: str = "markdown") -> Response:
    """Download a deterministic report, evidence index, bundle, or SARIF document."""
    data = _scans.get(scan_id)
    if not data or "graph" not in data:
        return JSONResponse({"error": "not found or not done"}, status_code=404)
    graph: ReachabilityGraph = data["graph"]
    context = _report_context(scan_id, data)
    audit = data.get("audit")
    normalized = str(format or "markdown").lower()
    if normalized == "json":
        body, media, ext = render_findings_json(graph), "application/json", "json"
    elif normalized == "bundle":
        body, media, ext = (
            render_report_bundle_json(
                graph,
                audit,
                report_markdown=data.get("report_md", ""),
                context=context,
            ),
            "application/json",
            "bundle.json",
        )
    elif normalized == "sarif":
        body, media, ext = (
            render_findings_sarif(graph, context=context),
            "application/sarif+json",
            "sarif",
        )
    elif normalized in {"evidence", "evidence-json"}:
        body, media, ext = (
            render_evidence_index_json(graph, audit, context=context),
            "application/json",
            "evidence.json",
        )
    elif normalized in {"evidence-md", "evidence-markdown"}:
        body, media, ext = (
            render_evidence_index_markdown(graph, audit, context=context),
            "text/markdown",
            "evidence.md",
        )
    else:
        report_md = data.get("report_md")
        if not isinstance(report_md, str) or not report_md:
            return JSONResponse({"error": "report not ready"}, status_code=409)
        if normalized == "html":
            body, media, ext = (
                _report_html(report_md, graph, audit, context=context),
                "text/html",
                "html",
            )
        else:
            body, media, ext = sanitize_report_markdown(report_md), "text/markdown", "md"
    return Response(
        content=body,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="reachagent-report.{ext}"',
            "X-Content-Type-Options": "nosniff",
        },
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
    print(f"Debug/crash log: {LOG_PATH}")
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
