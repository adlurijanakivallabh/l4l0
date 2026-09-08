"""FastAPI GUI backend: a cursor-resumable WebSocket + a minimal SPA shell.

**No longer token-gated — a deliberate, operator-requested reversal,
recorded here rather than silently dropped.** This module previously
required a per-launch, unguessable token (generated in :func:`main`,
checked via constant-time compare on every request and the WebSocket) —
informed by a reference agent's own viewer, whose docs state plainly "a
request without the token-derived session cannot read run data." That
model's real purpose: this server binds only to ``127.0.0.1``, so it is
never reachable from the network, but the token still mattered as a
same-machine defense — without it, any OTHER browser tab or local process
could silently ``POST /scan`` (launching a real, free-shell-capable agent)
or read a completed run's findings, a same-origin drive-by/CSRF risk any
localhost tool that manages something this powerful should normally guard
against. The operator explicitly asked for the token removed specifically
to make watching a live scan easier (pasting/retyping a token URL was
the actual friction), after being told this trade-off in those terms and
confirming anyway. If this GUI is ever bound to anything other than
``127.0.0.1``, or the free-shell capability broadens beyond a single local
operator's own machine, this decision needs revisiting — it was correct for
"my own laptop, my own browser," not for a shared or network-reachable
deployment.

The steering endpoint is read-only by design, per CLAUDE.md's own stated
GUI principle (independently reconfirmed against this same reference's own
comparison of a permissive session model that has "no read-only-first
gating... any session's agent can presumably call any tool"): it can only
ever append a ``steering`` event that a human or agent may later read — it
has no code path to ``record_finding`` or any tool dispatch, and this
module holds no reference to a live agent's tool registry at all, so no
future change here can accidentally wire one in without a new, visible
import.

The WebSocket poll loop (rather than a true push/notify primitive) is a
deliberate simplification for a single local viewer, not an oversight —
:mod:`lalo.gui.events` is a plain synchronous class with no async
notification hook, and a live-scan dashboard has exactly one reader who
will not notice a sub-second delay. If this ever needs true low-latency
push, the upgrade path is an ``asyncio.Queue`` per connection that
``EventLog`` also notifies on ``append``/``update`` — not a rewrite of the
cursor protocol itself.

The same reference already cited above for its token model has directly
relevant content on a third concern this phase's own search hints raise:
client-side XSS from rendering untrusted content in the browser. Its own
frontend (``interface/viewer/frontend/src/components/live/tool-renderers/``
and ``vulnerability/``, confirmed via source, not just its comparison doc)
uses React's ``dangerouslySetInnerHTML`` in several places to inject
``highlight.js``-tokenized HTML for LLM-authored PoC scripts, code diffs,
and vulnerability descriptions — reasoned as low-risk there specifically
because ``highlight.js`` tokenizes its input as plain text rather than
parsing it as HTML, so target-controlled content flowing through never
executes as markup. :mod:`lalo.gui.static.app.js` (the companion frontend
this module serves) makes a stricter, simpler choice than that reasoning
requires: every dynamic value rendered into the page — agent status,
finding titles, chain node ids, event payload text, steering log lines, all
of it potentially target- or LLM-influenced — goes through ``textContent``,
never ``innerHTML`` and never any HTML-templating equivalent, so there is
no HTML-parsing step at all to reason about being safe. A plain DOM
console with no code-fence/PoC rendering has no legitimate use for
``innerHTML`` in the first place, so this is a narrower surface making a
narrower, more conservative choice — not a rejection of the reference's own
(correctly reasoned) approach to a harder problem it actually has and this
module does not.

**Resume was a real, tested mechanism nobody could actually reach.**
:mod:`lalo.scan`'s own crash/resume replay (``_ResumeManifest``,
``DurableJournal``) is genuine and unit-tested - but ``/scan`` always
minted a fresh ``uuid.uuid4()`` run directory, so a crashed or
budget-exhausted run's own persisted manifest could never be matched
again through the one interface this project actually has. Writing an
operator doc explaining "how to resume a run" without fixing this first
would have documented a capability the GUI structurally couldn't reach.
``ScanRequest.resume_run_id`` closes it: when set, every locked engagement
field (mission, targets, exclusions, rules of engagement, egress lock)
comes back from that run's own :func:`~lalo.scan.read_resume_manifest`,
never from the request body - a resume can't even attempt to diverge from
what was originally authorized, on top of ``ScanRunner.run()``'s own
existing ``ResumeConfigMismatchError`` backstop if it somehow did.

A background security review of that same change caught a real path-
traversal bug in it, fixed same session: ``/runs/{run_id}/events`` and
``/runs/{run_id}/report/{fmt}`` take ``run_id`` as a URL PATH SEGMENT, so
Starlette's own routing already rejects an embedded ``/`` before their
``run_id in (".", "..")`` check ever runs - that check only ever needed to
catch the residual single-segment ``..`` case. ``resume_run_id`` is a
plain JSON body STRING with no such structural protection from the
framework; the identical-looking check let ``"../../../../etc"`` straight
through to ``runs_dir / run_id``, escaping ``runs_dir`` entirely and
handing an attacker (or a malformed client) read access to any
manifest-shaped JSON file reachable from that traversal, PLUS a
subsequent scan's ``journal.jsonl``/``events.jsonl``/``graph.json``/reports
all written wherever it pointed. ``_SAFE_RUN_ID`` closes it with a strict
allowlist (matches this project's own real run-id shape,
``uuid.uuid4().hex[:12]``) applied uniformly to all three call sites, not
just the newly-vulnerable one - defense in depth for the two that were
already structurally safe costs nothing and removes the asymmetry that
made the bug easy to introduce in the first place.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import threading
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..core.config import CURATED_PROVIDERS, load_settings
from ..core.env_file import merge_env_file
from ..core.errors import AllProvidersFailedError
from ..core.logging import get_logger
from ..core.providers import build_router, verify_router
from ..intake import parse_scan_intent
from ..report.manifest import verify_report_manifest
from ..report.writer import (
    CSV_FILENAME,
    DOCX_FILENAME,
    JSON_FILENAME,
    MARKDOWN_FILENAME,
    PDF_FILENAME,
    SARIF_FILENAME,
)
from ..scan import ScanConfig, ScanRunner, load_run_events, read_resume_manifest
from .events import EventLog

# fmt -> (filename in a run_dir, media type) - a fixed allowlist, not a raw
# path segment, so /runs/{id}/report/{fmt} can never be tricked into serving
# an arbitrary file from the run directory.
_REPORT_FORMATS: dict[str, tuple[str, str]] = {
    "md": (MARKDOWN_FILENAME, "text/markdown"),
    "json": (JSON_FILENAME, "application/json"),
    "sarif": (SARIF_FILENAME, "application/json"),
    "csv": (CSV_FILENAME, "text/csv"),
    "pdf": (PDF_FILENAME, "application/pdf"),
    "docx": (
        DOCX_FILENAME,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ),
}

_log = get_logger("lalo.gui")

STATIC_DIR = Path(__file__).parent / "static"
_POLL_INTERVAL_S = 0.3
_DEFAULT_RUNS_DIR = Path.home() / ".lalo" / "runs"
_SETTINGS_ENV_PATH = Path(".env")
# Every real run_id this project ever creates is uuid.uuid4().hex[:12] - a
# strict allowlist (not a "/"/".."  blocklist) closes path traversal for
# GOOD, including the shapes a blocklist alone would miss (an absolute
# path, a URL-encoded segment, a value that isn't even routed as a URL
# path segment at all - see build_app's own module docstring for the real
# bug this closed).
_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9_-]+$")


class SteeringMessage(BaseModel):
    text: str


class ScanRequest(BaseModel):
    # Both default empty rather than required: a resume request (resume_run_id
    # set) supplies neither - the locked engagement fields are read back from
    # that run's own resume_manifest.json instead, never retyped, so a resume
    # can never accidentally mismatch what was originally authorized.
    mission: str = ""
    targets: list[str] = []
    exclude_targets: list[str] = []
    rules_of_engagement: str = ""
    resume_run_id: str | None = None
    max_steps: int | None = None
    budget_ceiling: int | None = None
    egress_lock: bool = False
    redact_findings: bool = False


class ProviderSettingsRequest(BaseModel):
    provider_id: str
    api_key: str
    extra: dict[str, str] = {}


def _event_to_json(event: Any) -> dict[str, Any]:
    return asdict(event)


def _list_runs(runs_dir: Path, *, running_run_ids: set[str] | None = None) -> list[dict[str, Any]]:
    """Every run directory under ``runs_dir``, most recently modified first -
    pure filesystem enumeration, no separate run-index state to keep in sync.
    A directory missing/unreadable ``resume_manifest.json`` (a run that never
    got past the earliest preflight checks) still lists, just without a
    mission/targets summary.

    ``running_run_ids``, if given, marks each matching entry ``"running":
    True`` - multiple entries can be True at once, since several scans can
    now run concurrently (the caller derives this set from
    ``current_runners``), since filesystem state alone can't distinguish a
    completed run from one still in progress.
    """
    if not runs_dir.exists():
        return []
    summaries: list[dict[str, Any]] = []
    for entry in runs_dir.iterdir():
        if not entry.is_dir():
            continue
        mission: str | None = None
        target_specs: list[str] = []
        try:
            manifest = json.loads((entry / "resume_manifest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            manifest = {}
        if isinstance(manifest, dict):
            raw_mission = manifest.get("mission")
            mission = raw_mission if isinstance(raw_mission, str) else None
            raw_targets = manifest.get("target_specs")
            target_specs = raw_targets if isinstance(raw_targets, list) else []
        # Individually checked, not inferred from report.json alone: pdf/docx
        # are each independently best-effort at write time (write_report's
        # own documented behavior) - a run can have a canonical report with
        # no pdf if WeasyPrint hit a renderer bug, and the frontend needs to
        # know exactly which formats it can actually link to.
        report_formats = [
            fmt
            for fmt, (filename, _media) in _REPORT_FORMATS.items()
            if (entry / filename).exists()
        ]
        has_report = "json" in report_formats
        # Informational only, never a gate: ScanRunner's own idempotent-resume
        # fast path (scan.py) already makes resuming a run with an intact
        # report a cheap no-op, but the frontend still offered "Resume" with
        # no indication that nothing further would actually happen - this
        # lets it say so, purely for the operator's own expectations, while
        # the button itself stays exactly as clickable as before.
        report_valid = has_report and not verify_report_manifest(entry)
        summaries.append(
            {
                "run_id": entry.name,
                "mission": mission,
                "target_specs": target_specs,
                "has_report": has_report,
                "report_valid": report_valid,
                "report_formats": report_formats,
                "modified_at": entry.stat().st_mtime,
                "running": entry.name in (running_run_ids or set()),
            }
        )
    summaries.sort(key=lambda s: s["modified_at"], reverse=True)
    return summaries


def build_app(event_log: EventLog, *, runs_dir: Path | None = None) -> FastAPI:
    app = FastAPI()
    runs_dir = runs_dir or _DEFAULT_RUNS_DIR
    # A single mutable slot, not a list/registry: this GUI is a single-operator
    # local tool (CLAUDE.md's own design center) with one dashboard watching
    # Multiple scans CAN run concurrently, each keyed by its own run_id -
    # `event_log` (the instance this function was constructed with) is
    # always used for the first ("primary") scan launched, so every
    # existing caller/test that reads it directly keeps working unchanged.
    # Any ADDITIONAL concurrent scan gets its own fresh EventLog (tracked in
    # `extra_event_logs`), so two engagements' live events never interleave
    # into one indistinguishable stream. `/scan` refuses a second launch of
    # the SAME run_id, never a second run_id.
    current_runners: dict[str, ScanRunner] = {}
    extra_event_logs: dict[str, EventLog] = {}
    primary_run_id: list[str | None] = [None]  # single-element cell, closure-mutable

    def _event_log_for(run_id: str | None) -> EventLog | None:
        if run_id == primary_run_id[0]:
            return event_log
        return extra_event_logs.get(run_id) if run_id is not None else None

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.post("/scan")
    async def start_scan(request: ScanRequest) -> JSONResponse:
        if request.resume_run_id:
            run_id = request.resume_run_id
            if not _SAFE_RUN_ID.match(run_id):
                return JSONResponse({"error": "invalid run_id"}, status_code=400)
            if run_id in current_runners:
                return JSONResponse(
                    {"error": f"run {run_id!r} is already running"}, status_code=409
                )
            run_dir = runs_dir / run_id
            manifest = read_resume_manifest(run_dir)
            if manifest is None:
                return JSONResponse(
                    {"error": f"no resumable run found for {run_id!r}"}, status_code=404
                )
            # Every locked engagement field comes back from the run's OWN
            # persisted manifest, never from this request's mission/targets -
            # ScanRunner.run() would reject a mismatch anyway
            # (ResumeConfigMismatchError), but reading it back here means a
            # resume can never even attempt to diverge from what was
            # originally authorized in the first place.
            raw_targets = manifest["target_specs"]
            raw_excludes = manifest.get("exclude_target_specs", [])
            config = ScanConfig(
                mission=str(manifest["mission"]),
                target_specs=[str(t) for t in raw_targets] if isinstance(raw_targets, list) else [],
                exclude_target_specs=(
                    [str(t) for t in raw_excludes] if isinstance(raw_excludes, list) else []
                ),
                rules_of_engagement=str(manifest.get("rules_of_engagement", "")),
                egress_lock=bool(manifest["egress_lock"]),
                run_dir=run_dir,
                usage_path=run_dir / "usage.json",
            )
        else:
            mission = request.mission.strip()
            targets = [t.strip() for t in request.targets if t.strip()]
            exclude_targets = [t.strip() for t in request.exclude_targets if t.strip()]
            rules_of_engagement = request.rules_of_engagement.strip()
            if not mission:
                return JSONResponse(
                    {"error": "'mission' and 'targets' are required"}, status_code=400
                )
            if not targets:
                router = build_router(load_settings(os.environ))
                try:
                    parsed = parse_scan_intent(mission, router)
                except AllProvidersFailedError as exc:
                    return JSONResponse(
                        {
                            "error": "could not understand the request: every LLM provider failed",
                            "role": exc.role,
                            "failures": [
                                {"provider": name, "reason": reason}
                                for name, reason in exc.failures
                            ],
                        },
                        status_code=503,
                    )
                targets = parsed.targets
                exclude_targets = exclude_targets or parsed.exclude_targets
                rules_of_engagement = rules_of_engagement or parsed.rules_of_engagement
            if not targets:
                return JSONResponse(
                    {"error": "'mission' and 'targets' are required"}, status_code=400
                )
            run_id = uuid.uuid4().hex[:12]
            run_dir = runs_dir / run_id
            # Read ScanConfig's own dataclass defaults rather than
            # hardcoding a fallback number here - a hardcoded 25 here once
            # silently drifted out of sync with ScanConfig.max_steps' own
            # default after that was raised, caught by this project's own
            # test suite. This is the only spot that needs it: the resume
            # branch above never overrides either field at all.
            config = ScanConfig(
                mission=mission,
                target_specs=targets,
                exclude_target_specs=exclude_targets,
                rules_of_engagement=rules_of_engagement,
                run_dir=run_dir,
                usage_path=run_dir / "usage.json",
                max_steps=(
                    request.max_steps if request.max_steps is not None else ScanConfig.max_steps
                ),
                budget_ceiling=(
                    request.budget_ceiling
                    if request.budget_ceiling is not None
                    else ScanConfig.budget_ceiling
                ),
                redact_findings=request.redact_findings,
                egress_lock=request.egress_lock,
            )

        if primary_run_id[0] is None:
            this_event_log = event_log
            primary_run_id[0] = run_id
        else:
            this_event_log = EventLog()
            extra_event_logs[run_id] = this_event_log

        runner = ScanRunner(config, event_log=this_event_log)
        current_runners[run_id] = runner

        def _run_and_clear() -> None:
            try:
                runner.run()
            except Exception as exc:  # noqa: BLE001 - a background thread's own
                # exception has no caller to propagate to; the dashboard is the
                # only place this failure can surface, so it must be a status
                # event, never a silently dead thread.
                _log.exception("scan failed")
                payload: dict[str, object] = {"event": "scan_failed", "error": str(exc)}
                # AllProvidersFailedError already carries its per-provider
                # detail as real attributes (see core/errors.py) - str(exc)
                # alone flattens them into one line the frontend can't
                # re-segment, so surface role/failures as their own fields
                # too for a structured, per-provider rendering in the GUI.
                if isinstance(exc, AllProvidersFailedError):
                    payload["role"] = exc.role
                    payload["failures"] = [
                        {"provider": name, "reason": reason} for name, reason in exc.failures
                    ]
                this_event_log.append("status", payload)
            finally:
                # Only the running-scan slot is cleared - this_event_log stays
                # reachable (via primary_run_id/extra_event_logs) for the rest
                # of the process's life, so a completed run's live-scoped
                # WebSocket view still works exactly like its static replay.
                current_runners.pop(run_id, None)

        threading.Thread(target=_run_and_clear, daemon=True).start()
        return JSONResponse(
            {
                "ok": True,
                "run_dir": str(run_dir),
                "run_id": run_id,
                "resolved_targets": config.target_specs,
                "resolved_exclude_targets": config.exclude_target_specs,
                "resolved_rules_of_engagement": config.rules_of_engagement,
            }
        )

    @app.get("/status")
    def status(run_id: str | None = Query(default=None)) -> JSONResponse:
        target_run_id = run_id or primary_run_id[0]
        target_log = _event_log_for(target_run_id)
        cursor, events = target_log.snapshot() if target_log is not None else (0, [])
        findings_count = sum(1 for e in events if e.category == "finding")
        last_status = next((e.payload for e in reversed(events) if e.category == "status"), None)
        return JSONResponse(
            {
                "running": target_run_id in current_runners,
                "cursor": cursor,
                "findings_count": findings_count,
                "last_status": last_status,
                "active_run_ids": list(current_runners),
            }
        )

    @app.get("/runs")
    def list_runs() -> JSONResponse:
        return JSONResponse({"runs": _list_runs(runs_dir, running_run_ids=set(current_runners))})

    @app.get("/runs/{run_id}/events")
    def run_events(run_id: str) -> JSONResponse:
        # Starlette's default path converter already excludes "/" from a
        # single {run_id} segment; _SAFE_RUN_ID is defense in depth here
        # (this handler was never the vulnerable one - see the module
        # docstring for which one was and why the allowlist applies to all
        # three uniformly regardless).
        if not _SAFE_RUN_ID.match(run_id):
            return JSONResponse({"error": "invalid run_id"}, status_code=400)
        run_path = runs_dir / run_id
        if not run_path.is_dir():
            return JSONResponse({"error": "run not found"}, status_code=404)
        replay = load_run_events(run_path)
        cursor, events = replay.snapshot()
        return JSONResponse({"cursor": cursor, "events": [_event_to_json(e) for e in events]})

    @app.get("/runs/{run_id}/report/{fmt}", response_model=None)
    def run_report(run_id: str, fmt: str) -> FileResponse | JSONResponse:
        if not _SAFE_RUN_ID.match(run_id):
            return JSONResponse({"error": "invalid run_id"}, status_code=400)
        format_info = _REPORT_FORMATS.get(fmt)
        if format_info is None:
            return JSONResponse({"error": "invalid format"}, status_code=400)
        filename, media_type = format_info
        path = runs_dir / run_id / filename
        if not path.is_file():
            return JSONResponse({"error": "report not found"}, status_code=404)
        return FileResponse(path, media_type=media_type, filename=filename)

    @app.get("/settings/providers")
    def list_provider_settings() -> JSONResponse:
        settings = load_settings(os.environ)
        configured_ids = {p.id for p in settings.resolved}
        return JSONResponse(
            {
                "providers": [
                    {
                        "id": spec.id,
                        "credential_hint": spec.credential_hint,
                        "configured": spec.id in configured_ids,
                    }
                    for spec in CURATED_PROVIDERS
                ]
            }
        )

    @app.post("/settings/providers")
    def set_provider_settings(request: ProviderSettingsRequest) -> JSONResponse:
        spec = next((s for s in CURATED_PROVIDERS if s.id == request.provider_id), None)
        if spec is None:
            return JSONResponse(
                {"error": f"unknown provider {request.provider_id!r}"}, status_code=400
            )
        api_key = request.api_key.strip()
        if not api_key:
            return JSONResponse({"error": "'api_key' is required"}, status_code=400)
        unknown_extras = set(request.extra) - set(spec.extra_required_envs)
        if unknown_extras:
            return JSONResponse(
                {"error": f"unexpected 'extra' key(s) for {spec.id!r}: {sorted(unknown_extras)}"},
                status_code=400,
            )
        env = {spec.candidate_key_envs[0]: api_key, **request.extra}
        settings = load_settings(env)
        router = build_router(settings)
        ok, reason = verify_router(router).get(spec.id, (False, "not resolved"))
        if not ok:
            return JSONResponse({"error": f"verification failed: {reason}"}, status_code=400)
        merge_env_file(_SETTINGS_ENV_PATH, env)
        for key, value in env.items():
            os.environ[key] = value
        return JSONResponse({"ok": True, "provider_id": spec.id})

    @app.post("/scan/stop")
    async def stop_scan(run_id: str | None = Query(default=None)) -> JSONResponse:
        target_run_id = run_id or primary_run_id[0]
        runner = current_runners.get(target_run_id) if target_run_id is not None else None
        if runner is None:
            return JSONResponse({"error": "no scan is running"}, status_code=400)
        runner.cancel()
        return JSONResponse({"ok": True})

    @app.post("/steer")
    async def steer(
        message: SteeringMessage, run_id: str | None = Query(default=None)
    ) -> JSONResponse:
        text = message.text.strip()
        if not text:
            return JSONResponse({"error": "'text' is required"}, status_code=400)
        target_run_id = run_id or primary_run_id[0]
        target_log = _event_log_for(target_run_id)
        if target_log is None:
            return JSONResponse({"error": "no scan is running"}, status_code=400)
        target_log.append("steering", {"text": text})
        return JSONResponse({"ok": True})

    @app.websocket("/ws")
    async def ws(
        websocket: WebSocket,
        cursor: int | None = Query(default=None),
        run_id: str | None = Query(default=None),
    ) -> None:
        target_run_id = run_id or primary_run_id[0]
        target_log = _event_log_for(target_run_id)
        await websocket.accept()
        if target_log is None:
            await websocket.close(code=4404, reason=f"no such run {run_id!r}")
            return
        try:
            current, events = (
                target_log.changes_since(cursor) if cursor is not None else target_log.snapshot()
            )
        except ValueError as exc:
            await websocket.close(code=4400, reason=str(exc))
            return

        await websocket.send_json(
            {"cursor": current, "events": [_event_to_json(e) for e in events]}
        )
        last_cursor = current
        try:
            while True:
                await asyncio.sleep(_POLL_INTERVAL_S)
                new_cursor, changed = target_log.changes_since(last_cursor)
                if changed:
                    await websocket.send_json(
                        {"cursor": new_cursor, "events": [_event_to_json(e) for e in changed]}
                    )
                last_cursor = new_cursor
        except WebSocketDisconnect:
            return

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


def main() -> None:
    """Entry point for the ``lalo-gui`` script: the GUI is the primary way to run L4L0.

    ``POST /scan`` (mission + target specs, one scan at a time) launches a
    real :class:`~lalo.scan.ScanRunner` on a background thread, which
    streams every event into the returned ``EventLog`` — the wiring this
    function's docstring used to describe as a future integration pass's
    job now lives in :mod:`lalo.scan`, called from here.
    """
    import uvicorn

    event_log = EventLog()
    app = build_app(event_log)
    host, port = "127.0.0.1", 8000
    print(f"L4L0 GUI: http://{host}:{port}/")
    uvicorn.run(app, host=host, port=port)
