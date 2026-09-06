# L4L0 GUI v2 — Design Spec

**Status:** approved for planning (brainstormed interactively; user opted to
move directly to the implementation plan rather than a full mockup-review
cycle — decisions below are grounded in the real current code, not
guesses, but were not reviewed as visual mockups).

## Why

Real user feedback on the current single-conversation-thread GUI:

1. Clicking a past run in the "Past Runs" rail does nothing — only the tiny
   "Report" link and "Resume" button inside each row are interactive. The
   user expects ChatGPT-style behavior: click a past conversation, see its
   full history, and be able to type a new message to continue it.
2. The GUI shows almost nothing of what the agent is actually doing in real
   time — confirmed in code: every `tool_call`/`tool_result` event carries
   only the tool name and an `ok` boolean, never the real captured output.
   The user wants a live, updating shell/terminal view of the disposable
   container's actual command output while it runs.
3. Provider credentials and scan tuning (max_steps, budget_ceiling,
   egress_lock, rules of engagement, excluded targets) are only reachable
   by editing env vars or constructing `ScanConfig` in Python directly —
   confirmed in code: `ScanRequest` doesn't even have `max_steps`/
   `budget_ceiling` fields, and `rules_of_engagement`/`exclude_targets`
   exist on the model but have no composer form control.
4. Visual design: dark-only (no light theme exists at all — confirmed, one
   hardcoded `:root` token set, no `prefers-color-scheme` or `data-theme`
   handling anywhere), and the user wants it to look and feel like a
   polished chat product.

## Scope: four phases, each independently shippable

Ordered by dependency and risk — cheapest, highest-value, frontend-only
change first; the riskiest backend change (true live streaming) third, so
it's tackled once the easier wins are already banked; the visual redesign
last, so it can style whatever new UI elements the first three phases add.

1. **Open a past run like a ChatGPT conversation** — frontend-only. Click a
   run row → its full recorded history replaces the thread → composer
   continues it (resume + steer). No backend changes: `GET /runs/{id}/events`
   and `POST /scan {resume_run_id}` already exist and already do everything
   needed.
2. **In-GUI settings** — provider credential management (list/add/verify a
   key, mirroring `lalo-setup`'s own logic), a light/dark theme toggle, and
   an "Advanced" section exposing `max_steps`/`budget_ceiling`/
   `egress_lock`/`rules_of_engagement`/`exclude_targets` before launch.
3. **Live shell/terminal panel** — a new right-side panel showing the
   disposable container's real stdout/stderr as `run_command` executes,
   updating while the command is still running (not only after it
   finishes). Requires a new streaming exec path.
4. **Visual redesign** — a real light theme (doesn't exist today) + a theme
   toggle (built in phase 2) + a concrete component/spacing refresh across
   the whole page, informed by phases 1–3's new UI surface.

## Phase 1 — Open a past run

**Data flow:** `GET /runs/{run_id}/events` (existing, unchanged) → replay
each returned event through the EXISTING `applyEvent()` renderer (already
generically handles every event category — no new render code needed) →
composer switches to "continue this conversation" mode.

**New frontend state:**
- `viewingRunId: string | null` — which past run's history is currently
  displayed; `null` means "live."
- `pendingLiveCount: number` — live events received while viewing history,
  not yet shown (surfaced as a small "N new — back to live" pill).

**Behavior:**
- Clicking a `.run-item` (anywhere except its `.run-resume-btn`/
  `.run-report-link` children) calls `openRun(runId)`: fetches
  `/runs/{runId}/events`, clears the thread and all per-render state
  (`agents`, `findingCards`, counters), replays every event via the
  existing `applyEvent`, sets `viewingRunId = runId`, and marks that row
  `.viewing` in the CSS.
- While `viewingRunId !== null`, incoming live WebSocket events are
  **not** rendered into the thread (they'd corrupt the historical view) —
  instead `pendingLiveCount` increments and a pill appears. Clicking the
  pill (or a persistent "Back to live" banner) calls `returnToLive()`:
  sets `viewingRunId = null`, clears the thread, and forces a fresh
  WebSocket reconnect with `lastCursor = null` (reuses the *existing*
  reconnect-with-no-cursor snapshot behavior already in `connect()`'s
  `close` handler — no new snapshot logic needed).
- Submitting the composer while `viewingRunId !== null`: if that run isn't
  the one `current_runner` is actively running, first `POST /scan
  {resume_run_id: viewingRunId}` (existing endpoint), then send the typed
  text as a steering message (existing `sendSteering`), then behave exactly
  like a live scan (`viewingRunId = null`, `onScanStarted()`).

**No backend changes in this phase at all.**

## Phase 2 — In-GUI settings

### Provider credentials

**New backend surface** (`gui/app.py`):
- `GET /settings/providers` → for every `core.config.CURATED_PROVIDERS`
  entry, whether it's currently configured (`bool(load_settings(os.environ).get(id))`)
  — never the secret value itself.
- `POST /settings/providers` `{provider_id, api_key, extra: {<extra_env>: value}}`
  → build an env dict exactly like `lalo-setup` does, `load_settings(env)`,
  `build_router(settings)`, `verify_router(router)[provider_id]` (same
  reused verification call `lalo-setup` and `scan.py`'s own preflight
  already use) → on success: merge into the on-disk `.env` (extract
  `setup.py`'s `_merge_env_file` into a shared `core/env_file.py` so both
  `lalo-setup` and the GUI use the identical, already-tested logic) **and**
  set `os.environ[key] = value` for every key just written, so the
  *already-running* GUI process picks up the new credential immediately —
  writing to `.env` alone has zero effect on a process that already
  started with a different environment.

### Advanced scan options

`ScanRequest` gains optional `max_steps: int | None = None`,
`budget_ceiling: int | None = None`, `egress_lock: bool = False`
(`rules_of_engagement`/`exclude_targets` already exist — they just need a
form control). `start_scan` passes each through to `ScanConfig` only when
provided, else `ScanConfig`'s own existing defaults apply unchanged.

### Theme toggle

A dark/light choice persisted in `localStorage` (a per-browser UI
preference — no backend involvement, matches this project's own "browser
storage for per-viewer conveniences" convention). Implemented as part of
Phase 4's token system (`data-theme="light"`/`"dark"` on `<html>`), but the
*toggle control* itself (a button in the settings drawer) ships in this
phase so credential management and the toggle live in the same place.

### UI

A gear icon in the rail opens a settings drawer/modal: a "Providers" list
(configured/not, a masked-input add form, a "Verify" button), a theme
toggle, and an "Advanced" section rendered inline in the composer area
(collapsed by default) with the five fields above.

## Phase 3 — Live shell/terminal panel

**The core problem:** `RuntimeContainer.exec()` calls `subprocess.run(...,
capture_output=True)` — fully blocking, all output returned only once the
command exits. Nothing streams anywhere today, and no event the GUI
receives ever carries real command output text (only `ok: bool`).

**New method, additive — `exec()` is untouched, zero risk to existing
callers/tests:**

```python
# runtime/container.py
def exec_streaming(
    self,
    command: str | list[str],
    on_chunk: Callable[[str, str], None],  # (stream: "stdout"|"stderr", text: str)
    *,
    timeout: float = 120.0,
) -> ExecResult:
    """Like exec(), but calls on_chunk with output as it's produced instead
    of only returning once the command finishes. Returns the identical
    ExecResult shape exec() does - streaming is a side channel for a live
    viewer, never a replacement for the agent's own synchronous
    "run a command, get the final result" contract."""
```

Implementation: `subprocess.Popen(argv, stdout=PIPE, stderr=PIPE, text=True,
bufsize=1)`, one daemon reader thread per stream (`for line in
process.stdout: on_chunk("stdout", line)` / same for stderr), `process.wait(timeout=...)`
with the existing kill-on-timeout behavior, joining both reader threads
before building the final `ExecResult` from the accumulated text — stdout
and stderr stay separate, exactly like `exec()` today, so `run_command`'s
existing observation format (`stdout:\n...\nstderr:\n...`) is unaffected.

**Wiring — `runtime/tool.py`:** `build_run_command_tool` gains an optional
`on_shell_event: Callable[[dict[str, object]], None] | None = None`. When
provided, `_run()` generates a `command_id` (`uuid.uuid4().hex[:12]`),
calls `on_shell_event({"event": "start", "command_id": ..., "command": command})`,
uses `container.exec_streaming(command, lambda stream, text:
on_shell_event({"event": "chunk", "command_id": ..., "stream": stream, "text": text}), timeout=...)`
instead of `container.exec(...)`, then `on_shell_event({"event": "end",
"command_id": ..., "exit_code": ...})`. When `on_shell_event` is `None`
(every existing test, unchanged), behavior is byte-for-byte identical to
today.

**Wiring — `scan.py`:** a new `EventCategory` value `"shell"` (extend the
`Literal` in `gui/events.py`). Inside `_build_registry`, pass
`on_shell_event=lambda payload: self._emit("shell", {"agent_id": self_id, **payload})`
to `build_run_command_tool` — the exact same per-agent-attribution pattern
`on_event` already uses.

**Frontend:** a new right-side panel (`#shell-panel`), populated by a new
`applyShellEvent` branch in `applyEvent`'s switch, keyed by `command_id`
(mirrors the existing `findingCards` Map pattern exactly): `"start"`
creates a `<pre class="shell-block">` with a command header; `"chunk"`
appends `text` via `textContent` (never `innerHTML` — matches this
project's own existing, deliberate XSS-safety convention) to that block
and auto-scrolls; `"end"` adds an exit-code badge (green/red).

## Phase 4 — Visual redesign

**Palette** (both themes defined as CSS custom properties on `:root`,
switched via `data-theme` — dark stays the default with no attribute, per
this project's viewer convention):

- Dark (current, refined): keep the existing `--bg`/`--surface`/`--text`
  hue family, tighten the spacing scale to a consistent 4/8/12/16/24px
  rhythm (several current rules use ad hoc values), add a subtle 1px
  border on cards instead of relying on background-color contrast alone.
- Light (new): a clean off-white surface stack, dark-on-light text,
  identical structural rules — only the token values change, so this is a
  values-only addition to the existing custom-property system, not a
  rule-by-rule rewrite.

**Component polish**, informed by phases 1–3's actual new surface: the
settings drawer, the shell panel, and the "viewing history" banner all get
styled as part of this phase (they ship functionally plain in phases 2–3
and get the full visual treatment here, so redesign work happens once
against the final page shape instead of twice).

## Out of scope (explicitly, so it isn't silently expected)

- Remote/multi-viewer collaboration (this stays a single-operator local
  tool, per `CLAUDE.md`'s own design center).
- A true interactive PTY the *agent* can type follow-up input into mid-command
  — the agent's tool contract stays request/response (`run_command(cmd) → result`);
  only the *operator's view* of a running command becomes live.
- Report rendering beyond the existing download links (in-browser preview,
  format picker) — flagged as a good future idea, not built in this pass.
