# L4L0 GUI v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the GUI behave like a real chat product — past runs open like conversations and can be continued, credentials/theme/advanced options are managed in-GUI, the disposable container's real command output streams live, and the whole page gets a real light theme plus a component/spacing refresh.

**Architecture:** Four independently-shippable phases. Phase 1 is frontend-only (reuses existing endpoints). Phase 2 adds two small settings endpoints plus `ScanRequest` fields. Phase 3 adds a new, additive `RuntimeContainer.exec_streaming()` method (the existing `exec()` is never touched) wired through a new optional callback on `build_run_command_tool` and a new `"shell"` event category. Phase 4 is CSS/JS only, adding a light theme via existing custom-property tokens.

**Tech Stack:** Python 3.13, FastAPI/Starlette, pytest, vanilla JS/CSS (no framework, no build step — matches this project's existing frontend).

**Spec:** `docs/superpowers/specs/2026-09-06-gui-v2-design.md`

## Global Constraints

- Never use `innerHTML` or string-concatenated HTML in `app.js` — every dynamic value goes through `textContent` or template cloning (existing, deliberate XSS-safety convention; see the spec's Phase 3 note).
- `RuntimeContainer.exec()` must not change behavior or signature — `exec_streaming()` is strictly additive.
- Every new backend field/endpoint must have a working, tested default that changes nothing for a caller that doesn't use it (existing tests must keep passing unmodified).
- `ruff check`, `ruff format`, `mypy` (strict), and the relevant pytest file(s) must pass before every commit; run the full non-integration/non-live suite (`uv run pytest -q -m "not integration and not live"`) before each phase's final commit.
- No JS unit-test framework exists in this repo (confirmed) — frontend tasks are verified live via Playwright against a running `lalo-gui`, matching this project's own established convention, not invented unit tests.

---

## Phase 1 — Open a past run like a ChatGPT conversation

### Task 1: Click a past run to view its full history

**Files:**
- Modify: `src/lalo/gui/static/app.js`
- Modify: `src/lalo/gui/static/index.html:98-108` (`tpl-run-item` — add a "back to live" pill, add a `.viewing` state class hook)
- Modify: `src/lalo/gui/static/app.css` (`.run-item.viewing`, `.history-banner`, `.live-pill` styles)

**Interfaces:**
- Consumes: existing `GET /runs/{run_id}/events` (returns `{cursor, events: [...]}`), existing `applyEvent(event)` function (unchanged), existing `connect()`'s reconnect-with-`lastCursor=null` snapshot behavior (unchanged).
- Produces: `openRun(runId)`, `returnToLive()` — used by Task 2.

- [ ] **Step 1: Add the "viewing history" banner and pill markup**

In `index.html`, right after `<div class="thread" id="thread" ...>`'s opening tag's sibling content (i.e., as a new element inside `.thread-wrap`, before `#thread`):

```html
<div id="history-banner" class="history-banner" hidden>
  <span id="history-banner-text"></span>
  <button type="button" id="history-back-to-live" class="btn-icon">Back to live</button>
</div>
```

- [ ] **Step 2: Add state and the click-delegation guard in `app.js`**

Near the other top-level `let`/`const` state declarations (alongside `let scanActive = false;`):

```js
let viewingRunId = null; // null = live; otherwise the run_id currently displayed
let pendingLiveCount = 0;
const historyBanner = document.getElementById("history-banner");
const historyBannerText = document.getElementById("history-banner-text");
const historyBackToLiveBtn = document.getElementById("history-back-to-live");
```

- [ ] **Step 3: Write `openRun` and `returnToLive`**

Add near `loadRunHistory`:

```js
async function openRun(runId, missionText) {
  try {
    const response = await fetch(`/runs/${encodeURIComponent(runId)}/events`);
    if (!response.ok) return;
    const body = await response.json();
    threadEl.replaceChildren();
    agents.clear();
    findingCards.clear();
    findingCount = 0;
    chainCount = 0;
    statFindingsEl.textContent = "0";
    statChainsEl.textContent = "0";
    statAgentsEl.textContent = "0";
    openLogBlock = null;
    for (const event of body.events || []) {
      applyEvent(event);
    }
    viewingRunId = runId;
    pendingLiveCount = 0;
    historyBannerText.textContent = `Viewing: ${missionText || runId}`;
    historyBanner.hidden = false;
    composerInput.placeholder = "Continue this run…";
  } catch {
    // best-effort - the live view is unaffected by a failed history fetch
  }
}

function returnToLive() {
  viewingRunId = null;
  pendingLiveCount = 0;
  historyBanner.hidden = true;
  composerInput.placeholder = scanActive ? "Message this run…" : "Tell me what to test…";
  threadEl.replaceChildren();
  agents.clear();
  findingCards.clear();
  findingCount = 0;
  chainCount = 0;
  openLogBlock = null;
  lastCursor = null;
  socket.close(); // triggers the existing reconnect-with-no-cursor full snapshot
}

historyBackToLiveBtn.addEventListener("click", returnToLive);
```

- [ ] **Step 4: Wire the row click, excluding the existing buttons/links**

In `buildRunItem`, after the existing `if (!run.running) { ... }` block, store the mission text for `openRun` to use (add a data attribute):

```js
item.dataset.missionText = run.mission || "(no mission recorded)";
```

Add a new delegated listener near the existing `runHistoryListEl.addEventListener("click", ...)` for `.run-resume-btn` (keep that one; add this one right after it):

```js
runHistoryListEl.addEventListener("click", (ev) => {
  if (ev.target.closest(".run-resume-btn") || ev.target.closest(".run-report-link")) return;
  const item = ev.target.closest(".run-item");
  if (!item) return;
  document.querySelectorAll(".run-item.viewing").forEach((el) => el.classList.remove("viewing"));
  item.classList.add("viewing");
  openRun(item.dataset.runId, item.dataset.missionText);
});
```

This requires `buildRunItem` to also set `item.dataset.runId = run.run_id;` (add this line alongside the existing `item.dataset.missionText` line from this same step).

- [ ] **Step 5: Suppress live rendering while viewing history**

In the WebSocket `"message"` handler, change:

```js
socket.addEventListener("message", (ev) => {
  const data = JSON.parse(ev.data);
  lastCursor = data.cursor;
  for (const event of data.events || []) {
    applyEvent(event);
  }
});
```

to:

```js
socket.addEventListener("message", (ev) => {
  const data = JSON.parse(ev.data);
  lastCursor = data.cursor;
  const events = data.events || [];
  if (viewingRunId !== null) {
    pendingLiveCount += events.length;
    if (pendingLiveCount > 0) {
      historyBannerText.textContent = `${pendingLiveCount} new live event(s) — `;
    }
    return;
  }
  for (const event of events) {
    applyEvent(event);
  }
});
```

- [ ] **Step 6: Add CSS for the banner and viewing state**

In `app.css`, near `.run-item` rules. Deliberately no accent-colored
side-border for the `.viewing` state — a thick colored border on one side
of a card is one of the most recognizable AI-generated-UI tells (flagged
during actual implementation by this project's own design-review hook);
reuse the SAME idiom `.run-item.running` already establishes for its own
active-state indicator instead (an accent-colored `.run-status-dot`),
rather than inventing a second, different visual pattern for a
conceptually similar "this row is active" state:

```css
.run-item.viewing { background: var(--surface-muted); }
.run-item.running .run-status-dot,
.run-item.viewing .run-status-dot { background: var(--accent); }

.history-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 6px 12px;
  background: var(--surface-muted);
  border-bottom: 1px solid var(--border);
  font-size: 0.78rem;
  color: var(--text-muted);
}
/* Author `display: flex` above otherwise beats the UA stylesheet's own
   `[hidden] { display: none }` at equal specificity - toggling the
   `hidden` attribute via JS would silently stop working without this
   (a real bug caught during actual implementation, not a hypothetical). */
.history-banner[hidden] { display: none; }
```

- [ ] **Step 7: Verify live, with Playwright**

Start `uv run lalo-gui`, navigate to it, seed at least two run directories under `~/.lalo/runs/` each with a `resume_manifest.json` and an `events.jsonl` containing a couple of real event lines (reuse the fixture shape from `tests/lalo/test_gui_app.py::test_run_events_replays_a_persisted_runs_narration`). Click a run row (not its Resume/Report controls) and confirm: the thread clears and replays that run's events, the row gets a `.viewing` highlight, the history banner appears with the mission text, and clicking "Back to live" clears the banner and restores the empty/live thread.

- [ ] **Step 8: Commit**

```bash
git add src/lalo/gui/static/app.js src/lalo/gui/static/index.html src/lalo/gui/static/app.css
git commit -m "feat(L4L0): open a past run's full history by clicking its row"
```

### Task 2: Continue a viewed historical run via the composer

**Files:**
- Modify: `src/lalo/gui/static/app.js`

**Interfaces:**
- Consumes: `resumeRun(runId, button)` (existing — refactor its POST logic into a reusable piece), `sendSteering(text)` (existing, unchanged), `viewingRunId`/`returnToLive` behavior from Task 1.
- Produces: `continueViewedRun(text)`.

- [ ] **Step 1: Extract the resume POST into a reusable function**

Refactor the existing `resumeRun`:

```js
async function launchResume(runId) {
  const response = await fetch("/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ resume_run_id: runId }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error || `request failed (${response.status})`);
  }
}

async function resumeRun(runId, button) {
  button.disabled = true;
  try {
    await launchResume(runId);
    appendAgentText(`Resuming run ${runId}…`);
    onScanStarted();
  } catch (err) {
    appendAgentText(`[resume failed: ${err.message}]`);
    button.disabled = false;
  }
}
```

- [ ] **Step 2: Write `continueViewedRun`**

```js
async function continueViewedRun(text) {
  const runId = viewingRunId;
  composerSendBtn.disabled = true;
  composerInput.disabled = true;
  try {
    if (!scanActive) {
      await launchResume(runId);
    }
    viewingRunId = null;
    historyBanner.hidden = true;
    onScanStarted();
    await sendSteering(text);
  } catch (err) {
    appendAgentText(`[continue failed: ${err.message}]`);
  } finally {
    composerSendBtn.disabled = false;
    composerInput.disabled = false;
    composerInput.focus();
  }
}
```

- [ ] **Step 3: Route composer submission through it when viewing history**

Change the existing composer submit handler:

```js
composerForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const text = composerInput.value.trim();
  if (!text) return;
  if (viewingRunId !== null) {
    composerInput.value = "";
    await continueViewedRun(text);
  } else if (scanActive) {
    await sendSteering(text);
  } else {
    await launchFromPrompt(text);
  }
});
```

- [ ] **Step 4: Verify live, with Playwright**

With `lalo-gui` running (no provider key needed for this check — the failure path is exactly what proves the wiring), open a past run, type a message, submit, and confirm a `POST /scan` with `resume_run_id` fires (Network tab), followed by a `POST /steer` once the (expected, if no credentials) scan-failed or scan-started state settles — or, with a real provider configured, confirm the run actually resumes and the typed message arrives as a steering event.

- [ ] **Step 5: Commit**

```bash
git add src/lalo/gui/static/app.js
git commit -m "feat(L4L0): continue a viewed past run by typing in the composer"
```

---

## Phase 2 — In-GUI settings

### Task 3: Shared `.env` merge helper + provider settings endpoints

**Files:**
- Create: `src/lalo/core/env_file.py`
- Modify: `src/lalo/setup.py` (use the extracted helper instead of its own copy)
- Modify: `src/lalo/gui/app.py` (`GET /settings/providers`, `POST /settings/providers`)
- Test: `tests/lalo/test_env_file.py`
- Test: `tests/lalo/test_gui_app.py`

**Interfaces:**
- Produces: `merge_env_file(path: Path, values: dict[str, str]) -> None` in `core/env_file.py` (moved verbatim from `setup.py`'s existing `_merge_env_file`, same behavior).
- Consumes: `core.config.CURATED_PROVIDERS`, `core.config.load_settings`, `core.providers.build_router`, `core.providers.verify_router` (all existing, unchanged).

- [ ] **Step 1: Write the failing test for the extracted helper**

```python
# tests/lalo/test_env_file.py
from __future__ import annotations

import stat
from pathlib import Path

from lalo.core.env_file import merge_env_file


def test_merge_env_file_creates_a_fresh_file(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    merge_env_file(path, {"ANTHROPIC_API_KEY": "sk-ant-abc"})
    assert path.read_text(encoding="utf-8") == "ANTHROPIC_API_KEY=sk-ant-abc\n"


def test_merge_env_file_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    merge_env_file(path, {"ANTHROPIC_API_KEY": "sk-ant-abc"})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_merge_env_file_preserves_unrelated_existing_lines(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("SOME_OTHER_VAR=unrelated\n# a comment\n", encoding="utf-8")
    merge_env_file(path, {"ANTHROPIC_API_KEY": "sk-ant-abc"})
    content = path.read_text(encoding="utf-8")
    assert "SOME_OTHER_VAR=unrelated" in content
    assert "ANTHROPIC_API_KEY=sk-ant-abc" in content


def test_merge_env_file_replaces_a_matching_key_in_place(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("ANTHROPIC_API_KEY=old\nOTHER=kept\n", encoding="utf-8")
    merge_env_file(path, {"ANTHROPIC_API_KEY": "sk-ant-new"})
    assert path.read_text(encoding="utf-8").splitlines() == ["ANTHROPIC_API_KEY=sk-ant-new", "OTHER=kept"]
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/lalo/test_env_file.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'lalo.core.env_file'`

- [ ] **Step 3: Create `core/env_file.py` (moved from `setup.py`)**

```python
"""Merge values into a local .env file - owner-only, preserving unrelated
lines, never a blind overwrite. Shared by lalo-setup and the GUI's own
settings endpoint so both use the identical, single-tested implementation.
"""

from __future__ import annotations

from pathlib import Path

from .atomic_io import atomic_write_verified


def merge_env_file(path: Path, values: dict[str, str]) -> None:
    """Update ``path`` with ``values``, replacing matching keys in place and
    preserving every other line untouched - the file may already hold
    unrelated content, so this never blindly overwrites it."""
    remaining = dict(values)
    out_lines: list[str] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            key = stripped.split("=", 1)[0].strip() if "=" in stripped else None
            if key and not stripped.startswith("#") and key in remaining:
                out_lines.append(f"{key}={remaining.pop(key)}")
            else:
                out_lines.append(line)
    out_lines.extend(f"{key}={value}" for key, value in remaining.items())
    atomic_write_verified(path, ("\n".join(out_lines) + "\n").encode("utf-8"))
```

- [ ] **Step 4: Update `setup.py` to use the shared helper**

In `src/lalo/setup.py`: delete the local `_merge_env_file` function body, replace its call site and import:

```python
from .core.env_file import merge_env_file
```

Replace `_merge_env_file(_ENV_PATH, env)` with `merge_env_file(_ENV_PATH, env)`. Delete the now-unused `from .core.atomic_io import atomic_write_verified` import from `setup.py` (it's used inside `env_file.py` now, not here).

- [ ] **Step 5: Update `tests/lalo/test_setup.py`'s imports**

Change `from lalo.setup import _collect_env, _merge_env_file, _prompt_provider, main` to `from lalo.setup import _collect_env, _prompt_provider, main` and `from lalo.core.env_file import merge_env_file`; update the three `_merge_env_file(...)` call sites in that test file to `merge_env_file(...)`.

- [ ] **Step 6: Run tests to verify everything passes**

Run: `uv run pytest tests/lalo/test_env_file.py tests/lalo/test_setup.py -v`
Expected: PASS (14 existing setup tests + 4 new env_file tests)

- [ ] **Step 7: Write the failing test for `GET /settings/providers`**

Add to `tests/lalo/test_gui_app.py`:

```python
def test_get_settings_providers_reports_which_are_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-real")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    client, _ = _client(runs_dir=tmp_path)
    response = client.get("/settings/providers")
    assert response.status_code == 200
    providers = {p["id"]: p["configured"] for p in response.json()["providers"]}
    assert providers["anthropic"] is True
    assert providers["openai"] is False
```

- [ ] **Step 8: Run it to verify it fails**

Run: `uv run pytest tests/lalo/test_gui_app.py::test_get_settings_providers_reports_which_are_configured -v`
Expected: FAIL with 404 (route doesn't exist)

- [ ] **Step 9: Implement `GET /settings/providers`**

In `src/lalo/gui/app.py`, add near the other `@app.get` routes:

```python
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
```

Add imports: `import os` (if not already present), `from ..core.config import CURATED_PROVIDERS, ProviderSpec, load_settings`, `from ..core.providers import build_router, verify_router`.

- [ ] **Step 10: Run it to verify it passes**

Run: `uv run pytest tests/lalo/test_gui_app.py::test_get_settings_providers_reports_which_are_configured -v`
Expected: PASS

- [ ] **Step 11: Write the failing tests for `POST /settings/providers`**

```python
def test_post_settings_providers_verifies_and_writes_env_and_updates_process_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    env_path = tmp_path / ".env"
    monkeypatch.setattr(app_module, "_SETTINGS_ENV_PATH", env_path)
    monkeypatch.setattr(app_module, "verify_router", lambda _router: {"anthropic": (True, "ok")})
    client, _ = _client(runs_dir=tmp_path)
    response = client.post(
        "/settings/providers", json={"provider_id": "anthropic", "api_key": "sk-ant-real", "extra": {}}
    )
    assert response.status_code == 200
    assert env_path.read_text(encoding="utf-8") == "ANTHROPIC_API_KEY=sk-ant-real\n"
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-ant-real"  # picked up by THIS process immediately


def test_post_settings_providers_writes_nothing_on_failed_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_path = tmp_path / ".env"
    monkeypatch.setattr(app_module, "_SETTINGS_ENV_PATH", env_path)
    monkeypatch.setattr(
        app_module, "verify_router", lambda _router: {"anthropic": (False, "401 unauthorized")}
    )
    client, _ = _client(runs_dir=tmp_path)
    response = client.post(
        "/settings/providers", json={"provider_id": "anthropic", "api_key": "sk-ant-bad", "extra": {}}
    )
    assert response.status_code == 400
    assert not env_path.exists()


def test_post_settings_providers_rejects_an_unknown_provider_id(
    tmp_path: Path,
) -> None:
    client, _ = _client(runs_dir=tmp_path)
    response = client.post(
        "/settings/providers", json={"provider_id": "not-a-real-provider", "api_key": "x", "extra": {}}
    )
    assert response.status_code == 400
```

(Add `import os` to the test file's imports if not already present.)

- [ ] **Step 12: Run them to verify they fail**

Run: `uv run pytest tests/lalo/test_gui_app.py -k settings_providers -v`
Expected: FAIL (route doesn't exist / `_SETTINGS_ENV_PATH` doesn't exist)

- [ ] **Step 13: Implement `POST /settings/providers`**

Add the module-level path constant near `_DEFAULT_RUNS_DIR`:

```python
_SETTINGS_ENV_PATH = Path(".env")
```

Add the Pydantic request model near `ScanRequest`:

```python
class ProviderSettingsRequest(BaseModel):
    provider_id: str
    api_key: str
    extra: dict[str, str] = {}
```

Add the route:

```python
    @app.post("/settings/providers")
    def set_provider_settings(request: ProviderSettingsRequest) -> JSONResponse:
        spec = next((s for s in CURATED_PROVIDERS if s.id == request.provider_id), None)
        if spec is None:
            return JSONResponse({"error": f"unknown provider {request.provider_id!r}"}, status_code=400)
        api_key = request.api_key.strip()
        if not api_key:
            return JSONResponse({"error": "'api_key' is required"}, status_code=400)
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
```

Add the import: `from ..core.env_file import merge_env_file`.

- [ ] **Step 14: Run them to verify they pass**

Run: `uv run pytest tests/lalo/test_gui_app.py -k settings_providers -v`
Expected: PASS (3 tests)

- [ ] **Step 15: Full-suite check and commit**

Run: `uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"`

```bash
git add src/lalo/core/env_file.py src/lalo/setup.py src/lalo/gui/app.py tests/lalo/test_env_file.py tests/lalo/test_setup.py tests/lalo/test_gui_app.py
git commit -m "feat(L4L0): in-GUI provider settings (GET/POST /settings/providers)"
```

### Task 4: Advanced scan options (max_steps, budget_ceiling, egress_lock, redact_findings)

**Files:**
- Modify: `src/lalo/gui/app.py` (`ScanRequest`, `start_scan`)
- Test: `tests/lalo/test_gui_app.py`

**Interfaces:**
- Consumes: `ScanConfig` (existing fields `max_steps: int = 25`, `budget_ceiling: int = 300`, `egress_lock: bool = False`, `redact_findings: bool = False` — all unchanged, `redact_findings` landed in a separate commit after this plan was first written).

- [ ] **Step 1: Write the failing test**

```python
def test_scan_request_advanced_options_pass_through_to_scan_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    client.post(
        "/scan",
        json={
            "mission": "find a bug",
            "targets": ["example.com"],
            "max_steps": 10,
            "budget_ceiling": 50,
            "egress_lock": True,
            "redact_findings": True,
        },
    )
    config = current_config()
    assert config.max_steps == 10
    assert config.budget_ceiling == 50
    assert config.redact_findings is True
    assert config.egress_lock is True


def test_scan_request_advanced_options_default_to_scan_configs_own_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    client, _ = _client(runs_dir=tmp_path)
    client.post("/scan", json={"mission": "find a bug", "targets": ["example.com"]})
    config = current_config()
    assert config.max_steps == 25
    assert config.budget_ceiling == 300
    assert config.egress_lock is False
    assert config.redact_findings is False
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/lalo/test_gui_app.py -k advanced_options -v`
Expected: FAIL (`max_steps`/`budget_ceiling`/`egress_lock`/`redact_findings` unexpected keyword arguments on `ScanRequest`, or config values don't match)

- [ ] **Step 3: Add the fields and thread them through**

In `ScanRequest`:

```python
    max_steps: int | None = None
    budget_ceiling: int | None = None
    egress_lock: bool = False
    redact_findings: bool = False
```

In `start_scan`'s non-resume branch, when constructing `ScanConfig`:

```python
            config = ScanConfig(
                mission=mission,
                target_specs=targets,
                exclude_target_specs=exclude_targets,
                rules_of_engagement=request.rules_of_engagement.strip(),
                run_dir=run_dir,
                usage_path=DEFAULT_USAGE_PATH,
                max_steps=request.max_steps if request.max_steps is not None else 25,
                budget_ceiling=request.budget_ceiling if request.budget_ceiling is not None else 300,
                redact_findings=request.redact_findings,
                egress_lock=request.egress_lock,
            )
```

(25/300 match `ScanConfig`'s own current field defaults exactly — keeping them explicit here, rather than omitting the kwargs when `None`, makes the resolved values visible at the call site rather than relying on a reader already knowing `ScanConfig`'s defaults.)

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/lalo/test_gui_app.py -k advanced_options -v`
Expected: PASS

- [ ] **Step 5: Full check and commit**

Run: `uv run ruff check src/lalo/gui/app.py tests/lalo/test_gui_app.py --fix && uv run ruff format src/lalo/gui/app.py tests/lalo/test_gui_app.py && uv run mypy && uv run pytest tests/lalo/test_gui_app.py -q`

```bash
git add src/lalo/gui/app.py tests/lalo/test_gui_app.py
git commit -m "feat(L4L0): expose max_steps/budget_ceiling/egress_lock via POST /scan"
```

### Task 5: Settings drawer UI (providers + advanced options + theme toggle control)

**Files:**
- Modify: `src/lalo/gui/static/index.html` (settings drawer markup, gear button in rail, advanced-options fieldset in composer area)
- Modify: `src/lalo/gui/static/app.js` (drawer open/close, provider list rendering, add-key form submit, advanced-options collection into the `/scan` POST body)
- Modify: `src/lalo/gui/static/app.css` (drawer styles)

**Interfaces:**
- Consumes: `GET /settings/providers`, `POST /settings/providers` (Task 3), the `max_steps`/`budget_ceiling`/`egress_lock` fields on `POST /scan` (Task 4).
- Produces: theme toggle button wired to a `themeToggle` click event that Phase 4/Task 9 attaches real behavior to (this task only needs the button and its `localStorage` no-op-safe presence — Task 9 makes it actually switch themes).

- [ ] **Step 1: Add the settings drawer and gear button markup**

In `index.html`, inside `<aside class="rail">`, right after the `<div class="brand">` block:

```html
<button type="button" id="open-settings" class="btn-icon" aria-label="Settings" title="Settings">⚙</button>
```

Before `</body>`, add the drawer (hidden by default):

```html
<div id="settings-drawer" class="settings-drawer" hidden>
  <div class="settings-drawer-header">
    <span>Settings</span>
    <button type="button" id="close-settings" class="btn-icon" aria-label="Close">✕</button>
  </div>
  <section class="settings-section">
    <h3>Providers</h3>
    <ul id="provider-list" class="provider-list"></ul>
    <form id="provider-form" class="provider-form">
      <select id="provider-select"></select>
      <input id="provider-key-input" type="password" placeholder="API key" autocomplete="off" />
      <button type="submit" class="btn btn-send">Save &amp; verify</button>
    </form>
    <p id="provider-form-status" class="provider-form-status"></p>
  </section>
  <section class="settings-section">
    <h3>Appearance</h3>
    <button type="button" id="theme-toggle" class="btn btn-ghost">Toggle theme</button>
  </section>
</div>
```

Add the advanced-options fieldset near the composer, right before `<form id="composer-form" ...>`:

```html
<details id="advanced-options" class="advanced-options">
  <summary>Advanced options</summary>
  <label>Max steps <input id="opt-max-steps" type="number" min="1" placeholder="25" /></label>
  <label>Budget ceiling <input id="opt-budget-ceiling" type="number" min="1" placeholder="300" /></label>
  <label><input id="opt-egress-lock" type="checkbox" /> Egress lock</label>
  <label><input id="opt-redact-findings" type="checkbox" /> Redact secrets in report/logs</label>
</details>
```

(`redact_findings` defaults to unchecked/`False`, matching `ScanConfig`'s
own default landed alongside this plan: captured secrets appear verbatim
in the report unless an operator explicitly checks this box.)

- [ ] **Step 2: Wire drawer open/close and provider list rendering**

In `app.js`, add near the other DOM references:

```js
const openSettingsBtn = document.getElementById("open-settings");
const closeSettingsBtn = document.getElementById("close-settings");
const settingsDrawer = document.getElementById("settings-drawer");
const providerListEl = document.getElementById("provider-list");
const providerSelectEl = document.getElementById("provider-select");
const providerForm = document.getElementById("provider-form");
const providerKeyInput = document.getElementById("provider-key-input");
const providerFormStatus = document.getElementById("provider-form-status");
```

Add:

```js
async function loadProviderSettings() {
  try {
    const response = await fetch("/settings/providers");
    if (!response.ok) return;
    const body = await response.json();
    providerListEl.replaceChildren();
    providerSelectEl.replaceChildren();
    for (const p of body.providers) {
      const li = document.createElement("li");
      li.textContent = `${p.id} — ${p.configured ? "configured" : "not configured"}`;
      providerListEl.appendChild(li);
      const opt = document.createElement("option");
      opt.value = p.id;
      opt.textContent = p.id;
      providerSelectEl.appendChild(opt);
    }
  } catch {
    // best-effort - settings drawer content, never blocks the live console
  }
}

openSettingsBtn.addEventListener("click", () => {
  settingsDrawer.hidden = false;
  loadProviderSettings();
});
closeSettingsBtn.addEventListener("click", () => {
  settingsDrawer.hidden = true;
});
```

- [ ] **Step 3: Wire the add-key form**

```js
providerForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const providerId = providerSelectEl.value;
  const apiKey = providerKeyInput.value.trim();
  if (!apiKey) return;
  providerFormStatus.textContent = "Verifying…";
  try {
    const response = await fetch("/settings/providers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider_id: providerId, api_key: apiKey, extra: {} }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `request failed (${response.status})`);
    providerFormStatus.textContent = `${providerId} verified and saved.`;
    providerKeyInput.value = "";
    loadProviderSettings();
  } catch (err) {
    providerFormStatus.textContent = `Failed: ${err.message}`;
  }
});
```

- [ ] **Step 4: Collect advanced options into the `/scan` request body**

In `launchFromPrompt`, change the `fetch("/scan", ...)` body to:

```js
      const maxSteps = document.getElementById("opt-max-steps").value;
      const budgetCeiling = document.getElementById("opt-budget-ceiling").value;
      const egressLock = document.getElementById("opt-egress-lock").checked;
      const redactFindings = document.getElementById("opt-redact-findings").checked;
      const response = await fetch("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          mission: text,
          targets,
          ...(maxSteps ? { max_steps: Number(maxSteps) } : {}),
          ...(budgetCeiling ? { budget_ceiling: Number(budgetCeiling) } : {}),
          egress_lock: egressLock,
          redact_findings: redactFindings,
        }),
      });
```

- [ ] **Step 5: Add drawer/advanced-options CSS**

```css
.settings-drawer {
  position: fixed;
  top: 0;
  right: 0;
  width: 320px;
  height: 100vh;
  background: var(--bg-rail);
  border-left: 1px solid var(--border);
  padding: 16px;
  overflow-y: auto;
  z-index: 20;
}
.settings-drawer-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.settings-section { margin-bottom: 20px; }
.provider-list { list-style: none; padding: 0; margin: 0 0 8px; font-size: 0.8rem; color: var(--text-muted); }
.advanced-options { padding: 4px 12px; font-size: 0.78rem; color: var(--text-muted); }
.advanced-options label { display: block; margin: 4px 0; }
```

- [ ] **Step 6: Verify live, with Playwright**

Start `lalo-gui`, click the gear icon, confirm the drawer opens and lists the curated providers with their configured/not-configured status (matches whatever env vars are actually set), submit a key for a provider and confirm the status line reflects success/failure correctly against a real (or intentionally invalid, to see the failure path) key. Expand "Advanced options," set a max-steps value, and confirm (via the Network tab) it's included in the `POST /scan` body when launching.

- [ ] **Step 7: Commit**

```bash
git add src/lalo/gui/static/index.html src/lalo/gui/static/app.js src/lalo/gui/static/app.css
git commit -m "feat(L4L0): settings drawer (providers, advanced scan options, theme toggle button)"
```

---

## Phase 3 — Live shell/terminal panel

### Task 6: `RuntimeContainer.exec_streaming()`

**Files:**
- Modify: `src/lalo/runtime/container.py`
- Test: `tests/lalo/test_runtime_streaming.py`

**Interfaces:**
- Produces: `RuntimeContainer.exec_streaming(command: str | list[str], on_chunk: Callable[[str, str], None], *, timeout: float = 120.0) -> ExecResult` — same `ExecResult` shape `exec()` already returns.
- Consumes: `subprocess.Popen`, `self._docker_bin()`/`self._name` (existing).

- [ ] **Step 1: Write the failing test**

```python
# tests/lalo/test_runtime_streaming.py
"""Hermetic tests for RuntimeContainer.exec_streaming - subprocess.Popen is
mocked, matching test_runtime_timeout.py's own subprocess.run-mocking
convention for this module. No real Docker daemon needed."""

from __future__ import annotations

from unittest.mock import patch

from lalo.runtime import RuntimeConfig, RuntimeContainer


class _FakePopen:
    def __init__(self, argv: list[str], **_kwargs: object) -> None:
        self.argv = argv
        self.stdout = iter(["line one\n", "line two\n"])
        self.stderr = iter(["an error line\n"])
        self.returncode = 0

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9


def _started_container() -> RuntimeContainer:
    container = RuntimeContainer(RuntimeConfig())
    container._started = True  # bypass a real docker start for this unit test
    return container


def test_exec_streaming_calls_on_chunk_for_each_line_of_each_stream() -> None:
    chunks: list[tuple[str, str]] = []
    with patch("lalo.runtime.container.subprocess.Popen", _FakePopen):
        result = _started_container().exec_streaming("echo hi", lambda stream, text: chunks.append((stream, text)))
    assert ("stdout", "line one\n") in chunks
    assert ("stdout", "line two\n") in chunks
    assert ("stderr", "an error line\n") in chunks


def test_exec_streaming_returns_the_same_exec_result_shape_as_exec() -> None:
    with patch("lalo.runtime.container.subprocess.Popen", _FakePopen):
        result = _started_container().exec_streaming("echo hi", lambda _s, _t: None)
    assert result.exit_code == 0
    assert result.stdout == "line one\nline two\n"
    assert result.stderr == "an error line\n"
    assert result.ok is True


def test_exec_streaming_before_start_raises_container_error() -> None:
    from lalo.core.errors import ContainerError
    import pytest

    container = RuntimeContainer(RuntimeConfig())
    with pytest.raises(ContainerError, match="not started"):
        container.exec_streaming("echo hi", lambda _s, _t: None)
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/lalo/test_runtime_streaming.py -v`
Expected: FAIL with `AttributeError: 'RuntimeContainer' object has no attribute 'exec_streaming'`

- [ ] **Step 3: Implement `exec_streaming`**

In `src/lalo/runtime/container.py`, add `import threading` and `from collections.abc import Callable` to the imports, then add the method after `exec()`:

```python
    def exec_streaming(
        self,
        command: str | list[str],
        on_chunk: Callable[[str, str], None],
        *,
        timeout: float = 120.0,
    ) -> ExecResult:
        """Like :meth:`exec`, but calls ``on_chunk(stream, text)`` with output
        as it's produced instead of only returning once the command
        finishes. Returns the identical :class:`ExecResult` shape - the
        streaming is a side channel for a live viewer, never a replacement
        for the agent's own synchronous "run a command, get the final
        result" contract every existing caller of :meth:`exec` relies on.
        """
        if not self._started:
            raise ContainerError("cannot exec: container not started")
        argv = (
            [_docker_bin(), "exec", self._name, "sh", "-c", command]
            if isinstance(command, str)
            else [_docker_bin(), "exec", self._name, *command]
        )
        try:
            process = subprocess.Popen(  # noqa: S603 - resolved binary; workload isolation is the control
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
            )
        except OSError as exc:
            return ExecResult(exit_code=1, stdout="", stderr=str(exc))

        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []

        def _pump(stream: object, sink: list[str], name: str) -> None:
            for line in stream:  # type: ignore[union-attr]
                sink.append(line)
                on_chunk(name, line)

        stdout_thread = threading.Thread(target=_pump, args=(process.stdout, stdout_chunks, "stdout"), daemon=True)
        stderr_thread = threading.Thread(target=_pump, args=(process.stderr, stderr_chunks, "stderr"), daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        try:
            process.wait(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            timed_out = True
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        return ExecResult(
            exit_code=124 if timed_out else process.returncode,
            stdout="".join(stdout_chunks),
            stderr="".join(stderr_chunks) if not timed_out else "".join(stderr_chunks) + "timeout",
            timed_out=timed_out,
        )
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/lalo/test_runtime_streaming.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Type-check and lint, then full runtime suite**

Run: `uv run ruff check src/lalo/runtime/container.py tests/lalo/test_runtime_streaming.py --fix && uv run ruff format src/lalo/runtime/container.py tests/lalo/test_runtime_streaming.py && uv run mypy && uv run pytest tests/lalo/test_runtime.py tests/lalo/test_runtime_timeout.py tests/lalo/test_runtime_streaming.py -q -m "not integration and not live"`
Expected: all pass, `exec()`'s own existing tests unaffected

- [ ] **Step 6: Commit**

```bash
git add src/lalo/runtime/container.py tests/lalo/test_runtime_streaming.py
git commit -m "feat(L4L0): add RuntimeContainer.exec_streaming (additive, exec() unchanged)"
```

### Task 7: Wire streaming into `run_command` and emit `"shell"` events

**Files:**
- Modify: `src/lalo/runtime/tool.py`
- Modify: `src/lalo/gui/events.py` (`EventCategory`)
- Modify: `src/lalo/scan.py` (`_build_registry`'s `build_run_command_tool` call)
- Test: `tests/lalo/test_runtime_tool.py`
- Test: `tests/lalo/test_scan.py`

**Interfaces:**
- Produces: `build_run_command_tool(container, *, timeout=120.0, max_timeout=600.0, on_shell_event: Callable[[dict[str, object]], None] | None = None) -> FunctionTool`.
- Consumes: `RuntimeContainer.exec_streaming` (Task 6), `ScanRunner._emit` (existing).

- [ ] **Step 1: Write the failing test for `run_command`'s new parameter**

`tests/lalo/test_runtime_tool.py` already defines `_FakeExecResult` (a
dataclass with `exit_code`/`stdout`/`stderr`/`timed_out`/`.ok`) and
`_FakeContainer` (holds `.exec()` only, records `last_command`/
`last_timeout`). Add a second fixture class right after `_FakeContainer`,
matching its own style exactly, and the new test after the existing ones:

```python
class _StreamingFakeContainer:
    """Like _FakeContainer, but implements exec_streaming instead of exec -
    exec() raises if called, proving the streaming path is actually taken
    when on_shell_event is provided."""

    def __init__(self, result: _FakeExecResult, chunks: list[tuple[str, str]]) -> None:
        self._result = result
        self._chunks = chunks

    def exec(self, command: str | list[str], *, timeout: float = 120.0) -> _FakeExecResult:
        raise AssertionError("exec() must not be called when on_shell_event is provided")

    def exec_streaming(self, command: str, on_chunk, *, timeout: float = 120.0) -> _FakeExecResult:
        for stream, text in self._chunks:
            on_chunk(stream, text)
        return self._result


def test_run_command_emits_start_chunk_end_shell_events_when_streaming_is_available() -> None:
    result = _FakeExecResult(exit_code=0, stdout="hello\n", stderr="")
    container = _StreamingFakeContainer(result, [("stdout", "hello\n")])
    events: list[dict[str, object]] = []
    tool = build_run_command_tool(container, on_shell_event=events.append)

    outcome = tool.run({"command": "echo hello"})

    assert outcome.ok is True
    assert events[0]["event"] == "start"
    assert events[0]["command"] == "echo hello"
    command_id = events[0]["command_id"]
    assert events[1] == {"event": "chunk", "command_id": command_id, "stream": "stdout", "text": "hello\n"}
    assert events[2] == {"event": "end", "command_id": command_id, "exit_code": 0}
```

No separate "falls back to plain exec" test is needed: every existing
test in this file already calls `build_run_command_tool` with no
`on_shell_event` at all, so Step 5 (re-running the whole file) is itself
the proof that the default path is unaffected.

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/lalo/test_runtime_tool.py -k shell_events_when_streaming -v`
Expected: FAIL with `TypeError: build_run_command_tool() got an unexpected keyword argument 'on_shell_event'`

- [ ] **Step 3: Extend `EventCategory`**

In `src/lalo/gui/events.py`:

```python
EventCategory = Literal["status", "log", "agent", "finding", "steering", "chain", "shell"]
```

- [ ] **Step 4: Implement the `on_shell_event` wiring in `runtime/tool.py`**

Add `import uuid` and `from collections.abc import Callable` to the imports. Change `build_run_command_tool`'s signature and `_run`:

```python
def build_run_command_tool(
    container: CommandExecutor,
    *,
    timeout: float = 120.0,
    max_timeout: float = _DEFAULT_MAX_TIMEOUT_S,
    on_shell_event: Callable[[dict[str, object]], None] | None = None,
) -> FunctionTool:
    def _run(args: dict[str, object]) -> ToolResult:
        command = args.get("command")
        if not isinstance(command, str) or not command.strip():
            return ToolResult(
                observation="error: 'command' (a non-empty string) is required", ok=False
            )
        effective_timeout = _parse_timeout(
            args.get("timeout"), default=timeout, max_timeout=max_timeout
        )
        if isinstance(effective_timeout, str):
            return ToolResult(observation=f"error: {effective_timeout}", ok=False)

        if on_shell_event is not None and hasattr(container, "exec_streaming"):
            command_id = uuid.uuid4().hex[:12]
            on_shell_event({"event": "start", "command_id": command_id, "command": command})

            def _on_chunk(stream: str, text: str) -> None:
                on_shell_event({"event": "chunk", "command_id": command_id, "stream": stream, "text": text})

            result = container.exec_streaming(command, _on_chunk, timeout=effective_timeout)  # type: ignore[attr-defined]
            on_shell_event(
                {"event": "end", "command_id": command_id, "exit_code": getattr(result, "exit_code", None)}
            )
        else:
            result = container.exec(command, timeout=effective_timeout)

        exit_code = getattr(result, "exit_code", None)
        stdout = getattr(result, "stdout", "")
        stderr = getattr(result, "stderr", "")
        ok = bool(getattr(result, "ok", exit_code == 0))
        prefix = (
            f"error: command timed out after {effective_timeout}s\n"
            if getattr(result, "timed_out", False)
            else ""
        )
        observation = f"{prefix}exit_code={exit_code}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        return ToolResult(observation=observation[:_MAX_OBSERVATION_CHARS], ok=ok)

    return FunctionTool(
        name="run_command",
        description=(
            "Run a shell command inside your disposable sandbox container. Full freedom "
            "inside the container -- install anything, run anything -- but nothing here "
            'reaches the host. args: {"command": str, "timeout": number (optional, seconds, '
            f"default {timeout:g}, capped at {max_timeout:g} - raise it for a genuinely "
            "long-running command like a broad scan or a slow install)}"
        ),
        func=_run,
    )
```

- [ ] **Step 5: Run to verify it passes**

Run: `uv run pytest tests/lalo/test_runtime_tool.py -v`
Expected: PASS (every existing test in the file plus the new ones)

- [ ] **Step 6: Wire `scan.py`'s `_build_registry` to pass `on_shell_event`**

Change the `build_run_command_tool(container)` call (currently `scan.py:860`) to:

```python
                build_run_command_tool(
                    container,
                    on_shell_event=lambda payload: self._emit("shell", {"agent_id": self_id, **payload}),
                ),
```

- [ ] **Step 7: Write the failing scan-level test**

`_FakeContainer` in `test_scan.py` currently implements only `.exec()` —
Step 8 below adds `.exec_streaming()` to it, matching Task 6's real
`ExecResult` contract, so this test needs that addition to pass (the
`hasattr(container, "exec_streaming")` guard in `runtime/tool.py` means a
container lacking it would silently fall back to `.exec()` and never emit
`"shell"` events — proving the streaming path requires actually adding it
here first).

Following `_respond`'s own established structure exactly (this file's one
scripted-response convention: check `"FINDING TO REVIEW"` first, then
whether `"MISSION:"` is absent at all — the real `verify_router` preflight
call, whose exact response text `verify_provider` never inspects — then
whether `"HISTORY (most recent last):"` is present to distinguish the
first mission turn from a later one), add a sibling response function and
the test to `tests/lalo/test_scan.py`:

```python
def _respond_run_command_then_finish(call_index: int, prompt: str) -> str:
    if "MISSION:" not in prompt:
        return "ok"
    if "HISTORY (most recent last):" not in prompt:
        return json.dumps({"tool": "run_command", "args": {"command": "ls"}})
    return _finish_call()


def test_scan_runner_emits_shell_events_for_a_real_run_command_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "docker_available", lambda: True)
    monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
    router = ModelRouter(
        providers={"fake": _ScriptedProvider(_respond_run_command_then_finish)},
        routes={"reasoning": ("fake",), "review": ("fake",)},
        default_route=("fake",),
    )
    monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

    event_log = EventLog()
    config = ScanConfig(mission="find a bug", target_specs=["example.com"], run_dir=tmp_path / "run")
    ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}, event_log=event_log).run()

    _cursor, events = event_log.snapshot()
    shell_events = [e for e in events if e.category == "shell"]
    assert any(e.payload.get("event") == "start" for e in shell_events)
    assert any(e.payload.get("event") == "end" and e.payload.get("exit_code") == 0 for e in shell_events)
```

- [ ] **Step 8: Add a minimal `exec_streaming` to `_FakeContainer` in `test_scan.py`**

```python
    def exec_streaming(self, command: object, on_chunk, *, timeout: float = 120.0) -> SimpleNamespace:
        on_chunk("stdout", "")
        return SimpleNamespace(exit_code=0, stdout="", stderr="", ok=True, timed_out=False)
```

- [ ] **Step 9: Run to verify it passes**

Run: `uv run pytest tests/lalo/test_scan.py -k shell_events -v`
Expected: PASS

- [ ] **Step 10: Full check and commit**

Run: `uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"`

```bash
git add src/lalo/runtime/tool.py src/lalo/gui/events.py src/lalo/scan.py tests/lalo/test_runtime_tool.py tests/lalo/test_scan.py
git commit -m "feat(L4L0): stream run_command output as shell events, per-agent"
```

### Task 8: Live shell panel (frontend)

**Files:**
- Modify: `src/lalo/gui/static/index.html` (panel container)
- Modify: `src/lalo/gui/static/app.js` (`applyEvent`'s new `"shell"` branch)
- Modify: `src/lalo/gui/static/app.css` (panel layout — this is the change that makes `.main` share the row with a new right column)

**Interfaces:**
- Consumes: `"shell"` category events (Task 7) shaped `{agent_id, event: "start"|"chunk"|"end", command_id, command?, stream?, text?, exit_code?}`.

- [ ] **Step 1: Add the panel markup**

In `index.html`, change the top-level `<div class="shell">` to include a third column, and add the panel:

```html
<div class="shell">
  <aside class="rail"> ... (unchanged) ... </aside>
  <main class="main"> ... (unchanged) ... </main>
  <aside id="shell-panel" class="shell-output-panel">
    <div class="shell-output-header">Live shell</div>
    <div id="shell-output-list" class="shell-output-list"></div>
  </aside>
</div>
```

- [ ] **Step 2: Add the `applyShellEvent` renderer and wire it into `applyEvent`**

In `app.js`, near `findingCards`:

```js
const shellBlocks = new Map(); // command_id -> the .shell-block element
const shellOutputListEl = document.getElementById("shell-output-list");

function applyShellEvent(payload) {
  const commandId = payload.command_id;
  if (payload.event === "start") {
    const block = document.createElement("pre");
    block.className = "shell-block";
    const header = document.createElement("div");
    header.className = "shell-block-header";
    header.textContent = `$ ${payload.command}`;
    const body = document.createElement("div");
    body.className = "shell-block-body";
    block.appendChild(header);
    block.appendChild(body);
    shellOutputListEl.appendChild(block);
    shellBlocks.set(commandId, block);
    block.scrollIntoView({ block: "end" });
  } else if (payload.event === "chunk") {
    const block = shellBlocks.get(commandId);
    if (!block) return;
    const line = document.createElement("span");
    line.className = payload.stream === "stderr" ? "shell-line-stderr" : "shell-line-stdout";
    line.textContent = payload.text;
    block.querySelector(".shell-block-body").appendChild(line);
    shellOutputListEl.scrollTop = shellOutputListEl.scrollHeight;
  } else if (payload.event === "end") {
    const block = shellBlocks.get(commandId);
    if (!block) return;
    const badge = document.createElement("span");
    badge.className = payload.exit_code === 0 ? "shell-exit-ok" : "shell-exit-fail";
    badge.textContent = `exit ${payload.exit_code}`;
    block.querySelector(".shell-block-header").appendChild(badge);
  }
}
```

Add the case to `applyEvent`'s `switch`:

```js
      case "shell":
        applyShellEvent(event.payload);
        break;
```

- [ ] **Step 3: Add panel layout CSS**

Modify the existing `.shell` rule (`app.css:69-73`, currently
`grid-template-columns: 200px 1fr; min-height: 100vh;`) to add the third
column, keeping `min-height` as-is (unchanged from today, so nothing about
existing page-overflow behavior changes):

```css
.shell {
  display: grid;
  grid-template-columns: 200px 1fr 340px;
  min-height: 100vh;
}
```

Then add the new panel's own rules:

```css
.shell-output-panel {
  background: var(--bg-rail);
  border-left: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.shell-output-header {
  padding: 12px 16px;
  font-size: 0.72rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--text-faint);
  border-bottom: 1px solid var(--border);
}
.shell-output-list {
  flex: 1;
  overflow-y: auto;
  padding: 8px;
  font-family: ui-monospace, "SF Mono", Consolas, monospace;
  font-size: 0.72rem;
}
.shell-block { margin-bottom: 10px; white-space: pre-wrap; word-break: break-word; }
.shell-block-header { color: var(--text-muted); margin-bottom: 2px; }
.shell-line-stdout { color: var(--text); display: block; }
.shell-line-stderr { color: var(--danger); display: block; }
.shell-exit-ok { color: var(--accent); margin-left: 8px; }
.shell-exit-fail { color: var(--danger); margin-left: 8px; }
```

(Check `--danger`/`--accent` are already defined in the existing `:root` token block before using them — they are, per the existing `.btn-ghost:hover` and `.run-item.running` rules.)

- [ ] **Step 4: Verify live, with Playwright and a real target**

This is the one step in this plan that genuinely needs a live scan to prove out (the streaming path only activates when `on_shell_event` is wired, which only happens through a real `ScanRunner` run — a fake/mocked test can prove the wiring but not the felt experience). Bring up a lab target (e.g. VAmPI, per this project's own "bring up only for live work, tear down immediately after" convention), launch a real scan through the GUI, and confirm the right-side panel fills with real command blocks as `run_command` calls happen, each showing real stdout/stderr text and an exit-code badge once it completes. Tear the target container down immediately after.

- [ ] **Step 5: Commit**

```bash
git add src/lalo/gui/static/index.html src/lalo/gui/static/app.js src/lalo/gui/static/app.css
git commit -m "feat(L4L0): render live shell output in a dedicated right-side panel"
```

---

## Phase 4 — Visual redesign

### Task 9: Light theme + working toggle

**Files:**
- Modify: `src/lalo/gui/static/app.css` (light token values, `@media`/`[data-theme]` guards)
- Modify: `src/lalo/gui/static/app.js` (theme toggle behavior + `localStorage` persistence)

**Interfaces:**
- Consumes: `#theme-toggle` button (Task 5, currently inert).

- [ ] **Step 1: Add light tokens alongside the existing dark `:root` block**

The current `:root` block (`app.css:13-34`) defines exactly these custom
properties: `--bg`, `--bg-rail`, `--surface`, `--surface-muted`,
`--border`, `--border-soft`, `--text`, `--text-muted`, `--text-faint`,
`--accent`, `--accent-hover`, `--accent-ink`, `--danger`, `--warning`,
`--caution`, `--focus` (plus `--font-sans`/`--font-mono`/`--radius-*`,
which are theme-independent and don't need light values). Keep the
existing `:root { ... }` block as the dark default (unchanged) and add
every color token's light equivalent — leaving any one of them out would
silently keep that element dark-colored under the light theme:

```css
:root[data-theme="light"] {
  color-scheme: light;
  --bg: #f8fafc;
  --bg-rail: #f1f5f9;
  --surface: #ffffff;
  --surface-muted: #e2e8f0;
  --border: #cbd5e1;
  --border-soft: #e2e8f0;
  --text: #0f172a;
  --text-muted: #475569;
  --text-faint: #64748b;
  --accent: #16a34a;
  --accent-hover: #15803d;
  --accent-ink: #f0fdf4;
  --danger: #dc2626;
  --warning: #d97706;
  --caution: #ca8a04;
  --focus: #16a34a;
}
```

(`color-scheme` is set directly on `:root[data-theme="light"]` here rather
than as a separate rule targeting `html` — `:root` and `html` are the same
element in an HTML document, so this one declaration is enough to override
the existing `html { color-scheme: dark; }` default and make native form
controls/scrollbars render correctly in both themes.)

- [ ] **Step 2: Wire the toggle in `app.js`**

```js
const themeToggleBtn = document.getElementById("theme-toggle");

function applyStoredTheme() {
  let stored = null;
  try {
    stored = localStorage.getItem("lalo-theme");
  } catch {
    // localStorage unavailable (private mode, blocked) - default theme stands
  }
  if (stored === "light" || stored === "dark") {
    document.documentElement.setAttribute("data-theme", stored);
  }
}

themeToggleBtn.addEventListener("click", () => {
  const current = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
  const next = current === "light" ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", next);
  try {
    localStorage.setItem("lalo-theme", next);
  } catch {
    // best-effort persistence only - the toggle still works for this page view
  }
});

applyStoredTheme();
```

- [ ] **Step 3: Verify live, with Playwright**

Load the GUI, click the theme toggle, confirm the whole page (rail, thread, settings drawer, shell panel) switches to a legible light palette with no element left unstyled/invisible, reload the page, confirm the choice persisted.

- [ ] **Step 4: Commit**

```bash
git add src/lalo/gui/static/app.css src/lalo/gui/static/app.js
git commit -m "feat(L4L0): add a real light theme and a working toggle"
```

### Task 10: Full craft pass — authored icons, motion, spacing, states

Expanded from a spacing-only pass after grounding in the persisted design
system (`design-system/l4l0/MASTER.md`) and the impeccable craft-floor
checklist. Four concrete, verified-real gaps, not generic "add polish":
(1) four buttons render an icon as a bare Unicode glyph, which the
craft-floor explicitly names as a tell ("Unicode glyphs or emoji standing
in for an icon system"); (2) the thread has exactly one authored motion
moment (`.log-block .line-fresh`'s fade-in) and nothing else in the UI
animates on append, despite the operator explicitly asking for animation;
(3) text-input carets use the browser default color instead of the
palette; (4) the spacing/border pass originally scoped for this task is
still real and still needed. `prefers-reduced-motion` must be respected by
every new animation, matching the existing guard already established for
`.line-fresh`.

**Files:**
- Modify: `src/lalo/gui/static/index.html` (icon buttons)
- Modify: `src/lalo/gui/static/app.js` (append the new "entering" class at each append site)
- Modify: `src/lalo/gui/static/app.css`

**Interfaces:**
- Consumes: `newAgentTurn()`, `appendUserMessage()`, `buildFindingCard()`, `renderChain()`, `applyShellEvent()`'s `"start"` branch (all existing, from `app.js`) — each gains one line adding an `entering` class to the element it just created/appended.

- [ ] **Step 1: Replace the four Unicode-glyph icon buttons with authored SVG icons**

Match the existing send-button/finding-copy-button convention already in
`index.html`: inline `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">`, one consistent stroke weight, `currentColor` so it inherits the button's existing text color and hover-color transitions with no CSS changes needed.

In `index.html`, replace:

```html
<button type="button" id="open-settings" class="btn-icon" aria-label="Settings" title="Settings">⚙</button>
```

with (a standard gear glyph, 8-tooth, matching the existing icon viewBox convention):

```html
<button type="button" id="open-settings" class="btn-icon" aria-label="Settings" title="Settings">
  <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
</button>
```

Replace `<button type="button" id="close-settings" class="btn-icon" aria-label="Close">✕</button>` with:

```html
<button type="button" id="close-settings" class="btn-icon" aria-label="Close">
  <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="M6 6l12 12"/></svg>
</button>
```

Replace `<button type="button" id="refresh-runs" class="btn-icon" aria-label="Refresh run history" title="Refresh">↻</button>` with:

```html
<button type="button" id="refresh-runs" class="btn-icon" aria-label="Refresh run history" title="Refresh">
  <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2v6h-6"/><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M3 22v-6h6"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/></svg>
</button>
```

Replace `<button type="button" id="jump-latest" class="jump-latest" hidden>↓ New activity</button>` with:

```html
<button type="button" id="jump-latest" class="jump-latest" hidden>
  <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14"/><path d="m19 12-7 7-7-7"/></svg>
  New activity
</button>
```

`.btn-icon`/`.jump-latest` already center their content with flex (`.btn-icon` has no `display: flex` today — add it, since a bare glyph didn't need it but an inline SVG plus text does):

```css
.btn-icon { display: inline-flex; align-items: center; justify-content: center; }
.jump-latest { display: inline-flex; align-items: center; gap: 6px; }
```

- [ ] **Step 2: Add one authored "entering" motion, applied at every append site**

One motion vocabulary, reused everywhere something new appears in the
thread or shell panel — not a different animation per component. Add
next to the existing `@keyframes fade-in-line`:

```css
@keyframes turn-enter {
  from { opacity: 0; transform: translateY(4px); }
  to { opacity: 1; transform: translateY(0); }
}

.entering { animation: turn-enter 220ms ease-out; }

@media (prefers-reduced-motion: reduce) {
  .entering { animation: none; }
}
```

In `app.js`, add the class at each append site — one line per site,
immediately after the element is appended to its parent:

In `newAgentTurn()`, after `threadEl.appendChild(node);`:
```js
msg.classList.add("entering");
```

In `appendUserMessage()`, after `threadEl.appendChild(node);`:
```js
msg.classList.add("entering");
```

In `buildFindingCard()`, the caller `renderFinding()` already has the
card local; add after `body.appendChild(card);` (in the "new finding"
branch only — an in-place severity/confidence update via `replaceWith`
should not re-animate, since that would misleadingly read as a brand new
finding):
```js
card.classList.add("entering");
```

In `renderChain()`, after `body.appendChild(card);`:
```js
card.classList.add("entering");
```

In `applyShellEvent()`'s `"start"` branch, after `shellOutputListEl.appendChild(block);`:
```js
block.classList.add("entering");
```

This reuses the exact class-added-on-append idiom `.log-block .line-fresh`
already established (`appendScrollback`'s `line.className = "line-fresh"`)
— extending an existing pattern rather than inventing a second one.

- [ ] **Step 3: Theme the input caret**

```css
#composer-input,
#provider-key-input {
  caret-color: var(--accent);
}
```

- [ ] **Step 4: Normalize the spacing scale**

Audit `app.css` for one-off padding/margin values and replace them with a consistent 4/8/12/16/24px rhythm (e.g. a `7px 6px` padding on `.run-item` becomes `8px`; a `24px 24px 0` on `.main` stays, since it already fits the scale). This is a values-only pass — no selectors change, so no rendering logic is at risk, only spacing consistency.

- [ ] **Step 5: Add a subtle card border to finding/chain/shell-block elements**

```css
.finding-card, .chain-card, .shell-block { border: 1px solid var(--border); border-radius: 8px; padding: 8px 10px; }
```

- [ ] **Step 6: Fix the "exit null" display gap flagged in Task 8's review**

In `applyShellEvent`'s `"end"` branch (`app.js`), `payload.exit_code` can
genuinely be `null` (a timed-out command never gets a real exit code —
see `runtime/tool.py`'s `getattr(result, "exit_code", None)`). Render `—`
instead of the literal string `"null"`:

```js
badge.textContent = payload.exit_code === null || payload.exit_code === undefined
  ? "exit —"
  : `exit ${payload.exit_code}`;
```

- [ ] **Step 7: Verify live, with Playwright, in both themes**

Load the GUI in both dark and light mode (Task 9 must land first). Confirm: the four buttons render crisp SVG icons (not glyphs) that inherit hover color correctly; a new agent turn/finding/chain/shell block visibly fades and rises in on append, and does NOT re-animate on an in-place finding update; toggling the OS/browser's reduced-motion setting (or emulating it via Playwright) removes the animation entirely with content still appearing; the composer/provider-key input carets render in the accent color; spacing and card borders read correctly against both palettes (no invisible borders, no clashing contrast); a simulated timed-out shell command (exit_code omitted/null in a replayed run) shows "exit —", not "exit null".

- [ ] **Step 8: Commit**

```bash
git add src/lalo/gui/static/index.html src/lalo/gui/static/app.js src/lalo/gui/static/app.css
git commit -m "style(L4L0): authored SVG icons, one motion vocabulary, spacing/border polish"
```

---

## Final check (after all 10 tasks)

Run: `uv run ruff check src/lalo tests/lalo && uv run ruff format --check src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"`

Then a full live Playwright walkthrough covering everything in one pass: open a past run, continue it, open settings and add/verify a provider key, set an advanced option and launch a scan, watch the live shell panel fill in, toggle the theme.
