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

## Phase 5 — Capability-gap features

Sourced from a multi-lens brainstorm workflow grounded in real code reads
across agent-methodology, report-findings-richness, operator-productivity,
and observability-debugging. Every cheap/medium-effort idea from that pass
is folded in below (the one large-effort idea — a verbatim closure-decision
ledger surviving history compaction — is explicitly excluded, per an
earlier "cheap and medium everything" scoping decision). Grouped into 9
tasks by code locality rather than 19 separate task-loops, since most of
these are small, independent, file-disjoint features better reviewed
together than ceremony-per-idea.

**A note on precision for this phase:** the exact current signatures below
were gathered via direct source research this session (not guessed), but a
few specifics (an exact returned-dict shape, an exact accessor name on
`AgentCoordinator`, `FireResult`'s exact fields, `FindingRecord`'s exact
field list, whether `AgentLoop` already tracks root-vs-child) were not
independently confirmed and are flagged inline as "verify against the live
file" — this is the same discipline every earlier task in this plan already
used when a brief's snapshot might have drifted from the current file; here
it's flagged because the research pass didn't reach 100% instead of because
time passed, but the resolution is identical: the real file wins.

### Task 11: Observability core — wall-clock timestamps, agent-id tagging, split step span

**Files:**
- Modify: `src/lalo/gui/events.py`
- Modify: `src/lalo/orchestrator/journal.py`
- Modify: `src/lalo/observability/tracing.py`
- Modify: `src/lalo/agent/loop.py`
- Test: `tests/lalo/test_events.py`, `tests/lalo/test_journal.py`, `tests/lalo/test_tracing.py` (create if they don't already exist, mirroring this project's `tests/lalo/test_<module>.py` convention), plus whichever existing test file already exercises `AgentLoop` directly (find it — likely `tests/lalo/test_loop.py` or `tests/lalo/test_agent_loop.py`)

**Interfaces:**
- Produces: `Event.ts: float` (wall-clock, `time.time()`-based), `Checkpoint.ts: float`, `Span.wall_start: float` — all additive fields with `field(default_factory=time.time)` defaults, so every existing construction call site keeps working unchanged.
- Consumes: `Tracer.span(name, **attributes) -> Iterator[Span]` (existing, `src/lalo/observability/tracing.py`) — confirmed the yielded `Span`'s `.attributes` dict is mutable inside the `with` block, so tagging can happen via attribute assignment, not a new constructor argument.

- [ ] **Step 1: Add `ts` to `Event`**

In `src/lalo/gui/events.py`, add `import time` if not already present, and add a `ts` field to the `Event` dataclass:

```python
@dataclass
class Event:
    id: str
    category: EventCategory
    payload: dict[str, Any]
    version: int = 1
    ts: float = field(default_factory=time.time)
```

(Read the file first to confirm the exact current field list and whether `field` is already imported from `dataclasses`.)

Test:
```python
def test_event_carries_a_wall_clock_timestamp() -> None:
    before = time.time()
    log = EventLog()
    event = log.append("status", {"event": "x"})
    after = time.time()
    assert before <= event.ts <= after
```

- [ ] **Step 2: Add `ts` to `Checkpoint`**

In `src/lalo/orchestrator/journal.py`:
```python
@dataclass(frozen=True)
class Checkpoint:
    key: str
    result: Any
    ts: float = field(default_factory=time.time)
```
`DurableJournal.record(key, result)`'s signature is unchanged — it just picks up the new field's default.

Test: record a checkpoint, confirm `.get(key).ts` is a real wall-clock time within a tight window of the call.

- [ ] **Step 3: Add `wall_start` to `Span`**

In `src/lalo/observability/tracing.py` (the `Span` dataclass currently has `name: str`, `start: float`, `end: float | None = None`, `attributes: dict[str, Any]` — `start`/`end` are `time.monotonic()`-based, correct for duration math, and must stay that way):
```python
@dataclass
class Span:
    name: str
    start: float
    end: float | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    wall_start: float = field(default_factory=time.time)
```

Test: create a span via `Tracer().span("x")`, confirm `.wall_start` is within a tight window of `time.time()` at creation.

- [ ] **Step 4: Tag `agent_step` with `agent_id`, split into nested `llm_completion`/`tool_dispatch` spans, add a per-tool-name counter**

Read `src/lalo/agent/loop.py` around its `agent_step` span (currently `with self.tracer.span("agent_step", step=step):`, wrapping both the LLM completion call and the tool-dispatch call together — this is why "slow because the LLM took 40s" can never be told apart from "slow because a tool took 40s") and its `tool_calls` counter (currently `self.tracer.counter("tool_calls")`, one global counter with no per-tool breakdown). `AgentLoop.__init__` already takes `agent_id: str | None = None` and stores `self.agent_id`.

Change the outer span to carry identity:
```python
with self.tracer.span("agent_step", step=step, agent_id=self.agent_id):
```

Wrap the LLM completion call in its own nested span, and the tool-dispatch call in its own nested span carrying the tool name:
```python
with self.tracer.span("llm_completion", step=step, agent_id=self.agent_id):
    # ... the existing completion call, unchanged ...

with self.tracer.span("tool_dispatch", step=step, agent_id=self.agent_id, tool=call.name):
    # ... the existing dispatch call, unchanged ...
```

Add a per-tool-name counter alongside the existing aggregate (keep the aggregate — nothing should stop incrementing what it already increments):
```python
self.tracer.counter("tool_calls")
self.tracer.counter(f"tool_calls:{call.name}")
```

- [ ] **Step 5: Write the `AgentLoop`-level test**

Find the existing test file that already constructs a real `AgentLoop` and drives one `.run()` call against a scripted/fake provider (there should be one, given `AgentLoop` is the core execution primitive). Add a test asserting, after one run with at least one tool call:
- `loop.tracer.spans` contains a span named `"llm_completion"` and one named `"tool_dispatch"` (not just the outer `"agent_step"`), both carrying `attributes["agent_id"] == loop.agent_id`.
- `loop.tracer.counters` contains both `"tool_calls"` and a `f"tool_calls:{<the tool actually called>}"` key.

Match whatever scripted-provider/fake-tool convention that existing test file already uses — do not invent a new one.

- [ ] **Step 6: Run tests, full suite, commit**

Run the new/modified test files, then `uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"`.

```bash
git add src/lalo/gui/events.py src/lalo/orchestrator/journal.py src/lalo/observability/tracing.py src/lalo/agent/loop.py tests/lalo/test_events.py tests/lalo/test_journal.py tests/lalo/test_tracing.py
git commit -m "feat(L4L0): wall-clock timestamps, agent-id span tagging, per-tool counters"
```

### Task 12: Per-agent usage-delta surfacing + budget burn-rate

**Files:**
- Modify: `src/lalo/scan.py` (the usage-diffing block, currently doing flat-total diffs only; the `scan_completed` event's `usage_delta` payload)
- Modify: `src/lalo/agent/loop.py` (record budget fraction/band into the `agent_step` span each step)
- Test: `tests/lalo/test_scan.py`, `tests/lalo/test_usage.py` (if it exists)

**Interfaces:**
- Consumes: `UsageStats.by_agent: dict[str, dict[str, float]]` (existing, already populated per-agent via `record_usage(..., agent_id=...)`), `Budget.fraction() -> float`, `Budget.band(is_root: bool) -> BudgetBand` (existing, `src/lalo/orchestrator/budget.py`).

- [ ] **Step 1: Write a `_diff_by_agent` helper and wire it into the usage-delta block**

In `src/lalo/scan.py`, near the existing flat-total usage diffing (`usage_after.<field> - usage_before.<field>` for requests/input_tokens/output_tokens/cost_usd — find this block, it currently computes `report_usage`/feeds `scan_completed`'s `usage_delta`), add:

```python
def _diff_by_agent(
    before: dict[str, dict[str, float]], after: dict[str, dict[str, float]]
) -> dict[str, dict[str, float]]:
    """Diff two UsageStats.by_agent maps key-for-key, the same way flat
    totals are already diffed - the data was already computed and thrown
    away; this just stops throwing it away."""
    result: dict[str, dict[str, float]] = {}
    for agent_id in set(before) | set(after):
        b, a = before.get(agent_id, {}), after.get(agent_id, {})
        result[agent_id] = {
            field: a.get(field, 0) - b.get(field, 0)
            for field in ("requests", "input_tokens", "output_tokens", "cost_usd")
        }
    return result
```

Call it alongside the existing flat diff and add the result under a `"by_agent"` key in the `scan_completed` event's `usage_delta` payload (find where that payload dict is built and add one key — don't restructure the existing flat fields).

- [ ] **Step 2: Write the test**

Follow `test_scan.py`'s existing `_ScriptedProvider`/`_respond`-style convention. Construct a scan whose script causes at least one `spawn_agent` call (so a second `agent_id` besides `"root"` records usage), run it, and assert:

```python
_cursor, events = event_log.snapshot()
completed = next(e for e in events if e.category == "status" and e.payload.get("event") == "scan_completed")
by_agent = completed.payload["usage_delta"]["by_agent"]
assert by_agent["root"]["requests"] >= 1
```

(If constructing a real spawned child in this test is heavier than a single-agent test, a single-agent scan is still a valid test of the mechanism — assert `by_agent["root"]["requests"] >= 1` and that no other keys appear, and note in a comment that a multi-agent variant would additionally prove per-child attribution.)

- [ ] **Step 3: Record a budget burn-rate reading into each `agent_step` span**

In `src/lalo/agent/loop.py`, inside the (now-outer, per Task 11) `with self.tracer.span("agent_step", ...) as span:` block, after the budget is spent for that step, record the current reading directly onto the span's mutable `attributes` dict:

```python
span.attributes["budget_fraction"] = self.budget.fraction()
span.attributes["budget_band"] = self.budget.band(is_root=<is this loop the root?>).name
```

`Budget.band()` takes an `is_root: bool` — determine how `AgentLoop` currently knows whether it IS the root (read the constructor/`.run()` call sites; the root is invoked via `root_loop.run(mission, journal=journal, agent_key="root")` elsewhere, so there may already be an `agent_key`/`is_root`-shaped signal on the loop, or you may need to add one explicitly — if none exists, add a simple `is_root: bool = False` constructor parameter, defaulting to `False` so every existing (child) construction site is unaffected, and set it `True` only at the one root-loop construction site in `scan.py`).

This gives a walkable burn curve for free: any consumer can filter `tracer.spans` by `name == "agent_step"` and read `(span.wall_start, attributes["budget_fraction"], attributes["budget_band"])` in order — no new data structure needed, reusing exactly what Task 11 already made queryable.

- [ ] **Step 4: Write the test**

Assert, after a run with at least 2 steps, that at least 2 `"agent_step"` spans exist and each has `attributes["budget_fraction"]` present and monotonically non-decreasing across steps (spend only grows).

- [ ] **Step 5: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/scan.py src/lalo/agent/loop.py tests/lalo/test_scan.py
git commit -m "feat(L4L0): surface per-agent usage deltas and a budget burn-rate reading per step"
```

### Task 13: Persist full tool observations for spawned children

**Files:**
- Modify: `src/lalo/agent/loop.py`
- Test: `tests/lalo/test_scan.py` or wherever `AgentLoop`'s `tool_result` emission is already tested

**Context:** Today, `self._emit("tool_result", {"tool": call.name, "ok": ok})` (confirmed at the point right after the journal-entry-building code, so `observation` is already a local variable in scope there) carries only `{tool, ok}` for every agent, root and child alike. The FULL `{tool, args, observation, ok}` shape only ever lands in the root's own local transcript list and, when journaled, `DurableJournal`'s persisted entry (root-only, since only the root loop is ever constructed with `journal=<a real DurableJournal>`; a spawned child always gets `journal=None`). Since `EventLog` (unlike the journal) already durably persists every event for the WHOLE run regardless of which agent emitted it, the simplest, lowest-risk fix is adding `observation` to the `tool_result` payload itself — no new journal/checkpoint plumbing, and critically, no change to the journal's root-only *resume* semantics (children still correctly restart from scratch on resume; this task is about post-hoc debugging visibility, not resumability).

**Interfaces:**
- Produces: every `"tool_result"`-category event's payload gains an `observation` key (truncated) alongside the existing `tool`/`ok` keys.

- [ ] **Step 1: Add a truncated observation to every `tool_result` emit**

In `src/lalo/agent/loop.py`, add a module-level constant near the top (following the existing convention of a `_MAX_..._CHARS`-style constant elsewhere in this codebase, e.g. `runtime/tool.py`'s `_MAX_OBSERVATION_CHARS`):

```python
_MAX_EMITTED_OBSERVATION_CHARS = 2000
```

Change the `_emit("tool_result", ...)` call to:
```python
self._emit(
    "tool_result",
    {"tool": call.name, "ok": ok, "observation": observation[:_MAX_EMITTED_OBSERVATION_CHARS]},
)
```

- [ ] **Step 2: Write the failing test, then verify it passes**

Using `test_scan.py`'s existing conventions, drive a scan whose scripted response causes at least one real tool call (e.g. `run_command`, following `_respond_run_command_then_finish`'s existing pattern from an earlier task in this plan), then:

```python
_cursor, events = event_log.snapshot()
tool_result_events = [e for e in events if e.category == "log" and e.payload.get("tool") is not None]
assert any("observation" in e.payload and e.payload["observation"] for e in tool_result_events)
```

(Confirm the actual event `category` the `tool_result` payload lands under by reading `AgentLoop._emit`'s call — it may be `"log"` or a different category; use whatever the real code shows, don't assume.)

If feasible without excessive new scaffolding, extend this test (or add a second one) to prove the SAME behavior for a spawned child's tool call specifically, since that's the actual gap this task closes — if constructing a child in this test file requires substantially more scaffolding than a root-only test, a root-only test that proves the mechanism plus a one-line comment noting "the same `_emit` call path is used for every `AgentLoop` instance, root or child, so this applies identically to spawned children" is an acceptable, honestly-scoped substitute — say which you did in your report.

- [ ] **Step 3: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/agent/loop.py tests/lalo/test_scan.py
git commit -m "feat(L4L0): persist a truncated tool observation for every agent, not just the root"
```

### Task 14: Report enrichment — CWE/OWASP mapping, CSV export, Mermaid attack-chain diagrams

**Files:**
- Create: `src/lalo/report/taxonomy.py`
- Modify: `src/lalo/report/sarif.py`
- Modify: `src/lalo/report/markdown.py`
- Modify: `src/lalo/report/html.py`
- Create: `src/lalo/report/csv_export.py`
- Modify: wherever report formats are dispatched/written (find it — the GUI's `REPORT_LINK_PREFERENCE = ["pdf", "md", "json", "sarif", "docx"]` in `app.js` names the existing formats; find the corresponding Python-side format dispatch, likely in `src/lalo/report/collect.py` or `scan.py`'s report-writing call, and add `"csv"` alongside the existing ones)
- Test: `tests/lalo/test_sarif.py`, `tests/lalo/test_markdown.py`, `tests/lalo/test_html.py` (extend if they exist), `tests/lalo/test_csv_export.py` (create)

**Interfaces:**
- Produces: `cwe_for(vuln_class: str) -> str | None` (`taxonomy.py`), `csv_safe(value: str) -> str` and `build_csv(records: list[FindingRecord]) -> str` (`csv_export.py`).
- Consumes: `FindingRecord` (`src/lalo/report/collect.py:45`) — read its exact current field list before writing `build_csv`; it is NOT the same dataclass as the agent-facing `Finding` in `findings/model.py` (which has `title`/`vuln_class`/`target`/`remediation`/etc.) — `FindingRecord` is the report-layer shape and may have a different/overlapping field set. Verify directly.
- Consumes: `build_chain_records(chains, records) -> list[ChainRecord]` where `ChainRecord = {finding_ids: list[str], titles: list[str]}` (`src/lalo/report/collect.py:177`, existing).

- [ ] **Step 1: Write the curated CWE mapping**

```python
# src/lalo/report/taxonomy.py
"""Curated vuln_class -> CWE mapping for compliance-oriented report
consumers (SARIF viewers, OWASP-mapped dashboards). Intentionally small
and curated, not exhaustive - an unmapped vuln_class degrades to no CWE
line, never an error."""

from __future__ import annotations

CWE_BY_VULN_CLASS: dict[str, str] = {
    "sql-injection": "CWE-89",
    "command-injection": "CWE-78",
    "ssti": "CWE-1336",
    "xxe": "CWE-611",
    "ssrf": "CWE-918",
    "idor": "CWE-639",
    "broken-access-control": "CWE-284",
    "xss": "CWE-79",
    "path-traversal": "CWE-22",
    "insecure-deserialization": "CWE-502",
    "authentication-bypass": "CWE-287",
    "cors-misconfiguration": "CWE-942",
    "prototype-pollution": "CWE-1321",
    "cache-poisoning": "CWE-444",
    "web-cache-deception": "CWE-524",
    "race-conditions": "CWE-362",
    "http-request-smuggling": "CWE-444",
}


def cwe_for(vuln_class: str) -> str | None:
    """Best-effort CWE ID for a vuln_class slug, or None if unmapped."""
    return CWE_BY_VULN_CLASS.get(vuln_class.strip().lower())
```

Before finalizing, enumerate the actual `name:`/vuln-class-shaped frontmatter values across every file in `src/lalo/skills/content/vulnerabilities/*.md` (30+ files, one per vuln class) and extend this dict to cover as many as you reasonably can — the list above is a floor, not the final answer. Test:

```python
def test_cwe_for_known_vuln_class_returns_mapped_id() -> None:
    assert cwe_for("sql-injection") == "CWE-89"

def test_cwe_for_unknown_vuln_class_returns_none() -> None:
    assert cwe_for("not-a-real-class") is None
```

- [ ] **Step 2: Wire CWE into SARIF's rule relationships**

In `src/lalo/report/sarif.py`, find `_build_rule(record: FindingRecord) -> dict[str, Any]` and add a `relationships` entry when a mapping exists:

```python
cwe = cwe_for(record.vuln_class)
if cwe:
    rule["relationships"] = [
        {"target": {"id": cwe, "toolComponent": {"name": "CWE"}}, "kinds": ["relevant"]}
    ]
```

Test: build a rule for a `FindingRecord` with a mapped `vuln_class`, assert `relationships` is present with the right CWE id; build one for an unmapped class, assert no `relationships` key (never an empty list — absent).

- [ ] **Step 3: Add a CWE line to Markdown and HTML, per finding**

In `src/lalo/report/markdown.py` and `src/lalo/report/html.py`, find wherever each finding's `vuln_class` is currently rendered per-finding and add a CWE line right after it when `cwe_for(record.vuln_class)` returns a value (skip the line entirely when unmapped — never print "CWE: None").

- [ ] **Step 4: Mermaid attack-chain diagrams alongside the existing bullet**

In `src/lalo/report/markdown.py`, the existing chain rendering is `f"- {' → '.join(chain.titles)}"` per `ChainRecord`. Keep that bullet (explicit plain-text fallback) and add a Mermaid block after the full list of chains:

```python
def _render_chains_mermaid(chains: list[ChainRecord]) -> str:
    if not chains:
        return ""
    lines = ["```mermaid", "flowchart LR"]
    for i, chain in enumerate(chains):
        node_ids = [f"c{i}n{j}" for j in range(len(chain.titles))]
        for node_id, title in zip(node_ids, chain.titles, strict=True):
            lines.append(f'    {node_id}["{title.replace(chr(34), chr(39))}"]')
        for a, b in zip(node_ids, node_ids[1:], strict=True):
            lines.append(f"    {a} --> {b}")
    lines.append("```")
    return "\n".join(lines)
```

Call this once, after the existing bullet list, and include its output in the rendered Markdown report. (HTML report: Mermaid needs a JS renderer in a browser context that a static `.html` report file may or may not already load — check whether `html.py`'s output already includes a `<script>` tag anywhere; if not, skip the Mermaid addition for HTML and note in a comment why, rather than shipping an inert `\`\`\`mermaid` code fence with no renderer.)

Test: build `_render_chains_mermaid` output for 2 chains sharing one node, assert both `flowchart LR` and the expected `-->` edges appear, and that a chain title containing a `"` character doesn't break the Mermaid node syntax (gets converted to `'`).

- [ ] **Step 5: CSV export with a formula-injection guard**

First, read `FindingRecord`'s exact field list at `src/lalo/report/collect.py:45` directly — do not guess field names.

```python
# src/lalo/report/csv_export.py
"""CSV export of findings - flat, spreadsheet-friendly, with
formula-injection escaping since finding fields are attacker-influenced
text flowing into a spreadsheet formula-injection sink (a cell starting
with =, +, -, @, tab, or CR is interpreted by Excel/Sheets as a formula,
not literal text)."""

from __future__ import annotations

import csv
import io

from .collect import FindingRecord

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: str) -> str:
    """Prefix a leading apostrophe if value would otherwise be interpreted
    as a spreadsheet formula by Excel/Sheets."""
    return "'" + value if value and value[0] in _FORMULA_PREFIXES else value


def build_csv(records: list[FindingRecord]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    # Use FindingRecord's real field names here, at minimum: a finding
    # identifier, title, severity, vuln_class, target, confidence, remediation.
    writer.writerow([...])
    for record in records:
        writer.writerow([csv_safe(str(v)) for v in [...]])
    return buf.getvalue()
```

Test:
```python
def test_csv_safe_prefixes_a_leading_formula_character() -> None:
    assert csv_safe("=cmd|' /C calc'!A1").startswith("'=")

def test_csv_safe_leaves_ordinary_text_unchanged() -> None:
    assert csv_safe("ordinary title") == "ordinary title"

def test_build_csv_includes_a_header_and_one_row_per_finding() -> None:
    csv_text = build_csv([<one real FindingRecord>])
    rows = csv_text.strip().splitlines()
    assert len(rows) == 2  # header + one data row
```

- [ ] **Step 6: Wire `"csv"` into the report-format dispatch**

Find where `"pdf"`/`"md"`/`"json"`/`"sarif"`/`"docx"` are dispatched to their writer functions (report-writing orchestration, likely `scan.py` or `report/collect.py`) and add `"csv": build_csv` (or the equivalent call) alongside them, so a scan's `report_paths`/GUI report-download options gain a `csv` entry the same way every other format already does.

- [ ] **Step 7: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/report/taxonomy.py src/lalo/report/sarif.py src/lalo/report/markdown.py src/lalo/report/html.py src/lalo/report/csv_export.py tests/lalo/test_sarif.py tests/lalo/test_markdown.py tests/lalo/test_html.py tests/lalo/test_csv_export.py
git commit -m "feat(L4L0): CWE/OWASP mapping, CSV export, Mermaid attack-chain diagrams in reports"
```

### Task 15: Cross-run finding diff + operator-settable finding lifecycle status

**Files:**
- Modify: `src/lalo/report/collect.py` (`FindingRecord` gains `dedup_key: str = ""` and `status: str = "open"` fields)
- Create: `src/lalo/report/history.py`
- Modify: `src/lalo/report/overrides.py` (add a `StatusOverride` dataclass + `apply_status_overrides`, mirroring the existing `SeverityOverride`/`apply_overrides` pattern exactly)
- Test: `tests/lalo/test_history.py` (create), `tests/lalo/test_overrides.py` (extend)

**Scope note:** this task covers the backend mechanism only (diff + status-override dataclass/apply function, both non-destructive per the existing `overrides.py` pattern — never mutates the graph, always returns new records). A GUI affordance to actually set a status from the console is a natural follow-on, not part of this task's scope.

**Interfaces:**
- Consumes: `dedup_key(vuln_class, target, param) -> str` (existing, `src/lalo/findings/dedup.py:23`, deterministic).
- Produces: `FindingDiff(new: list[FindingRecord], resolved: list[FindingRecord], persisting: list[tuple[FindingRecord, FindingRecord]])` and `diff_findings(previous, current) -> FindingDiff` (`history.py`); `StatusOverride(finding_id, status, reason, overridden_by)` and `apply_status_overrides(records, overrides) -> list[FindingRecord]` (`overrides.py`).

- [ ] **Step 1: Add `dedup_key` and `status` fields to `FindingRecord`**

Read `src/lalo/report/collect.py:45`'s exact current `FindingRecord` fields first. Add:
```python
    dedup_key: str = ""
    status: str = "open"
```
Find wherever `FindingRecord` is actually constructed (grep `FindingRecord(`) and populate `dedup_key=dedup_key(record.vuln_class, record.target, record.param)` at that call site, reusing the existing `dedup_key()` function — every other existing construction site (if there's more than one) keeps working since both new fields default.

- [ ] **Step 2: Write `diff_findings`**

```python
# src/lalo/report/history.py
"""Diff findings across two runs of the same target by dedup_key - lets an
operator re-scanning a target see what's new/resolved/persisting instead
of eyeballing two report.json files by hand."""

from __future__ import annotations

from dataclasses import dataclass

from .collect import FindingRecord


@dataclass(frozen=True)
class FindingDiff:
    new: list[FindingRecord]
    resolved: list[FindingRecord]
    persisting: list[tuple[FindingRecord, FindingRecord]]


def diff_findings(previous: list[FindingRecord], current: list[FindingRecord]) -> FindingDiff:
    previous_by_key = {r.dedup_key: r for r in previous if r.dedup_key}
    current_by_key = {r.dedup_key: r for r in current if r.dedup_key}
    new = [r for key, r in current_by_key.items() if key not in previous_by_key]
    resolved = [r for key, r in previous_by_key.items() if key not in current_by_key]
    persisting = [
        (previous_by_key[key], current_by_key[key]) for key in current_by_key if key in previous_by_key
    ]
    return FindingDiff(new=new, resolved=resolved, persisting=persisting)
```

Test:
```python
def test_diff_findings_buckets_new_resolved_and_persisting() -> None:
    shared = _finding(dedup_key="k1")
    only_previous = _finding(dedup_key="k2")
    only_current = _finding(dedup_key="k3")
    diff = diff_findings(previous=[shared, only_previous], current=[shared, only_current])
    assert diff.new == [only_current]
    assert diff.resolved == [only_previous]
    assert diff.persisting == [(shared, shared)]
```
(Write a small `_finding(dedup_key=...)` test helper constructing a minimal valid `FindingRecord` with the other required fields filled with placeholder-but-valid test values.)

- [ ] **Step 3: Add `StatusOverride`, mirroring `SeverityOverride` exactly**

Read `src/lalo/report/overrides.py`'s existing `SeverityOverride`/`apply_overrides` first, then add the parallel pair:

```python
@dataclass(frozen=True)
class StatusOverride:
    finding_id: str
    status: str  # "open" | "false_positive" | "accepted_risk" | "remediated" | "needs_retest"
    reason: str
    overridden_by: str


def apply_status_overrides(
    records: list[FindingRecord], overrides: list[StatusOverride]
) -> list[FindingRecord]:
    latest_by_id = {o.finding_id: o for o in overrides}  # last-one-wins, matching apply_overrides
    return [
        dataclasses.replace(record, status=latest_by_id[record.finding_id].status)
        if record.finding_id in latest_by_id
        else record
        for record in records
    ]
```

Test (mirror whatever test already exists for `apply_overrides`): applying a `StatusOverride` changes only the targeted record's `status`, never mutates the input list, and a finding not present in `records` is silently ignored rather than raising.

- [ ] **Step 4: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/report/collect.py src/lalo/report/history.py src/lalo/report/overrides.py tests/lalo/test_history.py tests/lalo/test_overrides.py
git commit -m "feat(L4L0): cross-run finding diff and an operator-settable finding lifecycle status"
```

### Task 16: New agent tools — `fire_concurrent` and `diff_responses`

**Files:**
- Modify: `src/lalo/execution/tool.py` (add `build_fire_concurrent_tool`, `build_diff_responses_tool`, alongside the existing `build_http_tool`)
- Modify: `src/lalo/scan.py` (register both new tools in the tool registry list, alongside the existing `build_http_tool(firer)` call)
- Test: whichever test file already exercises `build_http_tool` (find it — likely `tests/lalo/test_execution_tool.py`)

**Context:** `HttpFirer.fire(method, url, *, headers=None, content=None) -> FireResult` is the only single-request firer; no concurrent-fire method exists anywhere, and the only `ThreadPoolExecutor` in the codebase drives `spawn_agents`' child agent loops, not wire-level request simultaneity. `race-conditions.md`'s core technique ("fire 5-20 identical requests as close to simultaneously as possible") is architecturally unreachable without this tool. Before writing either tool, read `FireResult`'s exact dataclass fields (status code, body, timing — the exact attribute names weren't independently confirmed) directly from its definition, and read `build_http_tool`'s exact existing implementation in `src/lalo/execution/tool.py` to match its argument-parsing idioms (`str_arg` from `agent/tools.py`, `_MAX_BODY_CHARS` truncation) exactly.

**Interfaces:**
- Produces: `build_fire_concurrent_tool(firer: HttpFirer) -> FunctionTool`, `build_diff_responses_tool(firer: HttpFirer) -> FunctionTool`.

- [ ] **Step 1: `fire_concurrent`**

```python
def build_fire_concurrent_tool(firer: HttpFirer) -> FunctionTool:
    """Fire N near-identical requests as close to simultaneously as
    possible, for race-condition testing - the one wire-level-simultaneity
    gap the agent's single-request-per-tool-call loop can't otherwise reach."""

    def _fire_concurrent(args: dict[str, object]) -> ToolResult:
        method = str_arg(args, "method", "GET")
        url = str_arg(args, "url", "")
        if not url:
            return ToolResult(observation="error: 'url' is required", ok=False)
        count = max(1, min(int(args.get("count", 10) or 10), 50))
        headers = args.get("headers") if isinstance(args.get("headers"), dict) else None
        content_str = str_arg(args, "content", "")
        content = content_str.encode() if content_str else None

        results: list[object] = [None] * count
        with ThreadPoolExecutor(max_workers=count) as pool:
            futures = {pool.submit(firer.fire, method, url, headers=headers, content=content): i for i in range(count)}
            for future, i in futures.items():
                try:
                    results[i] = future.result()
                except Exception as exc:  # noqa: BLE001 - report every failure, never drop one
                    results[i] = exc

        # Use FireResult's real field names (status code / timing) here once confirmed.
        lines = [f"[{i}] {r}" for i, r in enumerate(results)]
        ok = any(not isinstance(r, Exception) for r in results)
        return ToolResult(observation="\n".join(lines)[:_MAX_BODY_CHARS], ok=ok)

    return FunctionTool(
        name="fire_concurrent",
        description=(
            "Fire the same request N times (default 10, max 50) as close to simultaneously "
            "as possible via a thread pool, for race-condition testing. args: "
            '{"method": str, "url": str, "count": int (optional), "headers": dict (optional), '
            '"content": str (optional)}'
        ),
        func=_fire_concurrent,
    )
```

Test: mock `firer.fire` to return distinct results per call (or raise for some), assert all `count` results appear in the observation (in index order), and that a mix of successes/failures still returns `ok=True` if at least one succeeded.

- [ ] **Step 2: `diff_responses`**

```python
def build_diff_responses_tool(firer: HttpFirer) -> FunctionTool:
    """Fire two requests (e.g. as user A vs user B) and return a real line
    diff of status + body, instead of eyeballing two independently
    head+tail-truncated observations where the one differing field can
    fall inside the dropped middle of one but not the other."""

    def _diff(args: dict[str, object]) -> ToolResult:
        url_a = str_arg(args, "url_a", "")
        url_b = str_arg(args, "url_b", "")
        if not url_a or not url_b:
            return ToolResult(observation="error: 'url_a' and 'url_b' are required", ok=False)
        method_a = str_arg(args, "method_a", "GET")
        method_b = str_arg(args, "method_b", method_a)
        headers_a = args.get("headers_a") if isinstance(args.get("headers_a"), dict) else None
        headers_b = args.get("headers_b") if isinstance(args.get("headers_b"), dict) else None

        result_a = firer.fire(method_a, url_a, headers=headers_a)
        result_b = firer.fire(method_b, url_b, headers=headers_b)

        # Use FireResult's real status/body field names here once confirmed.
        body_a = getattr(result_a, "body", "")
        body_b = getattr(result_b, "body", "")
        body_a_text = body_a.decode(errors="replace") if isinstance(body_a, bytes) else str(body_a)
        body_b_text = body_b.decode(errors="replace") if isinstance(body_b, bytes) else str(body_b)
        diff = list(
            difflib.unified_diff(body_a_text.splitlines(), body_b_text.splitlines(), lineterm="", n=1)
        )
        lines = [f"body diff ({len(diff)} changed line(s)):", *diff[:200]]
        return ToolResult(observation="\n".join(lines)[:_MAX_BODY_CHARS], ok=True)

    return FunctionTool(
        name="diff_responses",
        description=(
            "Fire two requests and return a structural diff of status + body - a real "
            "line diff, not truncated eyeballing. args: "
            '{"method_a": str, "url_a": str, "headers_a": dict (optional), '
            '"method_b": str (optional, defaults to method_a), "url_b": str, '
            '"headers_b": dict (optional)}'
        ),
        func=_diff,
    )
```

Test: mock `firer.fire` to return two results with different bodies, assert the diff observation contains lines from both, and that identical bodies produce a "0 changed line(s)" result.

- [ ] **Step 3: Register both tools in `scan.py`**

Alongside the existing `build_http_tool(firer)` registration (~`scan.py:894`), add:
```python
build_fire_concurrent_tool(firer),
build_diff_responses_tool(firer),
```

- [ ] **Step 4: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/execution/tool.py src/lalo/scan.py tests/lalo/test_execution_tool.py
git commit -m "feat(L4L0): fire_concurrent and diff_responses agent tools"
```

### Task 17: New agent tools — `access_control_matrix` and `raw_tcp`

**Files:**
- Modify: `src/lalo/execution/tool.py` or a new small module alongside it (add `build_access_control_matrix_tool`, `build_raw_tcp_tool`)
- Modify: `src/lalo/scan.py` (register both)
- Test: alongside Task 16's test file

**Interfaces:**
- Consumes: `build_role_matrix(identity_ids, endpoint_ids) -> list[RoleMatrixEntry]` (existing, `src/lalo/identity/role_matrix.py`, zero prior callers), `tcp_send_recv(scope, host, port, payload=b"", *, timeout=5.0, recv_bytes=65535) -> RawResult` (existing, `src/lalo/execution/rawsock.py`, zero prior callers, already scope-checked + pinned-IP internally — the tool wrapper does NOT need to re-implement scope checking, just surface `result.scope_reason` when `result.fired` is `False`).

- [ ] **Step 1: `access_control_matrix` — a stateful coverage-tracking tool**

`build_role_matrix` produces immutable `RoleMatrixEntry` cells with no mutable "tested" state — the tool wrapper owns that state, closed over per-tool-instance (one matrix per scan, matching how `firer`/`scope` are already single-instances-per-scan):

```python
@dataclass
class _MatrixCell:
    entry: RoleMatrixEntry
    tested: bool = False
    observed_status: str | None = None


def build_access_control_matrix_tool() -> FunctionTool:
    """Track access-control test coverage as an identity x endpoint matrix,
    so coverage is machine-observed (queryable untested cells) rather than
    the agent's own self-reported todo list."""
    state: dict[tuple[str, str], _MatrixCell] = {}

    def _run(args: dict[str, object]) -> ToolResult:
        action = str_arg(args, "action", "")
        if action == "build":
            identity_ids = args.get("identity_ids")
            endpoint_ids = args.get("endpoint_ids")
            if not isinstance(identity_ids, list) or not isinstance(endpoint_ids, list):
                return ToolResult(observation="error: 'identity_ids' and 'endpoint_ids' must be lists", ok=False)
            state.clear()
            for entry in build_role_matrix([str(i) for i in identity_ids], [str(e) for e in endpoint_ids]):
                state[(entry.identity_id, entry.endpoint_id)] = _MatrixCell(entry=entry)
            return ToolResult(observation=f"built {len(state)} cells", ok=True)
        if action == "mark_tested":
            key = (str_arg(args, "identity_id", ""), str_arg(args, "endpoint_id", ""))
            cell = state.get(key)
            if cell is None:
                return ToolResult(observation=f"error: no cell for {key} - call action=build first", ok=False)
            cell.tested = True
            cell.observed_status = str_arg(args, "observed_status", "")
            return ToolResult(observation="marked", ok=True)
        if action == "query_untested":
            untested = [f"{c.entry.identity_id} x {c.entry.endpoint_id}" for c in state.values() if not c.tested]
            return ToolResult(observation="\n".join(untested) if untested else "all cells tested", ok=True)
        return ToolResult(observation=f"error: unknown action {action!r} - use build|mark_tested|query_untested", ok=False)

    return FunctionTool(
        name="access_control_matrix",
        description=(
            'Track access-control test coverage as an identity x endpoint matrix. args: '
            '{"action": "build"|"mark_tested"|"query_untested", ...}. build: '
            '{"identity_ids": [str], "endpoint_ids": [str]}. mark_tested: {"identity_id": str, '
            '"endpoint_id": str, "observed_status": str}. query_untested: {}.'
        ),
        func=_run,
    )
```

Test: build a 2x2 matrix (4 cells), query untested (expect all 4), mark one tested, query untested again (expect 3), and confirm `mark_tested` on a cell that was never built returns an error without raising.

- [ ] **Step 2: `raw_tcp`**

```python
def build_raw_tcp_tool(scope: ScopeGuard) -> FunctionTool:
    def _raw_tcp(args: dict[str, object]) -> ToolResult:
        host = str_arg(args, "host", "")
        port_raw = args.get("port")
        if not host or port_raw is None:
            return ToolResult(observation="error: 'host' and 'port' are required", ok=False)
        try:
            port = int(port_raw)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return ToolResult(observation="error: 'port' must be an integer", ok=False)
        payload = str_arg(args, "payload", "").encode()
        timeout = float(args.get("timeout", 5.0) or 5.0)  # type: ignore[arg-type]

        result = tcp_send_recv(scope, host, port, payload, timeout=timeout)
        if not result.fired:
            return ToolResult(observation=f"error: {result.scope_reason}", ok=False)
        observation = f"received {len(result.data)} bytes in {result.elapsed_ms}ms\n{result.data[:_MAX_BODY_CHARS]!r}"
        return ToolResult(observation=observation, ok=result.error is None)

    return FunctionTool(
        name="raw_tcp",
        description=(
            "Send raw bytes over a scope-checked, pinned-IP TCP connection and return "
            'whatever comes back. args: {"host": str, "port": int, "payload": str '
            '(optional, sent as raw bytes), "timeout": number (optional, seconds, default 5.0)}'
        ),
        func=_raw_tcp,
    )
```

Test: mock `tcp_send_recv` to return a `RawResult` with `fired=True` and some `data`, assert the observation includes the byte count and data; mock it to return `fired=False, scope_reason="out of scope"`, assert the tool returns `ok=False` with that reason surfaced.

- [ ] **Step 3: Register both tools in `scan.py`, alongside Task 16's registrations**

- [ ] **Step 4: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/execution/tool.py src/lalo/scan.py tests/lalo/test_execution_tool.py
git commit -m "feat(L4L0): wire role_matrix and rawsock into live access_control_matrix/raw_tcp tools"
```

### Task 18: Three missing skill playbooks + duplicate-spawn similarity guard

**Files:**
- Create: `src/lalo/skills/content/vulnerabilities/cors-misconfiguration.md`
- Create: `src/lalo/skills/content/vulnerabilities/prototype-pollution.md`
- Create: `src/lalo/skills/content/vulnerabilities/cache-poisoning.md`
- Modify: `src/lalo/skills/recall.py` (export a reusable plain-string similarity helper)
- Modify: `src/lalo/agent/spawn.py` (`_spawn`'s duplicate-check warning)
- Test: `tests/lalo/test_recall.py` (extend), `tests/lalo/test_spawn.py` (extend)

**Interfaces:**
- Produces: `token_overlap_ratio(a: str, b: str) -> float` (`recall.py`) — a plain two-string similarity function reusing `recall()`'s existing `_TOKEN` tokenizer, distinct from `_score` (which compares a query against a `Skill` object, not two arbitrary strings).

- [ ] **Step 1: Write the three playbooks**

Read one existing playbook in full first — `src/lalo/skills/content/vulnerabilities/race-conditions.md` — to match its exact structure: YAML frontmatter (`name`, `category: vulnerability`, `description`, `keywords`), then `# Title`, a framing paragraph, `## Attack Surface`, `## Recon`, `## Techniques (start quiet, escalate only as needed)` (numbered, cheapest/quietest first, explicit escalation gating), `## Proof Ladder` (L1-L4, ending with a `[[severity-calibration]]` pointer), `## Validation and False-Positive Discipline` (opens with "Apply `[[closure-discipline]]` before recording anything," then class-specific false-positive traps), `## Impact`, `## Summary`. Cross-references use `[[wiki-link]]` syntax.

Write real, substantive content for each of the three files — this is genuine methodology the agent will follow, not filler:
- `cors-misconfiguration.md`: reflected-origin ACAO, null-origin acceptance, subdomain-wildcard trust, credentials+wildcard combination, preflight bypass patterns.
- `prototype-pollution.md`: `__proto__`/`constructor.prototype` injection via JSON merge/deep-clone/query-string-parsing sinks, client-side (DOM XSS via polluted prototype) vs server-side (RCE/auth-bypass via polluted config) impact paths, gadget-finding technique.
- `cache-poisoning.md`: distinct from the existing `web-cache-deception.md` (which is about tricking a cache into storing a *private* response at a *public* URL) — this one is about injecting a *malicious* response into a *shared* cache via unkeyed inputs (unkeyed headers like `X-Forwarded-Host`, cache-key normalization discrepancies, fat GET/param cloaking).

- [ ] **Step 2: Verify retrievability**

Extend `tests/lalo/test_recall.py` (or the equivalent existing test file for `recall()`) with a query per new playbook proving it's actually retrieved for a representative real-world query, e.g.:

```python
def test_recall_surfaces_the_cors_playbook_for_a_relevant_query() -> None:
    skills = load_skills(...)  # however the existing test file already loads real skill content
    results = recall("reflected origin ACAO wildcard credentials", skills, top_k=3)
    assert any(r.skill.name == "cors-misconfiguration" for r in results)
```
(Match whatever fixture/loading convention the existing `recall()` tests already use — do not invent a new one.)

- [ ] **Step 3: Add `token_overlap_ratio` to `recall.py`**

```python
def token_overlap_ratio(a: str, b: str) -> float:
    """Fraction of shared tokens between two plain strings - the same
    [a-z0-9]+ tokenizer recall() uses for query/skill scoring, reused here
    to compare two task descriptions instead of a query against a Skill."""
    tokens_a = set(_TOKEN.findall(a.lower()))
    tokens_b = set(_TOKEN.findall(b.lower()))
    if not tokens_a or not tokens_b:
        return 0.0
    return len(tokens_a & tokens_b) / len(tokens_a | tokens_b)
```

Test: two near-identical task strings score high (>0.5), two unrelated ones score low, an empty string scores 0.0 without raising.

- [ ] **Step 4: Wire a duplicate-spawn warning into `_spawn`**

Read `src/lalo/agent/spawn.py`'s `_spawn` (currently goes straight to `coordinator.spawn(...)` with zero cross-check, despite the tool's own description already telling the model to call `view_agent_graph` first) and find how the coordinator exposes currently-running agents' tasks (whatever `view_agent_graph`'s own implementation reads from — reuse that same accessor, don't add a second one). Before spawning, compare the new task string against each running sibling's task via `token_overlap_ratio`; above a threshold, prepend a warning to the tool's returned observation rather than blocking the spawn (this is a warning, never a hard block — per this project's own confidence-not-gates philosophy, nothing here should prevent an agent from proceeding if it has good reason to):

```python
_DUPLICATE_TASK_SIMILARITY_THRESHOLD = 0.6
```

```python
warning = ""
for other_id, other_task in <running siblings' (id, task) pairs>:
    if token_overlap_ratio(task, other_task) >= _DUPLICATE_TASK_SIMILARITY_THRESHOLD:
        warning = (
            f"warning: this task looks similar to running agent {other_id}'s task "
            f"({other_task!r}) - confirm this isn't a duplicate before proceeding.\n"
        )
        break
# ... proceed with the existing coordinator.spawn(...) call unchanged, then prefix
# the tool's returned observation with `warning` (empty string is a no-op prefix).
```

Test: spawn two agents with near-identical task strings in the same test, assert the second spawn's returned observation contains the warning text and the spawn itself still succeeds (never blocked).

- [ ] **Step 5: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/skills/content/vulnerabilities/cors-misconfiguration.md src/lalo/skills/content/vulnerabilities/prototype-pollution.md src/lalo/skills/content/vulnerabilities/cache-poisoning.md src/lalo/skills/recall.py src/lalo/agent/spawn.py tests/lalo/test_recall.py tests/lalo/test_spawn.py
git commit -m "feat(L4L0): 3 new skill playbooks (CORS, prototype pollution, cache poisoning) + a duplicate-spawn similarity warning"
```

### Task 19: GUI operator productivity — duplicate-as-new-scan, bulk target import

**Files:**
- Modify: `src/lalo/gui/static/index.html` (a `.run-duplicate-btn` in `tpl-run-item`; a "paste scope list" `<details>` near the composer, matching Task 5's `#advanced-options` idiom)
- Modify: `src/lalo/gui/static/app.js`
- Modify: `src/lalo/gui/static/app.css`

**Context:** `GET /runs` already returns each run's `mission` (the operator's original free-form text, which already contains the target substrings `extractTargets` re-parses on resubmit) — so "duplicate as new scan" needs zero backend changes: pre-filling the composer with a past run's `mission` text and letting the operator edit/resubmit it through the exact same `launchFromPrompt` path every fresh scan already uses is the whole feature. Before wiring the button, read `src/lalo/gui/app.py`'s actual `GET /runs` response-building code to confirm `mission` is genuinely present in the per-run dict it returns (a prior research pass flagged this as needing direct confirmation — the source value is confirmed read from `resume_manifest.json`, but the final returned-dict literal a few lines further down wasn't independently re-checked).

- [ ] **Step 1: Add a "Duplicate" button to the run-item template**

In `index.html`'s `tpl-run-item` template, add a new button alongside the existing `.run-resume-btn`/`.run-report-link` (shown for every run, unlike Resume which is running-state-gated — duplicating is valid for a running OR completed run since it launches an independent new scan):

```html
<button type="button" class="run-duplicate-btn" title="Start a new scan with this run's mission">Duplicate</button>
```

- [ ] **Step 2: Wire the click handler**

In `app.js`, add a new delegated listener (do not disturb the two existing `runHistoryListEl` click listeners from Tasks 1/2):

```js
runHistoryListEl.addEventListener("click", (ev) => {
  const btn = ev.target.closest(".run-duplicate-btn");
  if (!btn) return;
  const item = btn.closest(".run-item");
  composerInput.value = item.dataset.missionText || "";
  composerInput.focus();
});
```

(`item.dataset.missionText` already exists from Task 1's `buildRunItem` — confirm the value it holds is the full original mission text, not a truncated display string, before relying on it here.)

- [ ] **Step 3: Bulk target import**

Add a collapsible "paste scope list" control near the composer, matching Task 5's `#advanced-options` `<details>` styling:

```html
<details id="bulk-import" class="advanced-options">
  <summary>Paste scope list</summary>
  <textarea id="bulk-import-textarea" rows="4" placeholder="one target per line"></textarea>
  <button type="button" id="bulk-import-add-btn" class="btn btn-ghost">Add to message</button>
</details>
```

```js
const bulkImportTextarea = document.getElementById("bulk-import-textarea");
const bulkImportAddBtn = document.getElementById("bulk-import-add-btn");

bulkImportAddBtn.addEventListener("click", () => {
  const lines = bulkImportTextarea.value.split("\n").map((l) => l.trim()).filter(Boolean);
  if (!lines.length) return;
  composerInput.value = [composerInput.value.trim(), ...lines].filter(Boolean).join(" ");
  bulkImportTextarea.value = "";
  composerInput.focus();
});
```

This reuses `extractTargets`'s existing regex unchanged — pasted lines just become more text in the same composer box a normal scan launch already parses, so no backend/endpoint change is needed here either.

- [ ] **Step 4: Verify live, with Playwright**

Confirm clicking "Duplicate" on a past run pre-fills the composer with that run's mission text (editable, not launched automatically); confirm pasting a multi-line scope list into the bulk-import textarea and clicking "Add to message" appends all lines into the composer, and that submitting afterward correctly extracts all pasted targets via the existing `extractTargets` regex.

- [ ] **Step 5: Commit**

```bash
git add src/lalo/gui/static/index.html src/lalo/gui/static/app.js src/lalo/gui/static/app.css
git commit -m "feat(L4L0): duplicate a past run as a new scan; paste a scope list into the composer"
```

---

## Final check (after all 19 tasks)

Run: `uv run ruff check src/lalo tests/lalo && uv run ruff format --check src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"`

Then a full live Playwright walkthrough covering everything in one pass: open a past run, continue it, open settings and add/verify a provider key, set an advanced option and launch a scan, watch the live shell panel fill in, toggle the theme, confirm the new icons/entrance animation/reduced-motion behavior, duplicate a past run and paste a scope list into the composer.
