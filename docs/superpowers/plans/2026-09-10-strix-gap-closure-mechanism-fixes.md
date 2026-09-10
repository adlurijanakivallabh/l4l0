# Strix Gap Closure — Mechanism Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close one real GUI request-authenticity gap (CSRF/Origin) plus nine small,
independent correctness fixes to existing code, each proven closed by a hermetic
regression test. Several items from the design spec's mechanism-gap table were
verified against live source during this planning pass and turned out to be already
covered or structurally inapplicable — those are recorded as closure notes at the end
rather than invented into tasks.

**Architecture:** No shared new abstraction, no new files except tests. Every fix is a
5–40 line change to a function that already exists.

**Tech Stack:** Python 3.13, pytest, FastAPI (for the CSRF fix), stdlib only otherwise.

**Spec:** `docs/superpowers/specs/2026-09-10-strix-gap-closure-design.md`, §4 and §5
(the CSRF item lives structurally in §5 but is called out there as the single
highest-priority item to actually close).

## Global Constraints

- No CLI/TUI, no confirmation/permission gates of any kind. Every fix here is either a
  header check on an HTTP request (rejects a forged cross-origin call, never asks the
  operator to approve anything), a retry-policy change (widens what gets retried,
  never narrows what's allowed), a prompt-text addition, or an argument-parsing
  tolerance fix — none of these are gates.
- No reference-project names in code/comments/docs/commit messages — describe
  patterns generically ("a defensive network-request check," "a compaction
  reliability improvement"), per CLAUDE.md's clean-room policy.
- Full non-live test suite + `uv run ruff check src/lalo tests/lalo` +
  `uv run ruff format --check src/lalo tests/lalo` + `uv run mypy` + a reference-name
  grep (`grep -rniE "strix" src/lalo tests/lalo` must return nothing) + `git fsck --full`
  after every task.
- Every file path/line number below was read live from current source during this
  planning session — trust the described current content, but re-read the live file
  if it's drifted by the time you implement rather than trusting a stale line number.
- Commit message convention: end every commit with the attribution line the harness
  supplies at commit time (not fixed text in this plan, since it can change between
  sessions — use whatever the current system prompt specifies).

---

### Task 1: Reject a cross-origin state-changing GUI request

**Files:**
- Modify: `src/lalo/gui/app.py:282-303` (inside `build_app`, before the route
  definitions) and each mutating route (`start_scan` at :309, `stop_scan` at :615,
  `steer` at :624, `set_provider_settings` at :588)
- Test: `tests/lalo/test_gui_app.py` (append)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: a new module-level function `_same_origin(request: Request, *, host: str,
  port: int) -> bool` in `gui/app.py`. No existing signature changes — every route
  keeps its current parameters; the check is inserted as the first statement in each
  mutating handler's body.

**Context:** `gui/app.py`'s own module docstring already documents that the GUI
deliberately has no auth (an explicit prior operator decision, not to be
re-litigated). This fix is unrelated to that decision: with zero cookies and zero
`Origin` validation, any webpage the operator's browser has open in another tab can
fire a blind cross-origin `POST /scan` (including a crafted `resume_run_id`) or
`POST /steer` against `http://127.0.0.1:8000` and have the browser honor it exactly
as if the operator typed it — a request-authenticity gap, not an authentication one.
FastAPI route handlers need the raw `Request` object to read a header not already
modeled as a `Query`/body field; `start_scan`/`stop_scan`/`steer` currently don't take
one.

- [ ] **Step 1: Write the failing test**

  Add to `tests/lalo/test_gui_app.py` (the file already builds a `TestClient` via
  `build_app(EventLog(), runs_dir=tmp_path)` in its existing fixtures — reuse that
  pattern):

  ```python
  def test_post_scan_rejects_a_foreign_origin_header(tmp_path: Path) -> None:
      client = TestClient(build_app(EventLog(), runs_dir=tmp_path))
      resp = client.post(
          "/scan",
          json={"mission": "test", "targets": ["http://example.com"]},
          headers={"Origin": "http://evil.example.com"},
      )
      assert resp.status_code == 403

  def test_post_scan_allows_a_matching_origin_header(tmp_path: Path) -> None:
      client = TestClient(build_app(EventLog(), runs_dir=tmp_path))
      resp = client.post(
          "/scan",
          json={"mission": "test", "targets": ["http://example.com"]},
          headers={"Origin": "http://127.0.0.1:8000"},
      )
      assert resp.status_code == 200

  def test_post_scan_allows_a_request_with_no_origin_header(tmp_path: Path) -> None:
      # Non-browser API clients (curl, a script, local dev tooling) never send
      # Origin at all - must not be broken by this fix.
      client = TestClient(build_app(EventLog(), runs_dir=tmp_path))
      resp = client.post("/scan", json={"mission": "test", "targets": ["http://example.com"]})
      assert resp.status_code == 200

  def test_post_steer_rejects_a_foreign_origin_header(tmp_path: Path) -> None:
      client = TestClient(build_app(EventLog(), runs_dir=tmp_path))
      resp = client.post(
          "/steer",
          json={"text": "hello"},
          headers={"Origin": "http://evil.example.com"},
      )
      assert resp.status_code == 403
  ```

  (`TestClient`/`EventLog`/`build_app`/`Path` are already imported at the top of
  `test_gui_app.py` — confirmed by its existing fixtures using the identical
  `build_app(EventLog(), runs_dir=tmp_path)` call shape.)

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_gui_app.py::test_post_scan_rejects_a_foreign_origin_header -v
  ```

  Expected: FAIL — currently returns 200 (or a 400 for missing mission/targets, but
  never a 403 for the Origin header, since nothing reads it today).

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/gui/app.py`, add `Request` to the existing `fastapi` import (line 113):

  ```python
  from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
  ```

  Add a small origin-check helper right after `_SAFE_RUN_ID` (around line 172),
  matching that constant's own "one small checked value, several call sites" shape:

  ```python
  def _rejects_foreign_origin(request: Request, *, host: str, port: int) -> bool:
      """True if ``request`` carries an Origin header that does NOT match this
      server's own bound address - a request with no Origin header at all
      (any non-browser client: curl, a script, local dev tooling) is never
      rejected here, only a browser-sent one that names a DIFFERENT origin.
      A browser always sets Origin on a cross-origin POST/PUT/DELETE; a
      same-origin request from the GUI's own served frontend also always
      carries a matching one, so this closes the drive-by/CSRF gap noted in
      this module's own docstring without requiring any credential or
      confirmation step.
      """
      origin = request.headers.get("origin")
      if origin is None:
          return False
      return origin != f"http://{host}:{port}"
  ```

  In `build_app`, capture the bound host/port as local closure variables (they're
  currently hardcoded in `main()` at the bottom of the file, never threaded into
  `build_app` itself — add them as `build_app` parameters with the same defaults
  `main()` already uses, so existing callers/tests that don't pass them keep working
  unchanged):

  ```python
  def build_app(
      event_log: EventLog,
      *,
      runs_dir: Path | None = None,
      host: str = "127.0.0.1",
      port: int = 8000,
  ) -> FastAPI:
  ```

  Insert the check as the first statement in each mutating handler
  (`start_scan`, `stop_scan`, `steer`, `set_provider_settings`):

  ```python
  @app.post("/scan")
  async def start_scan(request: ScanRequest, http_request: Request) -> JSONResponse:
      if _rejects_foreign_origin(http_request, host=host, port=port):
          return JSONResponse({"error": "cross-origin request rejected"}, status_code=403)
      ...  # existing body unchanged
  ```

  (FastAPI resolves a bare `Request`-typed parameter from the framework, not the
  request body, regardless of parameter order — the existing `ScanRequest` body
  parameter is unaffected. Repeat the same two-line insertion, with `http_request:
  Request` added to each signature, for `stop_scan`, `steer`, and
  `set_provider_settings` — each already takes different existing parameters
  (`run_id: str | None`, `message: SteeringMessage`, `request: ProviderSettingsRequest`
  respectively); add `http_request: Request` alongside without renaming anything
  existing.)

  Finally, update `main()` (bottom of the file) to pass its own already-hardcoded
  `host`/`port` locals through:

  ```python
  def main() -> None:
      ...
      event_log = EventLog()
      host, port = "127.0.0.1", 8000
      app = build_app(event_log, host=host, port=port)
      print(f"L4L0 GUI: http://{host}:{port}/")
      uvicorn.run(app, host=host, port=port)
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_gui_app.py -k "foreign_origin or matching_origin or no_origin_header" -v
  ```

  Expected: all four PASS.

- [ ] **Step 5: Run the full GUI test file to confirm no regression**

  ```
  uv run pytest tests/lalo/test_gui_app.py -v
  ```

  Expected: PASS — every existing test constructs its own `TestClient` with no
  `Origin` header set, so `_rejects_foreign_origin` returns `False` for all of them
  (the "no Origin header at all" branch) and none of the ~90 existing tests changes
  behavior.

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/gui/app.py tests/lalo/test_gui_app.py
  git commit -m "fix(gui): reject a cross-origin Origin header on every mutating endpoint

A page open in another browser tab could blind-POST /scan or /steer against
this server and have it honored, since the GUI has no cookie or Origin check
at all. Unrelated to the GUI's deliberate no-auth design (there is no
credential to protect) - this closes a request-authenticity gap, not an
authentication one. A request with no Origin header (any non-browser client)
is unaffected."
  ```

---

### Task 2: Scale compaction's trigger to a real per-model token budget

**Files:**
- Modify: `src/lalo/agent/loop.py:392-413` (`_truncate_observation`, unchanged —
  reference only), `:665-676` (`_maybe_compact_history`), `:280-288` (the
  `_VISIBLE_HISTORY_WINDOW`/`_COMPACTION_BATCH` constants — kept as a floor, not
  removed)
- Test: `tests/lalo/test_agent_loop.py` (append)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: a new pure function `_estimate_tokens(text: str) -> int` and a new
  `AgentConfig` field `context_window_tokens: int | None = None` (default `None`
  preserves today's fixed-item-count behavior exactly for every existing caller that
  doesn't opt in). `_maybe_compact_history`'s signature is unchanged (still takes only
  `transcript: list[dict[str, object]]`) — it reads `self.config.context_window_tokens`
  internally.

**Context:** Today `_maybe_compact_history` triggers purely on
`hidden_boundary - self._summarized_through < _COMPACTION_BATCH` (an item count,
`_COMPACTION_BATCH = 8`), regardless of how many actual tokens those 8 items carry or
what the configured model's real context window is. A model with a small context
window can overflow well before 12+8=20 items accumulate if even a few carry large
tool outputs (already capped at `max_observation_chars=4000` chars each, but 20 items
at 4000 chars each is ~80,000 characters, roughly 20,000 tokens — already close to or
over a small model's budget). A model with a huge context window compacts needlessly
early, paying for a real LLM call for no benefit. This task adds an opt-in, per-model
token estimate as an ADDITIONAL trigger condition alongside the existing item-count
one — either firing compaction (whichever is more conservative) is fine, since
firing early only costs one extra summarization call, never data loss.

- [ ] **Step 1: Write the failing test**

  Add to `tests/lalo/test_agent_loop.py` (the file already has a `_FakeRouter`/
  `_ScriptedProvider`-style fixture pattern and constructs `AgentLoop` with a
  `config=AgentConfig(...)` directly — reuse that shape):

  ```python
  def test_compaction_fires_early_when_a_small_context_window_would_otherwise_overflow() -> None:
      """A tiny context_window_tokens must trigger compaction well before the
      fixed _COMPACTION_BATCH=8 item count would, since 8 items of ordinary
      size can already exceed a genuinely small budget."""
      calls = {"compact": 0}

      class _CountingRouter:
          def complete(self, role: str, request: object) -> CompletionResponse:
              calls["compact"] += 1
              return CompletionResponse(text="summary", provider="fake", model="fake",
                                         input_tokens=1, output_tokens=1)

      loop = AgentLoop(
          _CountingRouter(),  # type: ignore[arg-type]
          ToolRegistry([]),
          system_prompt="sys",
          config=AgentConfig(context_window_tokens=50),
      )
      # Build a transcript with a few items, each carrying enough text that
      # a 50-token budget is already exceeded well before 8 items accumulate.
      transcript = [
          {"tool": "http", "args": {}, "observation": "x" * 200}
          for _ in range(3)
      ]
      loop._maybe_compact_history(transcript)
      assert calls["compact"] == 1
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_agent_loop.py::test_compaction_fires_early_when_a_small_context_window_would_otherwise_overflow -v
  ```

  Expected: FAIL — with only 3 items and `_COMPACTION_BATCH=8`, `_maybe_compact_history`
  returns immediately without calling the router at all (`calls["compact"] == 0`).

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/agent/loop.py`, add a token-estimate helper right after
  `_truncate_observation` (around line 414):

  ```python
  # A conservative, model-agnostic estimate (no tokenizer dependency) - real
  # BPE tokenizers vary, but 4 characters per token is a widely-used
  # conservative approximation that never wildly under-counts for English
  # or code text, which is what this loop's transcripts are made of.
  _CHARS_PER_TOKEN_ESTIMATE = 4


  def _estimate_tokens(text: str) -> int:
      return len(text) // _CHARS_PER_TOKEN_ESTIMATE
  ```

  Add the new `AgentConfig` field (after `provider_outage_base_delay_s`, around
  line 357):

  ```python
      # An operator-known context-window size for the configured model, used
      # ONLY as an additional, earlier compaction trigger alongside the
      # existing fixed _COMPACTION_BATCH item count - None (the default)
      # means every existing caller keeps today's item-count-only behavior
      # exactly. When set, compaction fires as soon as EITHER condition is
      # met, since firing early only costs one extra summarization call,
      # never data loss - a small-context model that would otherwise
      # overflow gets protected without needing every caller to opt in.
      context_window_tokens: int | None = None
  ```

  Modify `_maybe_compact_history` (currently lines 665-676):

  ```python
  def _maybe_compact_history(self, transcript: list[dict[str, object]]) -> None:
      hidden_boundary = max(0, len(transcript) - _VISIBLE_HISTORY_WINDOW)
      pending = hidden_boundary - self._summarized_through
      if pending < _COMPACTION_BATCH and not self._pending_batch_exceeds_budget(
          transcript, hidden_boundary
      ):
          return
      newly_hidden = transcript[self._summarized_through : hidden_boundary]
      if not newly_hidden:
          return
      self._history_summary = self._compact_history(newly_hidden)
      self._summarized_through = hidden_boundary
  ```

  Add the budget-check helper right above it:

  ```python
  def _pending_batch_exceeds_budget(
      self, transcript: list[dict[str, object]], hidden_boundary: int
  ) -> bool:
      if self.config.context_window_tokens is None:
          return False
      pending_text = "\n".join(
          f"{e['tool']}{e['args']}{e['observation']}"
          for e in transcript[self._summarized_through : hidden_boundary]
      )
      # A conservative reserve (half the configured window) rather than the
      # full window: this pending batch is only PART of what a real prompt
      # carries (system prompt, tool descriptions, the visible window,
      # mission text all add more) - triggering well before the nominal
      # ceiling is the whole point of an early, opt-in second trigger.
      return _estimate_tokens(pending_text) > self.config.context_window_tokens // 2
  ```

  Guard: if `hidden_boundary - self._summarized_through == 0` (nothing pending yet),
  the budget check must not fire compaction on an empty batch — the
  `if not newly_hidden: return` line above already handles this since an empty slice
  produces `newly_hidden == []`.

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_agent_loop.py::test_compaction_fires_early_when_a_small_context_window_would_otherwise_overflow -v
  ```

  Expected: PASS.

- [ ] **Step 5: Run the full existing compaction test suite to confirm no regression**

  ```
  uv run pytest tests/lalo/test_agent_loop.py -k compact -v
  ```

  Expected: all PASS — every existing compaction test constructs `AgentConfig()` with
  no `context_window_tokens` override, so `_pending_batch_exceeds_budget` always
  returns `False` for them (falling through to the unchanged item-count check).

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/agent/loop.py tests/lalo/test_agent_loop.py
  git commit -m "feat(agent): scale compaction trigger to a real per-model token budget

The existing fixed 8-item compaction batch can under- or over-fire depending
on a model's actual context window and how much text each item carries.
Adds an opt-in context_window_tokens config that triggers compaction early
when a rough token estimate of the pending batch already exceeds half the
configured budget - additive, defaults to None (today's item-count-only
behavior unchanged)."
  ```

---

### Task 3: Add reactive context-overflow recompaction

**Files:**
- Modify: `src/lalo/agent/loop.py:516-592` (`_complete`), `:790-856` (the main step
  loop in `run()`, specifically where `_complete`/`_retry_through_provider_outage`
  are called around line 806-811)
- Test: `tests/lalo/test_agent_loop.py` (append)

**Interfaces:**
- Consumes: `_maybe_compact_history` from Task 2 (calls it directly, forcing a
  compaction pass regardless of the normal trigger).
- Produces: a new pure function `_looks_like_context_overflow(message: str) -> bool`
  and a private `AgentLoop._recompact_and_retry(prompt_builder, transcript) ->
  CompletionResponse | None` helper. No changes to `AgentResult`/`run()`'s public
  return shape.

**Context:** Today, if a provider rejects a request because it's genuinely too large
for the model's context window, that failure surfaces through the normal
`AllProvidersFailedError` → `_complete` returns `None` → `_retry_through_provider_outage`
path — which is designed for transient outages (waits 30/60/120s and retries the
*identical* prompt), not for "the prompt itself is too big." Retrying an
identically-sized oversized prompt after a wait will fail identically every time.
This closes that: detect an overflow-shaped failure message, force a compaction pass
(shrinking the prompt), and retry once with the now-smaller prompt — distinct from,
and checked before, the outage-retry path.

- [ ] **Step 1: Write the failing test**

  ```python
  def test_a_context_overflow_error_forces_compaction_and_retries_once() -> None:
      """A provider rejection whose message looks like a genuine context-
      overflow (not a rate limit) should force one compaction pass and retry
      with the smaller prompt - not the identical-prompt outage-retry loop,
      which would fail identically forever on a too-large prompt."""
      attempts = {"n": 0}

      class _OverflowThenOkRouter:
          def complete(self, role: str, request: object) -> CompletionResponse:
              attempts["n"] += 1
              if attempts["n"] == 1:
                  raise AllProvidersFailedError(
                      role="reasoning",
                      failures=[("fake", "400: maximum context length exceeded")],
                  )
              return CompletionResponse(
                  text='{"tool": "finish", "args": {"summary": "ok"}}',
                  provider="fake", model="fake", input_tokens=1, output_tokens=1,
              )

      loop = AgentLoop(
          _OverflowThenOkRouter(),  # type: ignore[arg-type]
          ToolRegistry([]),
          system_prompt="sys",
          config=AgentConfig(max_steps=3),
      )
      result = loop.run("mission")
      assert result.stop_reason == "finished"
      assert attempts["n"] == 2
  ```

  (`AllProvidersFailedError`'s real constructor is `__init__(self, message="", *,
  role="", failures=None)` per `core/errors.py` — confirmed via the existing import
  at the top of `agent/loop.py`; the test above uses the keyword-only `role`/
  `failures` shape.)

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_agent_loop.py::test_a_context_overflow_error_forces_compaction_and_retries_once -v
  ```

  Expected: FAIL — today's `_complete` catches `AllProvidersFailedError` and returns
  `None` unconditionally; `run()` then calls `_retry_through_provider_outage`, which
  sleeps 30s (or whatever `provider_outage_base_delay_s` is) before retrying — this
  test would either time out or (since the router's `complete()` is called again with
  the *same* prompt and would raise `AllProvidersFailedError` again on retry only if
  `attempts["n"] == 1` gates the raise, meaning attempt 2 already succeeds through the
  *existing* outage-retry path) actually pass via the wrong path. To make the RED
  state meaningful, first assert the test fails for the RIGHT reason: temporarily set
  `provider_outage_base_delay_s=0.0` is not enough by itself — the real signal is
  that this scenario should NOT need to invoke the 30s-scaled outage-retry path at
  all. Confirm RED by running with the loop's default `provider_outage_base_delay_s`
  (30.0) and a short pytest timeout, or more precisely: patch `AgentLoop._sleep` to a
  no-op recording function and assert it is NEVER called for this scenario once the
  fix lands (add this assertion in Step 4, not Step 1) — for now, the meaningful RED
  signal is simply that no code path yet exists that recognizes "this specific
  failure should skip the outage-retry wait and instead force compaction," so add a
  second assertion capturing that:

  ```python
      # (added to the same test, before running loop.run)
      sleeps: list[float] = []
      loop._sleep = sleeps.append  # type: ignore[assignment]
  ```

  and after `loop.run(...)`:

  ```python
      assert sleeps == []  # must never enter the 30s-scaled outage-retry wait
  ```

  Run again — expected FAIL: `sleeps` is non-empty (today's code sleeps once via the
  outage-retry path before its second, successful attempt).

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/agent/loop.py`, add the overflow-message classifier near
  `_call_signature` (around line 388):

  ```python
  # A genuine context-overflow rejection, not a rate-limit/throttle one -
  # checked in that order deliberately: a rate-limit message can legitimately
  # contain the word "limit" or "exceeded" too, and must never be
  # misclassified as an overflow (which would force a pointless compaction
  # pass instead of the correct outage-retry wait).
  _OVERFLOW_MARKERS = ("context length", "context_length", "maximum context", "too many tokens")
  _RATE_LIMIT_MARKERS = ("rate limit", "rate_limit", "too many requests", "429")


  def _looks_like_context_overflow(message: str) -> bool:
      lowered = message.lower()
      if any(marker in lowered for marker in _RATE_LIMIT_MARKERS):
          return False
      return any(marker in lowered for marker in _OVERFLOW_MARKERS)
  ```

  Modify `_complete` to record the failure's own message (not just the
  `all_non_retryable` flag it already records) so the caller can classify it. Current
  `_complete` (lines 516-592) has:

  ```python
          except AllProvidersFailedError as exc:
              self._last_failure_non_retryable = exc.all_non_retryable
              return None
  ```

  becomes:

  ```python
          except AllProvidersFailedError as exc:
              self._last_failure_non_retryable = exc.all_non_retryable
              self._last_failure_message = str(exc)
              return None
  ```

  Add the new instance attribute in `__init__` alongside `_last_failure_non_retryable`
  (around line 510):

  ```python
          self._last_failure_non_retryable = False
          # Set alongside _last_failure_non_retryable on every _complete()
          # failure - read once, immediately after, by run()'s own overflow
          # check; stale values from an earlier step are never read since
          # run() only ever checks this right after a fresh _complete() call
          # that itself just returned None.
          self._last_failure_message = ""
  ```

  In `run()`'s main step loop (currently lines 805-811):

  ```python
                  with self.tracer.span("llm_completion", step=step, agent_id=self.agent_id):
                      response = self._complete(prompt, step_key=step_key)
                  if response is None:
                      response = self._retry_through_provider_outage(prompt, step_key=step_key)
                  if response is None:
                      self._emit("provider_failed", {"step": step})
                      return AgentResult("provider_failed", step, transcript)
  ```

  becomes:

  ```python
                  with self.tracer.span("llm_completion", step=step, agent_id=self.agent_id):
                      response = self._complete(prompt, step_key=step_key)
                  if response is None and _looks_like_context_overflow(self._last_failure_message):
                      response = self._recompact_and_retry(mission, transcript, step_key=step_key)
                  if response is None:
                      response = self._retry_through_provider_outage(prompt, step_key=step_key)
                  if response is None:
                      self._emit("provider_failed", {"step": step})
                      return AgentResult("provider_failed", step, transcript)
  ```

  Add `_recompact_and_retry` right after `_maybe_compact_history` (around line 676):

  ```python
      def _recompact_and_retry(
          self, mission: str, transcript: list[dict[str, object]], *, step_key: str | None = None
      ) -> CompletionResponse | None:
          """A genuine context-overflow rejection means the JUST-SENT prompt was
          too large - retrying it unchanged (the outage-retry path's own
          behavior) would fail identically forever. Force one compaction pass
          regardless of the normal trigger, then rebuild and resend the prompt
          exactly once. Never retries a second time here - if the freshly
          recompacted prompt still overflows, that's a genuinely different,
          worse problem (a single transcript item too large on its own) this
          one-shot recovery isn't meant to solve; the caller's own
          _retry_through_provider_outage remains the fallback either way.
          """
          hidden_boundary = max(0, len(transcript) - _VISIBLE_HISTORY_WINDOW)
          newly_hidden = transcript[self._summarized_through : hidden_boundary]
          if newly_hidden:
              self._history_summary = self._compact_history(newly_hidden)
              self._summarized_through = hidden_boundary
          directives = [d for d in (self._budget_directive(),) if d]
          prompt = self._render_prompt(mission, transcript, directives)
          return self._complete(prompt, step_key=step_key)
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_agent_loop.py::test_a_context_overflow_error_forces_compaction_and_retries_once -v
  ```

  Expected: PASS, including the `assert sleeps == []` assertion.

- [ ] **Step 5: Run the full agent-loop suite to confirm no regression**

  ```
  uv run pytest tests/lalo/test_agent_loop.py -v
  ```

  Expected: all PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/agent/loop.py tests/lalo/test_agent_loop.py
  git commit -m "fix(agent): force a compaction pass on a genuine context-overflow rejection

A provider rejecting a request as too large previously fell through to the
outage-retry path, which waits and retries the IDENTICAL prompt - guaranteed
to fail again. Classifies the failure message (excluding rate-limit-shaped
messages first, so a throttle is never misdiagnosed as an overflow), forces
one compaction pass, and retries once with the smaller prompt before falling
back to the existing outage-retry path."
  ```

---

### Task 4: Instruct the compaction summarizer to preserve credentials/findings verbatim

**Files:**
- Modify: `src/lalo/agent/loop.py:290-299` (`_COMPACTION_SYSTEM_PROMPT`)
- Test: `tests/lalo/test_agent_loop.py` (append)

**Interfaces:**
- Consumes: nothing.
- Produces: no signature change — `_COMPACTION_SYSTEM_PROMPT` is a module constant
  string; only its text changes.

**Context:** The current prompt says "Preserve concrete facts only: targets tested,
tools run, findings filed, approaches that failed and why" but never explicitly
instructs the summarizer to keep a captured credential/token/secret value *verbatim*
rather than paraphrasing or generalizing it away. For a tool whose entire value is
the credentials and findings it discovers, a summarization pass that turns "found
JWT secret `abc123xyz`" into "found a weak JWT secret" during compaction is a real,
silent data-loss risk on a long-running scan.

- [ ] **Step 1: Write the failing test**

  ```python
  def test_compaction_system_prompt_instructs_verbatim_credential_preservation() -> None:
      """The compaction summarizer must be told to preserve credentials/
      secrets/tokens/findings VERBATIM, not paraphrased - a real data-loss
      risk for a tool whose whole value is what it captured."""
      from lalo.agent.loop import _COMPACTION_SYSTEM_PROMPT

      lowered = _COMPACTION_SYSTEM_PROMPT.lower()
      assert "verbatim" in lowered
      assert "credential" in lowered or "secret" in lowered
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_agent_loop.py::test_compaction_system_prompt_instructs_verbatim_credential_preservation -v
  ```

  Expected: FAIL — current text has neither word.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/agent/loop.py`, replace `_COMPACTION_SYSTEM_PROMPT` (lines 290-299):

  ```python
  _COMPACTION_SYSTEM_PROMPT = (
      "You compact an autonomous security-testing agent's own step history into "
      "a dense working-memory summary for that SAME agent's continued reasoning. "
      "Preserve concrete facts only: targets tested, tools run, findings filed, "
      "approaches that failed and why, anything the agent should not repeat. "
      "Any captured credential, secret, token, session value, or specific "
      "finding detail must be copied VERBATIM, character-for-character, never "
      "paraphrased, generalized, or replaced with a placeholder - the agent "
      "needs the exact value to keep using it, and a summary that only says "
      "'found a weak credential' has silently destroyed the one thing that "
      "made the finding useful. Never state a verdict on whether anything is "
      "a real vulnerability - this summary is orientation for the agent, "
      "never evidence for a finding. A few dense bullet points, terse - fold "
      "any existing summary shown in with the newly completed steps into one "
      "updated summary."
  )
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_agent_loop.py::test_compaction_system_prompt_instructs_verbatim_credential_preservation -v
  ```

  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/agent/loop.py tests/lalo/test_agent_loop.py
  git commit -m "fix(agent): instruct compaction to preserve credentials/findings verbatim

The compaction summarizer's system prompt asked for 'concrete facts' but
never explicitly forbade paraphrasing a captured credential/token/secret
value away - a real data-loss risk on a long scan for a tool whose value is
exactly the credentials and findings it discovers."
  ```

---

### Task 5: Bound MCP tool calls with a classified transient-failure retry

**Files:**
- Modify: `src/lalo/integrations/mcp_client.py:253-295` (`call_external_tool`)
- Test: `tests/lalo/test_integrations_mcp_client.py` (append)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: no signature change to `call_external_tool` (still `(config, tool_name,
  arguments, *, connector=None, env=None) -> ToolResult`). New private helpers
  `_is_transient_mcp_failure(exc: Exception) -> bool` and internal retry loop inside
  `call_external_tool`.

**Context, corrected from the design spec's original framing:** the spec's mechanism-
gap table (M8) was written expecting strix's own long-lived, reconnect-and-quarantine
session-supervision model. Live reading of `mcp_client.py` this session shows L4L0's
architecture is simpler and doesn't need that: `call_external_tool` already does a
**fresh connect → call → disconnect cycle on every single invocation** (via
`_default_connector`, opened and closed within one `asyncio.run(_run())` call) — there
is no persistent session across calls for a background failure to corrupt, and the
existing blanket `except Exception` already prevents one dead connection from
crashing the calling agent's turn. What's actually missing, given that shape, is much
smaller: a single transient failure (a network blip, a 5xx-shaped error from an HTTP
transport) degrades today to one failed `ToolResult` with no automatic retry at all,
requiring the agent itself to notice and manually retry. This task adds a small,
bounded retry loop for transient failures only — never for the fail-closed policy
checks (`check_tool_call`/`validate_server_url`/`resolve_credential`), which must
keep failing on the first denial exactly as today.

- [ ] **Step 1: Write the failing test**

  Add to `tests/lalo/test_integrations_mcp_client.py` (the file already builds a
  `MCPServerConfig` and a fake `connector` callable per its own established fixture
  pattern — reuse that shape rather than a new one):

  ```python
  def test_call_external_tool_retries_a_transient_connection_failure() -> None:
      """A single transient network-shaped failure (a ConnectionError, not an
      auth/policy denial) should be retried a bounded number of times before
      giving up, rather than failing on the very first attempt."""
      attempts = {"n": 0}
      config = MCPServerConfig(
          name="test", transport="http", credential_env_var="TEST_MCP_TOKEN",
          allowed_tools={"do_thing": "read"}, url="https://example.com/mcp",
      )

      @asynccontextmanager
      async def _flaky_connector(cfg: MCPServerConfig, credential: str):
          attempts["n"] += 1
          if attempts["n"] < 3:
              raise ConnectionError("transient network failure")

          class _FakeSession:
              async def call_tool(self, name: str, args: dict[str, object]) -> object:
                  class _Result:
                      content = [TextContent(type="text", text="ok")]
                      isError = False
                  return _Result()

          yield _FakeSession()

      result = call_external_tool(
          config, "do_thing", {}, connector=_flaky_connector,
          env={"TEST_MCP_TOKEN": "secret"},
      )
      assert result.ok
      assert result.observation == "ok"
      assert attempts["n"] == 3
  ```

  (`asynccontextmanager`, `TextContent`, `MCPServerConfig`, `call_external_tool` are
  already imported at the top of `test_integrations_mcp_client.py` per its existing
  fixtures.)

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_integrations_mcp_client.py::test_call_external_tool_retries_a_transient_connection_failure -v
  ```

  Expected: FAIL — today's `call_external_tool` calls `asyncio.run(_run())` exactly
  once; the first `ConnectionError` is caught by the blanket `except Exception` and
  returned as a failed `ToolResult` immediately (`attempts["n"] == 1`, `result.ok is
  False`).

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/integrations/mcp_client.py`, add a transient-failure classifier near
  `_MAX_RESULT_CHARS` (around line 242):

  ```python
  _MAX_TRANSIENT_RETRIES = 3
  _TRANSIENT_RETRY_DELAY_S = 0.5

  # Network/connection-shaped failures only - never a policy denial (those
  # are returned as a failed ToolResult BEFORE any connection attempt, per
  # check_tool_call/validate_server_url/resolve_credential above, so they
  # never reach this classifier at all) and never an application-level tool
  # error the server itself reported (isError=True in _run(), which raises
  # RuntimeError with the server's own message - retrying an identical call
  # against a server that just said "invalid arguments" wastes attempts on
  # a failure retrying can never fix).
  _TRANSIENT_EXCEPTION_TYPES = (ConnectionError, TimeoutError, OSError)


  def _is_transient_mcp_failure(exc: Exception) -> bool:
      return isinstance(exc, _TRANSIENT_EXCEPTION_TYPES) and not isinstance(exc, RuntimeError)
  ```

  Modify `call_external_tool`'s try/except around `asyncio.run(_run())` (currently
  lines 291-294):

  ```python
      try:
          text = asyncio.run(_run())
      except Exception as exc:  # noqa: BLE001 - one dead/misbehaving integration must degrade, never crash the turn
          return ToolResult(observation=f"error: connection {config.name!r} failed: {exc}", ok=False)
      return ToolResult(observation=text, ok=True)
  ```

  becomes:

  ```python
      last_exc: Exception | None = None
      for attempt in range(_MAX_TRANSIENT_RETRIES):
          try:
              text = asyncio.run(_run())
          except Exception as exc:  # noqa: BLE001 - one dead/misbehaving integration must degrade, never crash the turn
              last_exc = exc
              if not _is_transient_mcp_failure(exc) or attempt == _MAX_TRANSIENT_RETRIES - 1:
                  break
              time.sleep(_TRANSIENT_RETRY_DELAY_S)
              continue
          return ToolResult(observation=text, ok=True)
      return ToolResult(
          observation=f"error: connection {config.name!r} failed: {last_exc}", ok=False
      )
  ```

  Add `import time` to the existing import block (currently `import asyncio` /
  `import os` at lines 77-78 — add alphabetically):

  ```python
  import asyncio
  import os
  import time
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_integrations_mcp_client.py::test_call_external_tool_retries_a_transient_connection_failure -v
  ```

  Expected: PASS.

- [ ] **Step 5: Run the full MCP client suite to confirm no regression**

  ```
  uv run pytest tests/lalo/test_integrations_mcp_client.py -v
  ```

  Expected: all PASS — every existing failure-path test either raises a non-transient
  exception (unaffected — breaks on attempt 1 exactly as before) or exercises the
  policy-check paths (`check_tool_call`/`validate_server_url`/`resolve_credential`),
  none of which reach the modified retry loop at all.

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/integrations/mcp_client.py tests/lalo/test_integrations_mcp_client.py
  git commit -m "fix(mcp): retry a transient connection failure before giving up

Each MCP call already does a fresh connect-call-disconnect cycle with no
persistent session, so a background-task-cancels-the-scan risk doesn't apply
here - but a single transient network blip still failed the whole call with
no retry at all. Adds a small, bounded retry loop for network/connection-
shaped exceptions only; a policy denial or an application-level tool error
the server itself reported still fails on the first attempt, unchanged."
  ```

---

### Task 6: Split the MCP session timeout into connect and per-call phases

**Files:**
- Modify: `src/lalo/integrations/mcp_client.py:207` (`_DEFAULT_SESSION_TIMEOUT`),
  `:210-239` (`_default_connector`)
- Test: `tests/lalo/test_integrations_mcp_client.py` (append)

**Interfaces:**
- Consumes: nothing.
- Produces: `_default_connector`'s signature is unchanged; a new module constant
  `_DEFAULT_CONNECT_TIMEOUT` is added alongside the existing `_DEFAULT_SESSION_TIMEOUT`
  (kept, now documented as the per-call operation timeout specifically).

**Context:** Today one flat 30-second `read_timeout_seconds` covers both the initial
`session.initialize()` handshake and every subsequent `call_tool()` — a legitimately
slow but healthy operation (a cloud-describe fan-out that takes 25 seconds) and a
genuinely hung handshake are indistinguishable to this single number. This is a small,
low-priority precision fix: give the handshake its own shorter timeout, independent
of a longer operation timeout for the actual tool call.

- [ ] **Step 1: Write the failing test**

  ```python
  def test_connect_timeout_is_shorter_than_the_operation_timeout() -> None:
      """A hung handshake should be caught faster than a hung tool call is
      allowed to legitimately run - the two timeouts must be independently
      named constants, not the same flat number reused for both."""
      from lalo.integrations.mcp_client import _DEFAULT_CONNECT_TIMEOUT, _DEFAULT_SESSION_TIMEOUT

      assert _DEFAULT_CONNECT_TIMEOUT < _DEFAULT_SESSION_TIMEOUT
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_integrations_mcp_client.py::test_connect_timeout_is_shorter_than_the_operation_timeout -v
  ```

  Expected: FAIL — `_DEFAULT_CONNECT_TIMEOUT` doesn't exist yet (`ImportError`).

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/integrations/mcp_client.py`, replace the single timeout constant
  (currently line 207) with two:

  ```python
  # A hung handshake (session.initialize()) should be caught faster than a
  # legitimately slow but healthy tool call is allowed to run - one flat
  # number previously covered both, unable to distinguish "the server is
  # genuinely dead at connect time" from "this specific call is just slow."
  from datetime import timedelta

  _DEFAULT_CONNECT_TIMEOUT = timedelta(seconds=10)
  _DEFAULT_SESSION_TIMEOUT = timedelta(seconds=30)
  ```

  (`from datetime import timedelta` is already imported at the top of the file —
  remove the duplicate import line above if adding it inline; the constant
  definitions alone are the actual change needed.)

  `ClientSession`'s own constructor only accepts one `read_timeout_seconds` applied to
  every request uniformly (confirmed via the existing `_default_connector` body,
  which passes it once at session construction, not per-call) — the `mcp` SDK does
  not expose a separate per-call override. Given that constraint, the honest,
  minimal fix achievable without vendoring a session wrapper is: use
  `_DEFAULT_CONNECT_TIMEOUT` for the `session.initialize()` call specifically (call it
  with `asyncio.wait_for`, which the SDK's own async call supports independent of the
  session's own configured timeout), and keep `_DEFAULT_SESSION_TIMEOUT` as the
  session-level default for every subsequent `call_tool()`:

  ```python
  @asynccontextmanager
  async def _default_connector(
      config: MCPServerConfig, credential: str
  ) -> AsyncIterator[ClientSession]:
      if config.transport == "stdio":
          params = StdioServerParameters(
              command=config.command or "",
              args=list(config.args),
              env={config.credential_env_var: credential},
          )
          async with stdio_client(params) as (read, write):
              async with ClientSession(
                  read, write, read_timeout_seconds=_DEFAULT_SESSION_TIMEOUT
              ) as session:
                  await asyncio.wait_for(
                      session.initialize(), timeout=_DEFAULT_CONNECT_TIMEOUT.total_seconds()
                  )
                  yield session
      else:
          from mcp.client.streamable_http import streamablehttp_client

          headers = {"Authorization": f"Bearer {credential}"}
          async with streamablehttp_client(config.url or "", headers=headers) as (
              read,
              write,
              _get_session_id,
          ):
              async with ClientSession(
                  read, write, read_timeout_seconds=_DEFAULT_SESSION_TIMEOUT
              ) as session:
                  await asyncio.wait_for(
                      session.initialize(), timeout=_DEFAULT_CONNECT_TIMEOUT.total_seconds()
                  )
                  yield session
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_integrations_mcp_client.py::test_connect_timeout_is_shorter_than_the_operation_timeout -v
  ```

  Expected: PASS.

- [ ] **Step 5: Run the full MCP client suite to confirm no regression**

  ```
  uv run pytest tests/lalo/test_integrations_mcp_client.py -v
  ```

  Expected: all PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/integrations/mcp_client.py tests/lalo/test_integrations_mcp_client.py
  git commit -m "fix(mcp): give the connect handshake its own, shorter timeout

One flat 30s timeout covered both session.initialize() and every later
call_tool(), unable to distinguish a genuinely dead server from a legitimately
slow operation. The handshake now fails fast at 10s independent of the
30s operation timeout every subsequent tool call still gets."
  ```

---

### Task 7: Sanitize the model-facing MCP tool/connection name

**Files:**
- Modify: `src/lalo/integrations/mcp_client.py:298-334` (`build_mcp_tool`)
- Test: `tests/lalo/test_integrations_mcp_client.py` (append)

**Interfaces:**
- Consumes: nothing.
- Produces: a new pure function `_sanitize_tool_label(name: str) -> str`. No change
  to `build_mcp_tool`'s public signature.

**Context:** `build_mcp_tool` builds the exposed tool's `name` as
`f"mcp_{config.name}"`. `config.name` is an operator-declared config value with no
validation against what a model's tool-calling API considers a legal tool name
(commonly `[a-zA-Z0-9_-]` only) — a space, a unicode character, or a punctuation mark
in a config file's connection name would produce a tool name some providers reject
outright. This never changes which server/tool actually gets called — only the label
the model sees.

- [ ] **Step 1: Write the failing test**

  ```python
  def test_build_mcp_tool_sanitizes_a_connection_name_with_invalid_characters() -> None:
      """A connection name from an operator's config file might contain
      spaces/punctuation a model's tool-calling API won't accept as a tool
      name - the exposed name must be sanitized even though the real
      dispatch still uses the connection's own unmodified name internally."""
      config = MCPServerConfig(
          name="my db (prod)", transport="http", credential_env_var="X",
          allowed_tools={}, url="https://example.com",
      )
      tool = build_mcp_tool(config)
      assert tool.name == "mcp_my_db__prod_"
      import re
      assert re.fullmatch(r"[a-zA-Z0-9_-]+", tool.name)
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_integrations_mcp_client.py::test_build_mcp_tool_sanitizes_a_connection_name_with_invalid_characters -v
  ```

  Expected: FAIL — today's `tool.name` is the literal `"mcp_my db (prod)"`, containing
  spaces and parentheses.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/integrations/mcp_client.py`, add the sanitizer near `build_mcp_tool`
  (around line 296):

  ```python
  import re

  _INVALID_TOOL_NAME_CHARS = re.compile(r"[^a-zA-Z0-9_-]")


  def _sanitize_tool_label(name: str) -> str:
      """The MODEL-FACING label only - dispatch always uses the connection's
      own unmodified config.name (see call_external_tool/check_tool_call,
      neither of which goes through this function), so a config value with
      characters a model's tool-calling API rejects still works correctly,
      it's just displayed differently to the model.
      """
      return _INVALID_TOOL_NAME_CHARS.sub("_", name)
  ```

  Modify `build_mcp_tool`'s `name=` line (currently in the `FunctionTool(...)`
  construction near line 322):

  ```python
      return FunctionTool(
          name=f"mcp_{_sanitize_tool_label(config.name)}",
          description=(
  ```

  (`import re` — check whether `re` is already imported in this file; if not, add it
  to the top-level import block alongside the existing `import asyncio` / `import os`
  / `import time` (from Task 5) imports, alphabetically.)

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_integrations_mcp_client.py::test_build_mcp_tool_sanitizes_a_connection_name_with_invalid_characters -v
  ```

  Expected: PASS.

- [ ] **Step 5: Run the full MCP client suite to confirm no regression**

  ```
  uv run pytest tests/lalo/test_integrations_mcp_client.py -v
  ```

  Expected: all PASS — every existing test presumably uses an already-valid
  connection name (e.g. `"test"`), which `_sanitize_tool_label` leaves unchanged.

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/integrations/mcp_client.py tests/lalo/test_integrations_mcp_client.py
  git commit -m "fix(mcp): sanitize the model-facing tool name for invalid characters

An operator-declared connection name could contain a space or punctuation a
model's tool-calling API rejects outright as a tool name. Sanitizes only the
label the model sees; dispatch still uses the connection's own unmodified
name internally, so behavior is unaffected for any already-valid name."
  ```

---

### Task 8: Tolerate a JSON-encoded-string or nullish tool-call argument

**Files:**
- Modify: `src/lalo/agent/tools.py:27-43` (`str_arg`, unchanged — reference only),
  `:123-126` (`_to_call`)
- Test: `tests/lalo/test_tools.py` (append)

**Interfaces:**
- Consumes: nothing.
- Produces: a new pure function `_coerce_args(raw: object) -> dict[str, object]`
  replacing the inline `raw_args if isinstance(raw_args, dict) else {}` check inside
  `_to_call`.

**Context:** `_to_call`'s current line — `raw_args = obj.get("args", {}); args =
raw_args if isinstance(raw_args, dict) else {}` — silently discards every argument
the model sent whenever `args` arrives as a JSON-encoded *string* rather than a
native JSON object (a real, observed small-model failure mode: emitting
`{"tool": "http", "args": "{\"url\": \"http://x\"}"}` instead of a nested object).
Today this becomes an empty-args call with no error and no signal to the model that
anything went wrong. This task decodes a JSON-object-shaped string before falling
back to `{}`.

- [ ] **Step 1: Write the failing test**

  Add to `tests/lalo/test_tools.py` (the file already tests `parse_tool_call`
  directly with raw text blobs — reuse that pattern):

  ```python
  def test_parse_tool_call_decodes_a_json_encoded_string_args_value() -> None:
      """A model sometimes emits args as a JSON-encoded STRING rather than a
      native object - today this silently becomes empty args with no signal
      anything went wrong."""
      call = parse_tool_call('{"tool": "http", "args": "{\\"url\\": \\"http://x\\"}"}')
      assert call is not None
      assert call.args == {"url": "http://x"}

  def test_parse_tool_call_still_defaults_a_non_object_non_string_args_to_empty() -> None:
      """A genuinely nonsensical args value (a number, a list) must still
      degrade to empty args, not raise."""
      call = parse_tool_call('{"tool": "http", "args": 42}')
      assert call is not None
      assert call.args == {}
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_tools.py::test_parse_tool_call_decodes_a_json_encoded_string_args_value -v
  ```

  Expected: FAIL — `call.args == {}` today (the string value fails the
  `isinstance(raw_args, dict)` check and falls back to the empty-dict default).

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/agent/tools.py`, add the coercion helper right before `_to_call`
  (around line 122):

  ```python
  def _coerce_args(raw: object) -> dict[str, object]:
      """``args`` as the model actually sent it - a native dict is used as-is;
      a JSON-encoded STRING that decodes to an object is decoded (a real,
      observed small-model failure mode: emitting the whole ``args`` value as
      a quoted JSON string instead of a nested object); anything else
      (missing, a number, a list, a malformed string) degrades to an empty
      dict rather than raising, matching this parser's overall tolerant
      design.
      """
      if isinstance(raw, dict):
          return raw
      if isinstance(raw, str):
          decoded = _try_load(raw)
          if decoded is not None:
              return decoded
      return {}
  ```

  Modify `_to_call` (currently lines 123-126):

  ```python
  def _to_call(obj: dict[str, object], *, dropped_calls: int = 0) -> ToolCall:
      args = _coerce_args(obj.get("args", {}))
      return ToolCall(name=str(obj["tool"]), args=args, dropped_calls=dropped_calls)
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_tools.py -k "coerce or json_encoded_string_args or non_object_non_string" -v
  ```

  Expected: both new tests PASS.

- [ ] **Step 5: Run the full tools suite to confirm no regression**

  ```
  uv run pytest tests/lalo/test_tools.py tests/lalo/test_agent_loop.py -v
  ```

  Expected: all PASS — every existing call already sends `args` as a native dict or
  omits it, both already handled identically by `_coerce_args`.

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/agent/tools.py tests/lalo/test_tools.py
  git commit -m "fix(agent): decode a JSON-encoded-string args value instead of dropping it

A model occasionally emits a tool call's args as a quoted JSON string rather
than a native object; this previously silently became empty args with no
signal anything went wrong. Now decoded when it parses as an object; any
other malformed shape still degrades to empty args rather than raising."
  ```

---

### Task 9: Strip control characters from finding titles before rendering

**Files:**
- Modify: `src/lalo/report/collect.py` (the exact function that builds a
  `FindingRecord.title` from a graph node — re-read live at implementation time to
  confirm the current field-extraction line; `collect_findings` per the design spec's
  own citation)
- Test: `tests/lalo/test_report_collect.py` (append)

**Interfaces:**
- Consumes: nothing.
- Produces: a new pure function `_clean_title(title: str) -> str` used inside
  `collect_findings`.

**Context:** A finding's title routinely quotes text captured verbatim from the
target (a reflected parameter, a banner string), which can carry embedded `\r`, `\n`,
or other control characters. `report/csv_export.py`'s `csv_safe` (formula-injection)
and `report/markdown.py`'s `safe_fence` (fence-breakout) already exist and cover
their respective concerns — confirmed by reading both files live this session — but
neither strips a raw control character from a title before it renders as a Markdown
heading, a CSV cell, or a GUI list row, where an embedded newline can corrupt the
surrounding structure (a fake extra heading, a broken CSV row).

- [ ] **Step 1: Write the failing test**

  Add to `tests/lalo/test_report_collect.py` (read the file's own existing
  `collect_findings`-exercising fixture — it already builds a `ReachabilityGraph`,
  adds a `FINDING` node with a `title` attribute, and asserts on the resulting
  `FindingRecord` — reuse that exact construction):

  ```python
  def test_collect_findings_strips_control_characters_from_the_title() -> None:
      graph = ReachabilityGraph()
      graph.add_node(
          "finding-1", NodeKind.FINDING,
          title="Reflected value\r\ncontains a newline",
          description="d", vuln_class="xss", target="http://x", param=None,
          evidence=["e"], evidence_excerpt="e", evidence_grounded=True,
          counterevidence="c", severity_change_conditions="s", remediation="r",
          cvss_score=5.0, cvss_severity="medium", cvss_vector="v",
          reproduced=False, identities_confirmed=[], dedup_key="k",
      )
      records = collect_findings(graph)
      assert "\r" not in records[0].title
      assert "\n" not in records[0].title
      assert "Reflected value" in records[0].title
  ```

  (Match the exact keyword set `test_report_collect.py`'s existing tests already pass
  to `graph.add_node` for a `FINDING` node — re-read the file's own first test at
  implementation time and copy its real attribute set verbatim rather than the
  illustrative one above, since `collect_findings`'s exact required node attributes
  must match live `report/collect.py` precisely.)

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_report_collect.py::test_collect_findings_strips_control_characters_from_the_title -v
  ```

  Expected: FAIL — `records[0].title` currently contains the raw `\r\n`.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/report/collect.py`, add near the top of the file (after imports):

  ```python
  import re

  _CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\r\n?|\n")


  def _clean_title(title: str) -> str:
      """Collapse embedded control characters (a raw newline/CR most commonly,
      from a target-controlled title quoting a reflected value verbatim) to a
      single space, so a title can never inject a fake extra Markdown
      heading, corrupt a CSV row, or break a GUI list row's own structure."""
      return _CONTROL_CHARS.sub(" ", title).strip()
  ```

  In `collect_findings` (the function iterating `graph.nodes_of_kind(NodeKind.FINDING)`
  and constructing each `FindingRecord`), wrap the `title` field assignment:

  ```python
      records.append(
          FindingRecord(
              ...,
              title=_clean_title(str(node["title"])),
              ...,
          )
      )
  ```

  (Re-read the live function body at implementation time to insert this at the exact
  existing `title=node["title"]`-shaped line — do not guess the surrounding
  construction's exact field order or variable names; only the `title` value's
  wrapping changes, every other field stays exactly as it is today.)

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_report_collect.py::test_collect_findings_strips_control_characters_from_the_title -v
  ```

  Expected: PASS.

- [ ] **Step 5: Run the full report-collect suite to confirm no regression**

  ```
  uv run pytest tests/lalo/test_report_collect.py -v
  ```

  Expected: all PASS — every existing test uses an ordinary, control-character-free
  title, unaffected by `_clean_title`.

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/report/collect.py tests/lalo/test_report_collect.py
  git commit -m "fix(report): strip control characters from a finding title on collection

A title quoting target-controlled text verbatim (a reflected parameter, a
banner) can carry an embedded newline or other control character, corrupting
a rendered Markdown heading, a CSV row, or a GUI list row's own structure.
Collapsed to a space at the single point every report format already reads
titles from."
  ```

---

## Closure notes (verified during this planning pass — no task needed)

The following items from the design spec's mechanism-gap table (§4) and non-issues
section (§5) were checked against live current source while writing this plan and
found to already be covered, structurally inapplicable, or smaller in scope than
first described. Recorded here so a future pass doesn't re-open them without a new
reason.

- **M3 (statusless/network-error retry).** `core/providers.py`'s `_post_with_retry`
  already catches the bare `httpx.HTTPError` base class (covering every transport-
  level failure — connection resets, timeouts, DNS failures — none of which carry an
  HTTP status code) and retries up to `_MAX_ATTEMPTS=3` times with backoff. This is
  already a "retry anything with no status code" policy in effect; no narrower
  status-code allowlist exists to widen. No task needed.
- **M5 (content-refusal labeling).** All three provider adapters
  (`AnthropicProvider`, `OpenAICompatibleProvider`, `OpenAIResponsesProvider`) already
  detect a structured refusal in otherwise-normal-shaped response content
  (`stop_reason == "refusal"`, `finish_reason == "content_filter"`,
  `block.get("type") == "refusal"`) and raise the already-distinct
  `ProviderRefusalError` — separate from `ProviderUnavailableError` — for exactly
  this case. `ModelRouter` already catches both distinctly. No task needed.
- **M16 (structured non-exception refusal).** Same evidence as M5 above — a refusal
  arriving as normal-shaped content is already converted into a distinct typed
  exception at the exact point it's detected, in every adapter. No task needed.
- **M7 (compaction tool-call/observation pairing).** `agent/loop.py`'s `transcript`
  entries are unified per-step dicts (`{"tool": ..., "args": ..., "observation":
  ...}`) built once the tool has already run and its result is known — there is no
  separate, providerpaired "call" item and "result" item the way a native-function-
  calling API's history has, so a compaction cut can never separate a call from its
  own result; the failure mode this item worried about is structurally impossible in
  L4L0's transcript shape. No task needed.
- **M12 (coverage/finding-ledger concurrency).** `findings/tool.py`'s
  `build_record_finding_tool` operates on whatever `ReachabilityGraph` it's given;
  during a `spawn_agents` fan-out, each concurrently-running child operates on its
  OWN isolated graph snapshot (via `agent/spawn.py`'s `isolate_for_child`), never the
  shared parent graph directly — the only shared-graph touch is the post-completion
  merge step, already serialized under `scan.py`'s own graph lock. There is no
  concurrent-write race on the current finding-record path to fix. (The NEW coverage-
  ledger tool being built in the companion capabilities plan is a different, genuinely
  new piece of shared state and must be designed with its own lock from the start —
  noted there, not here.)
- **M15 (unknown-tool-name recovery).** `agent/tools.py`'s `ToolRegistry.dispatch`
  already returns `ToolResult(observation=f"error: unknown tool {name!r}", ok=False)`
  for an unrecognized name — confirmed by direct read, never raises. No task needed.
- **M17 (Docker teardown exception hierarchy).** `runtime/container.py`'s
  `RuntimeContainer.stop()`/`_best_effort_remove` shell out to the `docker` CLI via
  `subprocess`, not the docker-py SDK — the specific sibling-exception trap strix's
  test guards against (`docker.errors.APIError` vs `requests.exceptions.
  ConnectionError`, two classes under a third-party SDK's own hierarchy) does not
  apply, since neither exception type is ever raised by a subprocess call; the
  existing `subprocess.TimeoutExpired` handling already covers the equivalent
  daemon-unresponsive failure shape. No task needed.
- **M11 remainder (CSV/Markdown injection hardening).** `report/csv_export.py`'s
  `csv_safe` (CWE-1236 formula-injection prefix) and `report/markdown.py`'s
  `safe_fence` (dynamic fence-widening past embedded backticks) already exist and
  were confirmed correct by direct read. Only the title-control-character gap (Task 9
  above) was a real, missing piece.
- **Graduated budget-warning cascade, MCP client existing, live operator steering,
  tool-call-ID collision, per-turn tool-call-count cap, local file 0600 permissions,
  operator-context scope-override guard, SARIF PoC-embedding, the concurrent
  reserve-notification race.** All already confirmed covered or structurally
  inapplicable in the design spec's own §5/§6 with live-source evidence recorded
  there — not re-verified again here since nothing about them is mechanism-fix
  shaped.

## Self-review

**Spec coverage:** every M1–M17 row and the CSRF item are accounted for above, either
as a task (1, 2, 3, 4, 5, 6, 7, 8, 9 — nine tasks covering M1, M2, M6, M8, M9, M10,
M13, M14, and the title-control-character part of M11) or a closure note (M3, M5, M7,
M11's csv/fence parts, M12, M15, M16, M17). No spec item is unaddressed.

**Placeholder scan:** no "TBD"/"TODO"/"add appropriate handling" anywhere above; every
step shows real code or an exact command.

**Type/signature consistency:** `_coerce_args` (Task 8) returns `dict[str, object]`,
matching `ToolCall.args`'s existing type. `_clean_title` (Task 9) takes and returns
`str`, matching `FindingRecord.title`'s existing type. `AgentConfig.context_window_tokens:
int | None = None` (Task 2) and its consumer `_pending_batch_exceeds_budget` (also
Task 2) agree on `int | None`. `_is_transient_mcp_failure(exc: Exception) -> bool`
(Task 5) is called only from within `call_external_tool`'s own `except Exception as
exc` block, so the parameter type matches every call site.
