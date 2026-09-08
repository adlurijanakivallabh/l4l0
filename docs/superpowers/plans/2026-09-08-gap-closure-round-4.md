# Gap-Closure Round 4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close 16 real capability/robustness gaps and add curated-provider/reporting polish surfaced by a fresh, exhaustive completeness audit against a mature reference security-agent project, while preserving L4L0's design center of maximum operator/agent freedom.

**Architecture:** Each task is an independent, additive change to an existing module (no new subsystems except a small IMAP-fetch tool and a per-run narrative log) — bug fixes first (credential redaction, resume idempotency, error-message wiring), then bounded capability/robustness additions, then reporting polish, then two architectural capability additions (a durable narrative log, an email/IMAP login tool), with one item (AWS Bedrock) resolved as an investigated-and-deferred note rather than a forced implementation.

**Tech Stack:** Python 3.13+, `uv` for env/deps, pytest for tests, Ruff for lint/format, mypy (strict) for types — matching this project's existing stack exactly.

**Spec:** No separate spec document — this plan was drafted directly from a 12-subsystem completeness audit's synthesized findings (kept as this plan's own record; the audit itself read a reference project's real source, which this project's own conventions require never be named in code/docs/commits — every task below describes patterns generically).

## Global Constraints

- Never name any reference project anywhere in code, comments, docs, or commit messages — describe patterns generically (this project's standing convention).
- Maximum agent/operator freedom is the design center: no confirmation gates, no per-action approval, nothing withheld from reports. Any new validation/limit/warning in this plan is non-blocking, informational, or opt-in (matching the existing `max_steps`/`max_duration_s`/`exclude_rules` precedent) — never a new default restriction. An operator-facing "don't test production" warning was explicitly considered and rejected as an unwanted restriction; it is not part of this plan.
- Read the actual current source before writing or trusting any signature/line-number claim — this project's own standing discipline. Several tasks below already record a live-verified correction to their own originating audit item; trust the verified code, not the audit's prose, wherever they conflict.
- Run only tests related to each task's change by default (`uv run pytest <specific path>`), not the full suite, except in the Final Check below.
- Lint/format/type-check after each task: `uv run ruff check src/lalo tests/lalo`, `uv run ruff format src/lalo tests/lalo`, `uv run mypy`.
- Commit per task with a real, specific message ending `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>` per this project's own commit convention.

## Explicitly deferred (not tasks in this plan)

- Subscription/OAuth credential-file reuse for provider billing — real ToS risk to the operator for an unattended autonomous workload; not pursued.
- Switching the existing curated `openai` provider entry from Chat Completions to the Responses API shape — risk of the same kind of subtle breakage a universal provider library evaluation surfaced and was rejected for earlier the same day this plan was written; needs its own independently-live-tested follow-up.
- A real-world-OSS-app-plus-patch-mining benchmark methodology (scoring recall against actual CVE-fixing commits) — a large, separate benchmarking effort, not a code gap.
- A checked-in sample report artifact and a static coverage-mapping document — documentation/positioning artifacts with no functional code behind them.
- The project's existing confined `source_reviewer` spawn role (opt-in, narrower toolset, inside a fully disposable no-host-mount/no-socket container) already covers the same host-escape threat class a reference project's own in-process filesystem jail addresses, just at a coarser but architecturally sufficient grain — no code change needed.
- An operator-facing "do not run against production" warning was explicitly rejected by the operator as an unwanted restriction and is not included anywhere in this plan.

---

### Task 1: Register TOTP secret with the shared redactor

**Files:**
- Modify: `src/lalo/identity/tool.py:50-56` (the `build_login_tool` signature/body, immediately before the `_login` closure)
- Test: `tests/lalo/test_identity_tool.py` (new test added after `test_login_as_registers_the_session_material_with_the_shared_redactor`, currently ending at line 142)

**Interfaces:**
- Consumes: `lalo.core.redaction.shared_redactor` (already imported in `identity/tool.py:43`, no new import needed) and its `.register_secret(value: str) -> None` method; `lalo.identity.login.LoginScheme.totp_secret: str | None` (`identity/login.py:59`); `build_login_tool(firer: HttpFirer, identities: IdentityStore, sessions: SessionRegistry, schemes: dict[str, LoginScheme]) -> FunctionTool` (existing signature, unchanged).
- Produces: no new public names. `build_login_tool` now has the side effect of registering every non-`None` `LoginScheme.totp_secret` in `schemes` with `shared_redactor()` at tool-build time, in addition to its existing behavior.

**Investigation notes (read all three files in full before writing code):**
- `identity/credentials.py`: `IdentityStore.add()` (line 64-68) is the existing precedent — it registers `identity.credential.value` with `shared_redactor()` the moment an identity enters the store.
- `identity/tool.py`: `build_login_tool`'s `_login` closure (line 86 in the current file) registers `session.value` with `shared_redactor()` the moment a login succeeds.
- `identity/login.py`: `LoginScheme` (line 43-60) is a plain frozen dataclass with no `__post_init__` and no side effects on construction — matching `Identity`/`Credential`'s own construction, which are also side-effect-free (their registration happens in the separate `IdentityStore.add()` step, not in `__init__`). `totp_secret` (line 59) is read in exactly one place, `login()` (line 130-136), only to derive the current 6-digit code — the raw secret itself is never put into any log/error string there (`TotpSecretError`'s message only echoes the base64-decode exception, never the secret value).
- There is no `LoginSchemeStore` class and no equivalent `.add()` step for schemes — `login_schemes: dict[str, LoginScheme]` is a plain `ScanConfig` field (`src/lalo/scan.py:223`) consumed directly by `build_login_tool(..., self.config.login_schemes)` (`scan.py:1160`). Within the three files this task is scoped to, `build_login_tool` is the one place that receives the *entire* `schemes` collection as a unit — the direct analogue of `IdentityStore.add()` receiving one `Identity` at a time — so a loop over `schemes.values()` at the top of `build_login_tool`, executed once at tool-build time (not lazily inside `_login`), is the correct call site: it protects a configured secret the moment it's wired into a running scan, independent of whether any agent ever actually calls `login_as` with it.
- Scope note: `ScanRunner._preflight_logins` (`scan.py:765-810`) calls `login()` directly, bypassing `build_login_tool` entirely, and runs *before* `build_login_tool` is ever invoked for the first agent. This is a pre-existing timing characteristic the password path already has too — `IdentityStore.add()` (which registers `identity.credential.value`) also only runs at `scan.py:1008-1010`, *after* preflight logins have already run once. Since `login()` never puts the raw secret into any log/error/event string (verified above), this preflight window is not a live leak path for either credential type today, so this task does not touch `scan.py` or attempt to close that pre-existing, out-of-scope timing gap.

- [ ] **Step 1: Write the failing test.** Add to `tests/lalo/test_identity_tool.py`, directly after `test_login_as_registers_the_session_material_with_the_shared_redactor` (ends at line 142):

  ```python
  def test_login_scheme_totp_secret_is_registered_with_the_shared_redactor() -> None:
      """Mirrors test_adding_an_identity_registers_its_credential_for_universal_redaction
      (test_identity.py) for the one LoginScheme field IdentityStore.add() never sees:
      a scheme's totp_secret. Registration happens at build time, not login time -- the
      tool is built here but never run, proving the secret is protected the moment a
      scheme carrying one is wired in, not only after a login happens to succeed.

      ``secret`` is deliberately short and low-entropy (not a plausible real base32
      TOTP seed) and the surrounding sentence avoids every word the redactor's
      pattern layer keys on ("token", "secret=", etc.) -- unlike this module's own
      ``super-secret-value``/``zzz-unique-marker`` style fixtures elsewhere, which
      the pattern layer alone would already catch, so this is the only way to prove
      register_secret() itself (not the unrelated pattern layer) is what redacts it.
      """
      secret = "totp-seed-mk9-77"
      scheme = LoginScheme(login_url="https://app.example.com/login", totp_secret=secret)
      build_login_tool(
          _firer(lambda r: httpx.Response(200)),
          IdentityStore(),
          SessionRegistry(ReachabilityGraph()),
          {"s": scheme},
      )
      leaked_line = f"login flow needs one-time code derived from {secret}"
      assert secret not in shared_redactor().redact(leaked_line)
  ```

  No new imports needed — `shared_redactor`, `LoginScheme`, `IdentityStore`, `SessionRegistry`, `ReachabilityGraph`, `build_login_tool`, `httpx`, and `_firer` are all already imported/defined earlier in this file.

  Note on the test value: an initial draft used a base32-looking secret (e.g. `base64.b32encode(...)`) in a line like `f"totp_secret={secret}"` and it passed *even without any fix applied*, because `core/redaction.py`'s generic high-entropy pattern layer (`_HIGH_ENTROPY_TOKEN` + `looks_secret_shaped`) independently redacts any long base64/hex-ish blob regardless of `register_secret()` ever being called. The chosen short, low-entropy `"totp-seed-mk9-77"` plus a context sentence with no trigger words is what actually isolates the exact-match layer being exercised. (This same weakness silently affects a couple of pre-existing tests in the suite, e.g. `test_shared_instance_is_universal` in `test_redaction.py`, whose `"token=..."` phrasing is independently caught by the pattern layer's key=value regex — out of scope for this task, noted only so no one re-derives false confidence from those as a template.)

- [ ] **Step 2: Run test to verify it fails.**

  ```
  uv run pytest tests/lalo/test_identity_tool.py::test_login_scheme_totp_secret_is_registered_with_the_shared_redactor -q
  ```

  Expected failure (confirmed by actually running it against the pre-fix code):
  ```
  AssertionError: assert 'totp-seed-mk9-77' not in 'login flow ...-seed-mk9-77'
  ```

- [ ] **Step 3: Write minimal implementation.** In `src/lalo/identity/tool.py`, insert a loop at the top of `build_login_tool`, before the `_login` closure is defined:

  ```python
  def build_login_tool(
      firer: HttpFirer,
      identities: IdentityStore,
      sessions: SessionRegistry,
      schemes: dict[str, LoginScheme],
  ) -> FunctionTool:
      # Every configured scheme's totp_secret is operator/engagement-setup
      # knowledge, exactly like identity.credential.value (registered by
      # IdentityStore.add()) and the session material registered below -- it
      # must never leak into a log line or captured observation unredacted
      # either. Registered once here, at tool-build time (this dict is fixed
      # for the life of the scan), not lazily inside `_login` on first use, so
      # a scheme's secret is protected the moment it's wired in even if no
      # agent ever calls login_as with it.
      for scheme in schemes.values():
          if scheme.totp_secret is not None:
              shared_redactor().register_secret(scheme.totp_secret)

      def _login(args: dict[str, object]) -> ToolResult:
          ...  # unchanged
  ```

  No new imports (`shared_redactor` is already imported at `identity/tool.py:43`). This is purely additive — informational registration with the shared redactor, not a gate, limit, or block of any kind; it never rejects a scheme, never blocks `login_as`, and changes no return value or control flow. It fully respects the project's non-blocking safety posture.

- [ ] **Step 4: Run test to verify it passes.**

  ```
  uv run pytest tests/lalo/test_identity_tool.py::test_login_scheme_totp_secret_is_registered_with_the_shared_redactor -q
  ```

  Expected: `1 passed`. Also run the full identity-adjacent files to confirm no regression (verified locally: `40 passed`):

  ```
  uv run pytest tests/lalo/test_identity_tool.py tests/lalo/test_identity.py tests/lalo/test_identity_login.py -q
  ```

  Also run `uv run ruff check src/lalo/identity/tool.py tests/lalo/test_identity_tool.py`, `uv run ruff format --check src/lalo/identity/tool.py tests/lalo/test_identity_tool.py`, and `uv run mypy src/lalo/identity/tool.py` — all confirmed clean locally.

- [ ] **Step 5: Commit.**

  ```
  git add src/lalo/identity/tool.py tests/lalo/test_identity_tool.py
  git commit -m 'fix(identity): register a login scheme'"'"'s TOTP secret with the shared redactor

  LoginScheme.totp_secret was configured and used (identity/login.py'"'"'s login())
  but never joined the exact-match redaction set that identity.credential.value
  and session material already do, so a raw TOTP seed had no protection if it
  ever ended up in a log line or captured observation. build_login_tool now
  registers every scheme'"'"'s totp_secret at tool-build time, mirroring
  IdentityStore.add()'"'"'s own registration of credential.value.'
  ```

  (Avoid backticks/apostrophe-heavy phrasing inside the double-quoted heredoc pitfalls — the message above uses single-quote escaping (`'"'"'`) for the apostrophes in `scheme's`/`login()'s`/etc. to survive a `bash -c` style invocation safely; a plain `git commit -F -` with a heredoc, or simply rewording to avoid apostrophes, is equally acceptable and arguably simpler.)

---

### Task 2: Idempotent resume — journaled finish + report-manifest adoption

**Files:**
- Modify: `src/lalo/agent/loop.py:679-712` (replay loop) and `:788-792` (the `finish` branch inside `run()`)
- Modify: `src/lalo/report/manifest.py:23-36` (add a new function right before `verify_report_manifest`)
- Modify: `src/lalo/scan.py:183` (import) and `:1213-1281` (`ScanRunner._run_inside`, the block from `result = root_loop.run(...)` through the `write_report`/`write_report_manifest` call)
- Modify: `src/lalo/gui/app.py:118-247` (`_list_runs`, informational `report_valid` field)
- Modify: `src/lalo/gui/static/app.js:312-334` (`buildRunItem`, informational resume-button label)
- Test: `tests/lalo/test_agent_loop.py` (new test near the existing resume tests, ~line 1195)
- Test: `tests/lalo/test_scan.py` (new test near `test_resume_after_a_crash_does_not_redispatch_the_completed_step`, ~line 1860)
- Test: `tests/lalo/test_report_manifest.py` (two new tests after the existing manifest tests)
- Test: `tests/lalo/test_gui_app.py` (three new tests near the existing `report_formats` tests, ~line 220)

**Interfaces:**
- Consumes: `DurableJournal.has`/`.get`/`.run_once`/`.completed_keys()` (`src/lalo/orchestrator/journal.py`, unchanged); `AgentResult(stop_reason: str, steps: int, transcript: list[dict], summary: str = "")` (unchanged shape); `verify_report_manifest(run_dir: Path) -> list[str]` (existing, `src/lalo/report/manifest.py`).
- Produces: `read_report_manifest_paths(run_dir: Path) -> dict[str, Path] | None` (new, `src/lalo/report/manifest.py`) — the per-format report path recorded in a run's `report_manifest.json`, keyed exactly like `write_report`'s own return value, or `None` if no manifest exists. A journaled `finish` entry now has the shape `{"tool": "finish", "args": <original finish call args>, "observation": <summary string>}` at key `f"{agent_key}:{step}"` — any future code reading raw journal entries must treat `"finish"` as a reserved sentinel tool name (it was already reserved at the `AgentLoop.run()` dispatch level, never a real registry tool). `_list_runs`'s per-run dict (`src/lalo/gui/app.py`) gains a `report_valid: bool` key alongside the existing `has_report`/`report_formats`.

- [ ] **Step 1: Write the failing tests**

  In `tests/lalo/test_agent_loop.py`, add (right before `test_a_crash_after_journaling_but_mid_step_still_resumes_correctly`):

  ```python
  def test_finish_step_is_journaled_so_a_resumed_run_never_recalls_the_model(tmp_path) -> None:
      """A completed run's own "finish" turn must land in the journal like every
      other step - otherwise a later resume of the SAME run_dir replays every
      step up to (but not including) the finish, then falls through to the
      live loop and asks the model AGAIN, purely to hear it say "done" a
      second time - a real, avoidable cost on every resume of an already-
      finished scan.
      """
      registry = ToolRegistry([])
      journal = DurableJournal(tmp_path / "j.jsonl")
      router1 = _scripted(['{"tool": "finish", "args": {"summary": "all done"}}'])
      loop1 = AgentLoop(router1, registry, system_prompt="")  # type: ignore[arg-type]
      result1 = loop1.run("mission", journal=journal, agent_key="root")
      assert result1.stop_reason == "finished"
      assert journal.has("root:0")  # the finish turn itself must be journaled

      # "Resume": a fresh process, same run_dir/journal - the model must never
      # be asked anything at all, since the mission already finished cleanly.
      router2 = _scripted(["THIS SHOULD NEVER BE READ"])
      loop2 = AgentLoop(router2, registry, system_prompt="")  # type: ignore[arg-type]
      result2 = loop2.run("mission", journal=journal, agent_key="root")
      assert result2.stop_reason == "finished"
      assert result2.summary == "all done"
      assert router2.calls == 0  # zero fresh LLM calls -- a real cost bug otherwise
  ```

  In `tests/lalo/test_scan.py`, add (right before `test_resume_reseeds_the_spawn_counter_so_a_second_child_gets_a_fresh_agent_id`):

  ```python
  def test_resuming_an_already_finished_run_adopts_the_report_with_no_new_llm_work(
      tmp_path: Path, monkeypatch: pytest.MonkeyPatch
  ) -> None:
      """A run that already finished cleanly and wrote a verified report must
      be a pure no-op on resume: no fresh mission turn just to hear the model
      say "done" again, and no full re-run of the confidence/adversarial-review
      pass (a real, avoidable LLM call per already-reviewed finding) plus a
      report rewrite, all to reach the exact same conclusion a second time.
      """
      monkeypatch.setattr(scan_module, "docker_available", lambda: True)
      monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

      router1 = ModelRouter(
          providers={"fake": _ScriptedProvider(_respond)},
          routes={"reasoning": ("fake",), "review": ("fake",)},
          default_route=("fake",),
      )
      monkeypatch.setattr(scan_module, "build_router", lambda _settings: router1)

      run_dir = tmp_path / "run"
      config = ScanConfig(mission="find a bug", target_specs=["example.com"], run_dir=run_dir)
      outcome1 = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()
      assert outcome1.status is RunStatus.COMPLETED
      original_markdown = outcome1.report_paths["markdown"].read_text()
      original_manifest = (run_dir / "report_manifest.json").read_text()

      def _fail_on_anything_but_the_preflight_healthcheck(_call_index: int, prompt: str) -> str:
          if "FINDING TO REVIEW" in prompt:
              raise AssertionError(
                  "adversarial review must not re-run for an already-reviewed "
                  "finding on a no-new-work resume"
              )
          if "MISSION:" in prompt:
              raise AssertionError(
                  "the model must not be asked for a new mission turn on a "
                  "resume of an already cleanly-finished run"
              )
          return "ok"  # only the preflight verify_router() health-check call

      router2 = ModelRouter(
          providers={"fake": _ScriptedProvider(_fail_on_anything_but_the_preflight_healthcheck)},
          routes={"reasoning": ("fake",), "review": ("fake",)},
          default_route=("fake",),
      )
      monkeypatch.setattr(scan_module, "build_router", lambda _settings: router2)

      # SAME config/run_dir -- ScanRunner auto-detects the existing, already-
      # finished journal + manifest and must adopt the standing report rather
      # than regenerate it.
      outcome2 = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

      assert outcome2.status is RunStatus.COMPLETED
      assert outcome2.report_paths["markdown"].read_text() == original_markdown
      assert (run_dir / "report_manifest.json").read_text() == original_manifest
      events = load_run_events(run_dir).snapshot()[1]
      assert any(
          e.category == "status" and e.payload.get("event") == "report_adopted" for e in events
      )
  ```

  In `tests/lalo/test_report_manifest.py`, add (after `test_verify_report_manifest_reports_missing_manifest_itself`):

  ```python
  def test_read_report_manifest_paths_reconstructs_the_written_paths(tmp_path: Path) -> None:
      from lalo.report.manifest import read_report_manifest_paths, write_report_manifest

      (tmp_path / "report.md").write_text("hello", encoding="utf-8")
      (tmp_path / "report.json").write_text('{"a": 1}', encoding="utf-8")
      report_paths = {"md": tmp_path / "report.md", "json": tmp_path / "report.json"}
      write_report_manifest(tmp_path, report_paths)

      assert read_report_manifest_paths(tmp_path) == report_paths


  def test_read_report_manifest_paths_on_a_run_with_no_manifest_is_none(tmp_path: Path) -> None:
      from lalo.report.manifest import read_report_manifest_paths

      assert read_report_manifest_paths(tmp_path) is None
  ```

  In `tests/lalo/test_gui_app.py`, add (before `test_list_runs_report_formats_reflects_a_partial_pdf_failure`):

  ```python
  def test_list_runs_reports_report_valid_true_for_an_intact_manifest(tmp_path: Path) -> None:
      """report_valid is purely informational (the frontend never hides or
      disables Resume on it - see gui/static/app.js's own buildRunItem) but
      must correctly reflect whether ScanRunner's own idempotent-resume fast
      path (scan.py) would actually adopt this run's report rather than
      regenerate it."""
      from lalo.report.manifest import write_report_manifest

      run_dir = tmp_path / "abc123"
      run_dir.mkdir()
      (run_dir / "report.json").write_text("{}", encoding="utf-8")
      (run_dir / "report.md").write_text("# report", encoding="utf-8")
      write_report_manifest(run_dir, {"json": run_dir / "report.json", "md": run_dir / "report.md"})

      client, _ = _client(runs_dir=tmp_path)
      runs = client.get("/runs").json()["runs"]
      assert runs[0]["has_report"] is True
      assert runs[0]["report_valid"] is True


  def test_list_runs_reports_report_valid_false_with_no_manifest_at_all(tmp_path: Path) -> None:
      run_dir = tmp_path / "abc123"
      run_dir.mkdir()
      (run_dir / "report.json").write_text("{}", encoding="utf-8")
      (run_dir / "report.md").write_text("# report", encoding="utf-8")
      # no report_manifest.json written for this run

      client, _ = _client(runs_dir=tmp_path)
      runs = client.get("/runs").json()["runs"]
      assert runs[0]["has_report"] is True
      assert runs[0]["report_valid"] is False


  def test_list_runs_reports_report_valid_false_when_a_reported_file_drifted(
      tmp_path: Path,
  ) -> None:
      from lalo.report.manifest import write_report_manifest

      run_dir = tmp_path / "abc123"
      run_dir.mkdir()
      (run_dir / "report.json").write_text("{}", encoding="utf-8")
      (run_dir / "report.md").write_text("# report", encoding="utf-8")
      write_report_manifest(run_dir, {"json": run_dir / "report.json", "md": run_dir / "report.md"})
      (run_dir / "report.md").write_text("# a different report now", encoding="utf-8")

      client, _ = _client(runs_dir=tmp_path)
      runs = client.get("/runs").json()["runs"]
      assert runs[0]["report_valid"] is False
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```
  uv run pytest tests/lalo/test_agent_loop.py::test_finish_step_is_journaled_so_a_resumed_run_never_recalls_the_model -q
  ```
  Actual failure obtained by running this against the current code:
  ```
  >       assert journal.has("root:0")  # the finish turn itself must be journaled
  E       AssertionError: assert False
  E        +  where False = has('root:0')
  ```

  ```
  uv run pytest tests/lalo/test_scan.py::test_resuming_an_already_finished_run_adopts_the_report_with_no_new_llm_work -q
  ```
  Actual failure obtained by running this against the current code (the second `ScanRunner.run()` call itself raises, because the confidence/review loop unconditionally re-runs):
  ```
  >           raise AssertionError(
                  "adversarial review must not re-run for an already-reviewed "
                  "finding on a no-new-work resume"
              )
  E           AssertionError: adversarial review must not re-run for an already-reviewed finding on a no-new-work resume
  tests/lalo/test_scan.py: in _fail_on_anything_but_the_preflight_healthcheck
  ```
  (raised from `src/lalo/findings/review.py:_compute_review` via `src/lalo/scan.py:_run_inside`'s per-finding review loop.)

  The two `test_report_manifest.py` tests fail with `ImportError: cannot import name 'read_report_manifest_paths'` (the function does not exist yet); the three `test_gui_app.py` tests fail with `KeyError: 'report_valid'` (the field does not exist yet on the `/runs` response).

- [ ] **Step 3: Write the minimal implementation**

  **`src/lalo/agent/loop.py`** — journal the `finish` step, and make replay recognize it:

  In the replay `while` loop (currently just appends every entry and advances `start_step`), detect a journaled finish and return immediately instead of continuing to loop toward a live turn:
  ```python
              while journal.has(f"{agent_key}:{start_step}"):
                  entry = journal.get(f"{agent_key}:{start_step}")
                  if entry["tool"] == "finish":
                      # A prior attempt already reached a genuine, journaled
                      # finish for this agent -- resume must adopt that result
                      # outright rather than fall through to the live loop
                      # below and ask the model to declare the same mission
                      # finished a second time (a real, avoidable LLM call on
                      # every resume of an already-completed run).
                      self._emit("resumed", {"replayed_steps": start_step})
                      return AgentResult(
                          "finished", start_step + 1, transcript, summary=str(entry["observation"])
                      )
                  transcript.append(
                      {
                          "tool": entry["tool"],
                          "args": entry["args"],
                          "observation": entry["observation"],
                      }
                  )
                  if self.budget is not None:
                      self.budget.spend(1)
                  start_step += 1
  ```

  In the live `finish` branch (currently returns immediately without journaling), journal it the same way the nudge/dispatch/skip branches already do:
  ```python
                  if call.name == "finish":
                      summary = str_arg(call.args, "summary")
                      finish_args = call.args  # assigned first: mypy strict does not
                                                # carry `call`'s non-None narrowing into
                                                # a nested def's own default-argument
                                                # expression (matches the existing
                                                # tool_name/tool_args pattern above)

                      def _finish_once(
                          _args: dict[str, object] = finish_args, _summary: str = summary
                      ) -> dict[str, object]:
                          return {"tool": "finish", "args": _args, "observation": _summary}

                      # Journaled like every other step (dispatch, nudge, skip)
                      # -- otherwise a resumed run_dir replays every step up to
                      # but not including this one, then falls through to a
                      # live loop iteration and asks the model AGAIN purely to
                      # hear it declare the same mission finished a second time.
                      if journal is not None:
                          journal.run_once(f"{agent_key}:{step}", _finish_once)
                      self._emit("finished", {"step": step})
                      return AgentResult("finished", step + 1, transcript, summary=summary)
  ```

  **`src/lalo/report/manifest.py`** — add the read-side counterpart to `write_report_manifest`, placed just before `verify_report_manifest`:
  ```python
  def read_report_manifest_paths(run_dir: Path) -> dict[str, Path] | None:
      """The per-format report path recorded in this run's own manifest, keyed
      the same way :func:`~lalo.report.writer.write_report`'s own return value
      is -- for a caller that wants to ADOPT an already-verified-intact prior
      report instead of regenerating it (see :func:`verify_report_manifest`,
      which should be checked first). ``None`` if no manifest exists yet.
      """
      manifest_path = run_dir / _MANIFEST_FILENAME
      if not manifest_path.exists():
          return None
      manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
      return {fmt: run_dir / entry["path"] for fmt, entry in manifest.get("artifacts", {}).items()}
  ```

  **`src/lalo/scan.py`** — import the new function alongside the existing two:
  ```python
  from .report.manifest import (
      read_report_manifest_paths,
      verify_report_manifest,
      write_report_manifest,
  )
  ```
  In `ScanRunner._run_inside`, snapshot the journal's key count right before `root_loop.run(...)`, then gate the confidence/review/report-write block on whether anything new was actually journaled this invocation:
  ```python
          journal_keys_before_root = len(journal.completed_keys())
          result = root_loop.run(self.config.mission, journal=journal, agent_key="root")
          coordinator.record_result(
              root_id,
              summary=result.summary,
              finding_ids=list(graph.nodes_of_kind(NodeKind.FINDING)),
              success=result.stop_reason in _TERMINAL_SUCCESS,
          )

          # Idempotent-resume fast path: journal.jsonl is strictly append-only
          # (see orchestrator/journal.py's own module docstring) and every
          # individual side-effecting step -- root or spawned child, dispatch,
          # nudge, skip, or a genuine finish -- gets its own journaled key (see
          # agent/loop.py's own finish-step journaling). If THIS invocation's
          # own root_loop.run() call above added not a single new key, nothing
          # anywhere in the whole spawn tree ran live this time -- the graph is
          # provably byte-identical to what it was before that call, which
          # already carries whatever confidence/review_verdict fields a PRIOR
          # invocation's own review pass persisted onto it. "cancelled" is
          # deliberately excluded even then: it's the one stop_reason that can
          # fire before any work is attempted for a reason specific to THIS
          # invocation (an operator cancel, or an unusually tight
          # max_duration_s tripping instantly) rather than a genuine verdict on
          # the mission -- adopting a stale report under a THIS-invocation-only
          # preemption would report a status the delivered report never
          # actually reached.
          no_new_work_this_invocation = (
              len(journal.completed_keys()) == journal_keys_before_root
              and result.stop_reason != "cancelled"
          )
          report_paths: dict[str, Path] | None = None
          if no_new_work_this_invocation and not verify_report_manifest(self.config.run_dir):
              report_paths = read_report_manifest_paths(self.config.run_dir)

          if report_paths is not None:
              # Adopt: recomputing confidence, re-running the adversarial-
              # review LLM call for every existing finding, and rewriting
              # every report format would spend real money to reach the exact
              # same conclusion a second time.
              self._emit(
                  "status",
                  {
                      "event": "report_adopted",
                      "report_paths": {fmt: str(path) for fmt, path in report_paths.items()},
                  },
              )
          else:
              for finding_id in graph.nodes_of_kind(NodeKind.FINDING):
                  confidence = compute_confidence(graph, finding_id)
                  review = run_adversarial_review(
                      graph,
                      finding_id,
                      confidence,
                      router,
                      second_opinion=self.config.enable_second_opinion_review,
                  )
                  node = graph.node(finding_id)
                  self._emit(
                      "finding",
                      {
                          "finding_id": finding_id,
                          "title": node.get("title", finding_id),
                          "severity": node.get("cvss_severity", "info"),
                          "confidence": confidence.score,
                          "verdict": review.verdict.value,
                      },
                  )

              for chain in graph.all_enabling_chains():
                  self._emit("chain", {"node_ids": chain.node_ids})
  ```
  ...and, further down, guard the existing `write_report`/`write_report_manifest` call the same way:
  ```python
          if report_paths is None:
              report_paths = write_report(
                  self.config.run_dir, graph, skills, status=status, usage=report_usage
              )
              write_report_manifest(self.config.run_dir, report_paths)
          graph.save(self.config.run_dir / "graph.json")
  ```
  (`status`/`report_usage` computation is left untouched and unconditional — both are pure/cheap, no LLM cost, and recomputing them keeps the emitted `scan_completed` event's status/usage-delta numbers honest for the adopt path too.)

  **`src/lalo/gui/app.py`** — add the import and compute `report_valid` in `_list_runs` (informational only, per the project's non-blocking-knob convention — this never hides, disables, or gates the Resume action):
  ```python
  from ..report.manifest import verify_report_manifest
  ```
  ```python
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
  ```

  **`src/lalo/gui/static/app.js`** — relabel (never hide/disable) the Resume button in `buildRunItem`:
  ```javascript
      if (!run.running) {
        const resumeBtn = item.querySelector(".run-resume-btn");
        resumeBtn.hidden = false;
        resumeBtn.dataset.runId = run.run_id;
        // Never hidden or disabled for a run with a valid report - resuming
        // one is a cheap, harmless no-op (the backend adopts the existing
        // report instead of redoing anything), and CLAUDE.md's own maximum-
        // agent-freedom stance rules out ever blocking the action outright.
        // This is purely informational: it stops the button from silently
        // implying more work remains when none does.
        if (run.report_valid) {
          resumeBtn.textContent = "Resume (already finished)";
          resumeBtn.title = "This run already has a verified final report - resuming will not redo it.";
        } else {
          resumeBtn.textContent = "Resume";
          resumeBtn.title = "";
        }
      }
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```
  uv run pytest tests/lalo/test_agent_loop.py tests/lalo/test_scan.py tests/lalo/test_report_manifest.py tests/lalo/test_gui_app.py -q
  ```
  Confirmed: `212 passed` (65 in `test_agent_loop.py`, 78 in `test_scan.py`, 7 in `test_report_manifest.py`, 65 in `test_gui_app.py` — includes the pre-existing suites, unaffected).

  Then confirm no regressions in typing/lint:
  ```
  uv run mypy
  uv run ruff check src/lalo tests/lalo
  uv run ruff format --check src/lalo tests/lalo
  ```
  Confirmed: `Success: no issues found in 104 source files`, `All checks passed!`, `182 files already formatted`.

- [ ] **Step 5: Commit**

  ```
  git add src/lalo/agent/loop.py src/lalo/report/manifest.py src/lalo/scan.py \
          src/lalo/gui/app.py src/lalo/gui/static/app.js \
          tests/lalo/test_agent_loop.py tests/lalo/test_scan.py \
          tests/lalo/test_report_manifest.py tests/lalo/test_gui_app.py
  git commit -m "fix(L4L0): resuming an already-finished scan is now a real no-op

  The agent loop's finish turn was never journaled, so resuming a cleanly-
  finished run_dir always made at least one fresh, wasted LLM call. Worse,
  the scan pipeline unconditionally recomputed confidence and re-ran the
  adversarial-review LLM call for every existing finding, then rewrote the
  report, on every root-loop return -- with no check for a run_dir that
  already has an intact, verified final report to adopt instead.

  Journal the finish step like every other step, so a resumed run whose
  journal replay reaches it short-circuits with no live model turn. In the
  scan pipeline, treat a resumed invocation that added zero new journal
  entries (append-only, so this proves nothing in the whole spawn tree ran
  live) as provably a no-op: verify the existing report_manifest.json is
  still byte-intact and adopt those report files outright instead of paying
  for a second review pass that reaches the identical conclusion. Also
  surface this on the run list (an informational report_valid flag) so the
  GUI's Resume button stops implying unfinished work on a run that already
  has a verified report -- the button itself stays exactly as clickable as
  before."
  ```

---

### Task 3: Wire safe_error_from_code into the real scan-failure path + fill missing error messages

**Files:**
- Modify: `src/lalo/core/redaction.py:86-97` (the `_ERROR_MESSAGES` table)
- Modify: `src/lalo/gui/app.py:118-123` (imports) and `src/lalo/gui/app.py:380-399` (the `_run_and_clear` scan-failure handler)
- Test: `tests/lalo/test_redaction.py`, `tests/lalo/test_gui_app.py`

**Interfaces:**
- Consumes: `safe_error_from_code(code: str) -> str` and the `_ERROR_MESSAGES` dict (existing, `core/redaction.py`); `LaloError.code: str` (present on every exception in `core/errors.py`, defaults to `"unknown"`); `AllProvidersFailedError.role`/`.failures` (existing, unchanged).
- Produces: `_ERROR_MESSAGES` now maps all 16 concrete `LaloError` subclass codes (plus the base `"unknown"`, 17 entries total) to a distinct, pre-approved message — `safe_error_from_code`'s signature is unchanged. `gui/app.py`'s scan-failure handler now emits `payload["error"] = safe_error_from_code(getattr(exc, "code", "unknown"))` instead of `str(exc)` — any later task rendering this payload (frontend, report export, another test) can rely on `payload["error"]` always being one of `_ERROR_MESSAGES`'s fixed values, never raw exception text.

- [ ] **Step 1: Write the failing tests**

  In `tests/lalo/test_redaction.py`, append (the module already imports `safe_error_from_code` at the top, no import change needed there):

  ```python
  def test_safe_error_from_code_covers_every_lalo_error_code() -> None:
      """Every concrete LaloError subclass's `code` needs its own entry in
      _ERROR_MESSAGES - an uncovered code silently falls back to the generic
      "unknown" message, and nothing else in the codebase would ever notice
      the table had drifted out of sync with core/errors.py."""
      from lalo.core import errors

      codes = {
          obj.code
          for obj in vars(errors).values()
          if isinstance(obj, type) and issubclass(obj, errors.LaloError)
      }
      assert codes == {
          "unknown",
          "config_error",
          "provider_error",
          "provider_refusal",
          "provider_unavailable",
          "all_providers_failed",
          "scope_error",
          "scope_violation",
          "target_unreachable",
          "container_error",
          "spawn_depth_exceeded",
          "login_failed",
          "session_not_mirrored",
          "jwt_malformed",
          "totp_secret_invalid",
          "resume_config_mismatch",
          "cost_limit_exceeded",
      }
      fallback = safe_error_from_code("definitely-not-a-real-code")
      for code in sorted(codes - {"unknown"}):
          assert safe_error_from_code(code) != fallback, (
              f"{code!r} has no dedicated entry in _ERROR_MESSAGES and silently "
              "falls back to the generic unknown-error message"
          )


  def test_safe_error_from_code_remediation_hints_name_the_real_opt_in_knobs() -> None:
      """target_unreachable/login_failed are the two LaloError codes that can
      actually reach a live scan_failed event today (via ScanConfig's
      fail_on_unreachable_targets/fail_on_broken_login, both opt-in and False
      by default) - lock the wording so a future rename of either field is
      caught here instead of silently going stale in the message text."""
      assert safe_error_from_code("target_unreachable") == (
          "The target failed its reachability preflight; confirm it is up, or turn "
          "off fail_on_unreachable_targets to proceed anyway."
      )
      assert safe_error_from_code("login_failed") == (
          "Login did not produce a usable session; check the identity's "
          "credentials, or turn off fail_on_broken_login to proceed anyway."
      )
  ```

  In `tests/lalo/test_gui_app.py`, change the import block:

  ```python
  import lalo.gui.app as app_module
  from lalo.core.errors import AllProvidersFailedError, LoginFailedError
  from lalo.core.redaction import safe_error_from_code
  from lalo.gui.app import build_app
  from lalo.gui.events import EventLog
  from lalo.scan import ScanConfig
  ```

  Add one assertion to the existing `test_a_failed_scan_with_all_providers_failed_surfaces_structured_per_provider_detail` (right after `assert payload is not None`):

  ```python
          assert payload["error"] == "All configured model providers failed."
  ```

  Then append two new tests:

  ```python
  def test_a_failed_scan_never_leaks_the_raw_exception_string(
      tmp_path: Path, monkeypatch: pytest.MonkeyPatch
  ) -> None:
      _FakeScanRunner.raises = RuntimeError("boom: connection to postgres://user:hunter2@db failed")
      monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
      try:
          client, event_log = _client(runs_dir=tmp_path)
          client.post("/scan", json={"mission": "find a bug", "targets": ["example.com"]})

          def _failed_event() -> dict | None:
              _cursor, events = event_log.snapshot()
              for e in events:
                  if e.category == "status" and e.payload.get("event") == "scan_failed":
                      return e.payload
              return None

          assert _wait_until(lambda: _failed_event() is not None)
          payload = _failed_event()
          assert payload is not None
          assert payload["error"] == "An unexpected error occurred."
          assert "hunter2" not in payload["error"]
      finally:
          _FakeScanRunner.raises = None


  def test_a_failed_scan_maps_a_lalo_error_through_its_own_code(
      tmp_path: Path, monkeypatch: pytest.MonkeyPatch
  ) -> None:
      _FakeScanRunner.raises = LoginFailedError(
          "login for identity admin failed: fired=True status=401 body=secret-debug-token-xyz"
      )
      monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
      try:
          client, event_log = _client(runs_dir=tmp_path)
          client.post("/scan", json={"mission": "find a bug", "targets": ["example.com"]})

          def _failed_event() -> dict | None:
              _cursor, events = event_log.snapshot()
              for e in events:
                  if e.category == "status" and e.payload.get("event") == "scan_failed":
                      return e.payload
              return None

          assert _wait_until(lambda: _failed_event() is not None)
          payload = _failed_event()
          assert payload is not None
          assert payload["error"] == safe_error_from_code("login_failed")
          assert "secret-debug-token-xyz" not in payload["error"]
      finally:
          _FakeScanRunner.raises = None
  ```

- [ ] **Step 2: Run the tests to verify they fail**

  ```
  uv run pytest tests/lalo/test_redaction.py tests/lalo/test_gui_app.py -q
  ```

  Expected failures (current code has `str(exc)` in `gui/app.py` and only 9 of 16 codes covered in `_ERROR_MESSAGES`):
  - `test_safe_error_from_code_covers_every_lalo_error_code`: `AssertionError: 'cost_limit_exceeded' has no dedicated entry in _ERROR_MESSAGES and silently falls back to the generic unknown-error message` (first missing code in sorted order — `config_error`/`container_error` already exist and sort before it).
  - `test_safe_error_from_code_remediation_hints_name_the_real_opt_in_knobs`: `AssertionError: assert 'An unexpected error occurred.' == 'The target failed its reachability preflight; confirm it is up, or turn off fail_on_unreachable_targets to proceed anyway.'`
  - `test_a_failed_scan_with_all_providers_failed_surfaces_structured_per_provider_detail` (new assertion): `AssertionError: assert 'anthropic: 401 unauthorized; openai: timeout' == 'All configured model providers failed.'`
  - `test_a_failed_scan_never_leaks_the_raw_exception_string`: `AssertionError: assert 'boom: connection to postgres://user:hunter2@db failed' == 'An unexpected error occurred.'`
  - `test_a_failed_scan_maps_a_lalo_error_through_its_own_code`: `AssertionError: assert 'secret-debug-token-xyz' not in "login for identity admin failed: fired=True status=401 body=secret-debug-token-xyz"`

- [ ] **Step 3: Write the minimal implementation**

  `src/lalo/core/redaction.py` — replace lines 86-97 (the current table has 9 real codes + `unknown`; add the 7 missing ones in the same order their classes appear in `core/errors.py`, each pairing a short statement with an operator-actionable next step, same tone/length family as the existing entries):

  ```python
  _ERROR_MESSAGES: dict[str, str] = {
      "config_error": "Configuration is invalid or incomplete.",
      "provider_error": "A model provider call failed.",
      "provider_refusal": "The model provider declined this request.",
      "provider_unavailable": "The model provider is currently unavailable.",
      "all_providers_failed": "All configured model providers failed.",
      "scope_error": "A scope check failed.",
      "scope_violation": "Target is outside the declared engagement scope.",
      "target_unreachable": (
          "The target failed its reachability preflight; confirm it is up, or turn "
          "off fail_on_unreachable_targets to proceed anyway."
      ),
      "container_error": "The runtime container failed.",
      "spawn_depth_exceeded": (
          "A spawned agent hit the depth ceiling; raise spawn_max_depth if deeper "
          "nesting is expected for this mission."
      ),
      "login_failed": (
          "Login did not produce a usable session; check the identity's "
          "credentials, or turn off fail_on_broken_login to proceed anyway."
      ),
      "session_not_mirrored": (
          "No graph node exists for this session; re-run login for this identity."
      ),
      "jwt_malformed": "The JWT string was not well-formed; capture a fresh token from the target.",
      "totp_secret_invalid": (
          "The TOTP secret is not valid base32; check the seed configured for this identity."
      ),
      "resume_config_mismatch": "This scan's saved state doesn't match the current config.",
      "cost_limit_exceeded": (
          "The run's spend crossed the configured cost ceiling; raise or clear the limit to continue."
      ),
      "unknown": "An unexpected error occurred.",
  }
  ```

  `src/lalo/gui/app.py` — add one import (line 123, alphabetically after `..core.providers`, before `..intake`):

  ```python
  from ..core.providers import build_router, verify_router
  from ..core.redaction import safe_error_from_code
  from ..intake import parse_scan_intent
  ```

  Then replace the handler body (currently lines 380-399):

  ```python
          def _run_and_clear() -> None:
              try:
                  runner.run()
              except Exception as exc:  # noqa: BLE001 - a background thread's own
                  # exception has no caller to propagate to; the dashboard is the
                  # only place this failure can surface, so it must be a status
                  # event, never a silently dead thread.
                  _log.exception("scan failed")
                  # str(exc) put whatever the raising code chose to interpolate -
                  # a provider's raw error body, a stack-trace fragment, a
                  # credential caught mid-request - straight onto the dashboard,
                  # which is exactly what safe_error_from_code's own docstring
                  # says it exists to prevent. The full exception is still on
                  # disk via _log.exception above; only the GUI-facing payload
                  # is sanitized. A plain (non-LaloError) exception has no
                  # `.code` attribute at all, hence the getattr fallback to the
                  # same "unknown" bucket every unmapped code already resolves to.
                  code = getattr(exc, "code", "unknown")
                  payload: dict[str, object] = {
                      "event": "scan_failed",
                      "error": safe_error_from_code(code),
                  }
                  # AllProvidersFailedError already carries its per-provider
                  # detail as real attributes (see core/errors.py) - the fixed
                  # message above alone would flatten them into one generic
                  # line, so surface role/failures as their own fields too for
                  # a structured, per-provider rendering in the GUI.
                  if isinstance(exc, AllProvidersFailedError):
                      payload["role"] = exc.role
                      payload["failures"] = [
                          {"provider": name, "reason": reason} for name, reason in exc.failures
                      ]
                  this_event_log.append("status", payload)
  ```

- [ ] **Step 4: Run the tests to verify they pass**

  ```
  uv run pytest tests/lalo/test_redaction.py tests/lalo/test_gui_app.py -q
  ```

  All tests in both files pass, including the pre-existing `test_a_failed_scan_with_a_plain_error_has_no_role_or_failures_fields` and `test_a_failed_scan_emits_a_status_event_instead_of_dying_silently` (both untouched, still green — neither asserted on the raw `error` string).

- [ ] **Step 5: Commit**

  ```
  git add src/lalo/core/redaction.py src/lalo/gui/app.py tests/lalo/test_redaction.py tests/lalo/test_gui_app.py
  git commit -m "$(cat <<'EOF'
  fix(gui): map scan_failed's error through the fixed message table

  The dashboard's scan-failure handler built its payload from str(exc)
  directly, bypassing the one reason the redaction module's error-code
  mapping exists: a raw exception string can carry a leaked credential
  or internal detail straight onto the page. Route it through
  safe_error_from_code(getattr(exc, "code", "unknown")) instead - the
  full exception still reaches the server log via the existing
  _log.exception call, only the GUI-facing text is sanitized.

  Also fills in the 7 _ERROR_MESSAGES entries that had no message at
  all (target_unreachable, spawn_depth_exceeded, login_failed,
  session_not_mirrored, jwt_malformed, totp_secret_invalid,
  cost_limit_exceeded), each naming a short operator-actionable next
  step, so every LaloError code now resolves to its own fixed message
  instead of silently falling back to the generic unknown-error text.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 4: Add host.docker.internal reachability + forward operator /etc/hosts entries

**Files:**
- Create: none — this is additive to two existing files, no new module needed
- Modify: `src/lalo/runtime/container.py:60-72` (imports), `:74-88` (module constants), `:138-181` (`RuntimeConfig` dataclass + docstring), `:184` (new module-level functions inserted immediately before `class RuntimeContainer`), `:205-241` (`_run_args()`)
- Modify: `docs/OPERATING.md:106-119` ("Pointing a scan at a target on your own machine")
- Test: `tests/lalo/test_runtime.py:12` (new import) and appended after line 145 (3 new test functions)

**Interfaces:**
- Consumes: `_in_metadata_range(ip: str) -> bool` from `lalo.execution.scope` (existing, unchanged — already imported the same way by `lalo/integrations/mcp_client.py:92` and `lalo/browser/session.py:89`, so this isn't a new cross-package dependency direction); existing `RuntimeConfig`/`RuntimeContainer`/`docker_available` public API.
- Produces: `RuntimeConfig.forward_etc_hosts: bool = True` (new field, default on); `_parse_etc_hosts_add_host_args(text: str) -> list[str]` (new pure function in `lalo.runtime.container`, private — text-in/args-out so it's unit-testable without touching the filesystem); `_operator_add_host_args() -> list[str]` (new private thin wrapper reading `/etc/hosts`); `RuntimeContainer._run_args()` now always includes `["--add-host", "host.docker.internal:host-gateway"]`, plus (when `forward_etc_hosts` is `True`) one `--add-host` pair per qualifying operator `/etc/hosts` entry.

- [ ] **Step 1: Write the failing test**

  Add one import and three test functions to the existing `tests/lalo/test_runtime.py` (it already tests `_run_args()` shape directly for other flags, e.g. `test_vpn_is_off_by_default`/`test_enable_vpn_grants_net_admin_and_the_tun_device` — same pattern):

  Add after the existing import block (line 12):
  ```python
  from lalo.runtime.container import _parse_etc_hosts_add_host_args
  ```

  Append at the end of the file (after `test_enable_vpn_grants_a_working_tun_device_and_net_admin_on_a_live_daemon`, line 145):
  ```python
  def test_add_host_host_docker_internal_present() -> None:
      # Native Docker Engine 20.10+ feature on Linux too, not Docker-Desktop-only
      # -- always wired up, never gated behind a toggle.
      args = RuntimeContainer(RuntimeConfig(image=_IMAGE))._run_args()
      idx = args.index("host.docker.internal:host-gateway")
      assert args[idx - 1] == "--add-host"


  def test_parse_etc_hosts_forwards_custom_entries_and_rewrites_loopback() -> None:
      sample = (
          "127.0.0.1 localhost\n"
          "127.0.1.1 kali\n"
          "::1 localhost ip6-localhost ip6-loopback\n"
          "169.254.169.254 metadata.internal\n"
          "fe80::1 somelink.local\n"
          "10.129.15.187 bedside.htb research.bedside.htb bedside\n"
          "# a comment 10.0.0.1 commented.out\n"
          "\n"
      )
      args = _parse_etc_hosts_add_host_args(sample)
      assert "kali:host-gateway" in args
      assert "bedside.htb:10.129.15.187" in args
      assert "research.bedside.htb:10.129.15.187" in args
      assert "bedside:10.129.15.187" in args
      assert not any("localhost" in a for a in args)
      assert not any("metadata.internal" in a for a in args)
      assert not any("somelink.local" in a for a in args)
      assert not any("commented.out" in a for a in args)


  def test_forward_etc_hosts_defaults_to_on_and_can_be_disabled() -> None:
      assert RuntimeConfig(image=_IMAGE).forward_etc_hosts is True
      args = RuntimeContainer(RuntimeConfig(image=_IMAGE, forward_etc_hosts=False))._run_args()
      add_host_values = [args[i + 1] for i, a in enumerate(args) if a == "--add-host"]
      assert add_host_values == ["host.docker.internal:host-gateway"]
  ```

  These assertions were hand-checked against real sample data (`127.0.1.1 kali` mirrors this machine's actual `/etc/hosts`): `127.0.0.1`/`::1`'s hostnames are all in the standard-alias set so nothing is emitted for them; `127.0.1.1 kali` is loopback-but-not-standard so it rewrites to `kali:host-gateway`; `169.254.169.254` and `fe80::1` fall inside `lalo.execution.scope`'s existing metadata/link-local ranges so both are skipped; the commented-out line is stripped by the `#` split before it ever reaches the hostname filter; the HTB-style line has no standard aliases so all three of its hostnames pass through with the literal IP.

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_runtime.py -v
  ```

  Expected failure: a collection error for the whole module, since `_parse_etc_hosts_add_host_args` doesn't exist yet in `lalo.runtime.container`:
  ```
  ERROR tests/lalo/test_runtime.py - ImportError: cannot import name '_parse_etc_hosts_add_host_args' from 'lalo.runtime.container'
  ```
  (Docker is reachable in this environment, so this is a real collection-time failure, not the module's `skipif(not docker_available())` guard kicking in.)

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/runtime/container.py`, extend the import block (lines 60-72):
  ```python
  from __future__ import annotations

  import ipaddress
  import shutil
  import subprocess
  import threading
  import uuid
  from collections.abc import Callable
  from dataclasses import dataclass
  from pathlib import Path

  from ..core.errors import ContainerError
  from ..core.logging import get_logger
  from ..execution.scope import _in_metadata_range
  ```

  Add a new constant near `_BASELINE_CAPS` (after line 88):
  ```python
  # Hostnames every stock /etc/hosts ships with -- never something an operator
  # added for an engagement, so never forwarded into the sandbox.
  _STANDARD_HOSTNAMES: frozenset[str] = frozenset(
      {
          "localhost",
          "ip6-localhost",
          "ip6-loopback",
          "ip6-localnet",
          "ip6-mcastprefix",
          "ip6-allnodes",
          "ip6-allrouters",
          "broadcasthost",
      }
  )
  ```

  Add `forward_etc_hosts` to the `RuntimeConfig` dataclass fields (after `enable_vpn: bool = False`, line 170):
  ```python
      enable_vpn: bool = False
      forward_etc_hosts: bool = True
      log_max_size: str = "10m"
  ```
  and a paragraph to its docstring, inserted before the existing "No restart policy is set on purpose" sentence:
  ```
      ``forward_etc_hosts`` (on by default) mirrors the operator's own custom
      ``/etc/hosts`` entries into the sandbox via ``--add-host``, alongside the
      unconditional ``host.docker.internal:host-gateway`` mapping every run's
      args always carry: a lab target the operator can already reach by hostname
      on their own machine shouldn't need a manual gateway-IP lookup to reach
      from inside the container too. Purely additive reachability, never a
      restriction, so it defaults on; set ``False`` only if a specific entry
      ever gets in the way of a scan.
  ```

  Add two new module-level functions immediately before `class RuntimeContainer:`:
  ```python
  def _parse_etc_hosts_add_host_args(text: str) -> list[str]:
      """Turn the operator's own custom ``/etc/hosts`` lines into Docker
      ``--add-host`` args, so a target already reachable by hostname on the
      operator's own machine (a lab DNS entry, a local dev vhost, their own
      machine's hostname) is reachable by that same hostname from inside the
      sandbox too -- no manual gateway-IP lookup required.

      Pure text-in, args-out so it's testable without touching a real
      filesystem. Skips comments, blank lines, and the standard localhost/
      multicast aliases every ``/etc/hosts`` ships with (:data:`_STANDARD_HOSTNAMES`).
      A loopback entry (the operator's own machine -- e.g. the installer-
      generated ``127.0.1.1 <hostname>`` line) is rewritten to Docker's
      ``host-gateway`` sentinel rather than forwarded literally, since
      ``127.0.0.1`` inside the container is the container itself, not the
      host. Anything in a cloud-metadata or link-local range is skipped
      outright, reusing the same check :mod:`lalo.execution.scope` already
      uses to deny those as direct firer targets.
      """
      args: list[str] = []
      for raw_line in text.splitlines():
          line = raw_line.split("#", 1)[0].strip()
          if not line:
              continue
          fields = line.split()
          if len(fields) < 2:
              continue
          ip_text, hostnames = fields[0], fields[1:]
          try:
              addr = ipaddress.ip_address(ip_text)
          except ValueError:
              continue
          if _in_metadata_range(ip_text):
              continue
          target = "host-gateway" if addr.is_loopback else ip_text
          for hostname in hostnames:
              if hostname.lower() in _STANDARD_HOSTNAMES:
                  continue
              args += ["--add-host", f"{hostname}:{target}"]
      return args


  def _operator_add_host_args() -> list[str]:
      """Best-effort: an unreadable or malformed ``/etc/hosts`` yields no extra
      flags rather than failing the run -- this is a convenience, never a
      requirement for a scan to start."""
      try:
          text = Path("/etc/hosts").read_text()
      except (OSError, UnicodeDecodeError):
          return []
      return _parse_etc_hosts_add_host_args(text)
  ```

  In `_run_args()`, insert right after the existing `enable_vpn` block and before the "Deliberately NO -v/--mount" comment:
  ```python
          if self.config.enable_vpn:
              args += ["--cap-add", "NET_ADMIN", "--device", "/dev/net/tun:/dev/net/tun"]
          # host.docker.internal:host-gateway is a native Docker Engine 20.10+
          # feature on Linux (not Docker-Desktop-only, despite the old docs claim
          # this replaces) -- always wired up so the agent's free shell and
          # http/browser tools can reach a service the operator runs on their own
          # machine without a manual `docker network inspect bridge` lookup first.
          args += ["--add-host", "host.docker.internal:host-gateway"]
          if self.config.forward_etc_hosts:
              args += _operator_add_host_args()
          # Deliberately NO -v/--mount (no host filesystem) and NO docker socket —
  ```

  In `docs/OPERATING.md`, replace the "Pointing a scan at a target on your own machine" section — the current text wrongly claims `host.docker.internal` is Docker-Desktop-only and tells operators to manually run `docker network inspect bridge`:
  ```markdown
  ## Pointing a scan at a target on your own machine

  The agent's free shell and `http`/`browser` tools run *inside* the
  disposable runtime container (Docker's default `bridge` network, not host
  networking), so `localhost`/`127.0.0.1` inside that container is the
  container itself, not your machine. Every sandbox is started with
  `--add-host host.docker.internal:host-gateway`, so `host.docker.internal`
  reaches your machine from inside the container — this is a native Docker
  Engine 20.10+ feature on Linux, not a Docker-Desktop-only convenience, so
  it's wired up unconditionally rather than left as a manual lookup. Point a
  target at `host.docker.internal` (a dev server, a lab target container
  you've brought up for eval purposes) instead of `localhost`.

  Any custom entry already in your own `/etc/hosts` (a lab DNS name, your
  machine's own hostname) is also forwarded into the sandbox automatically as
  its own `--add-host`, so a target you can already reach by name on your own
  machine is reachable by that same name from inside the container too — no
  extra step needed. Set `forward_etc_hosts=False` on `RuntimeConfig` to turn
  this off if a specific entry ever causes a problem.
  ```

  No test is written for the doc change itself — it's non-executable prose describing behavior the code tests above already cover.

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_runtime.py -v
  ```

  Expected: no collection error, and every test in the file — including the three new ones — reports `PASSED` (or the whole module uniformly `SKIPPED` if Docker becomes unreachable, per the pre-existing module-level `skipif(not docker_available())` guard).

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/runtime/container.py docs/OPERATING.md tests/lalo/test_runtime.py
  git commit -m "$(cat <<'EOF'
  feat(L4L0): reach host.docker.internal + forward operator /etc/hosts entries

  Every sandbox now starts with --add-host host.docker.internal:host-gateway
  -- a native Docker Engine 20.10+ feature on Linux, not the Docker-Desktop-
  only convenience OPERATING.md previously (incorrectly) claimed it was --
  so the agent's free shell and http/browser tools can reach a service the
  operator runs on their own machine without a manual docker network
  inspect bridge gateway-IP lookup first. RuntimeConfig gains a default-on
  forward_etc_hosts toggle that also mirrors the operator's own custom
  /etc/hosts entries (a lab DNS name, a local dev vhost) into the sandbox
  as their own --add-host flags, rewriting a loopback target to
  host-gateway and skipping cloud-metadata/link-local ranges via the same
  check lalo.execution.scope already uses for that. Purely additive
  reachability -- nothing existing is restricted, and the toggle exists
  only so one forwarded entry can be turned off if it ever gets in the
  way, never as a default-off gate. Updates OPERATING.md to match.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 5: Thread engagement target/scope and model/provider into every report format

**Files:**
- Modify: `src/lalo/report/collect.py:173-176` (new `ReportMetadata` dataclass, inserted between the existing `ReportUsage` and `ChainRecord` dataclasses)
- Modify: `src/lalo/report/writer.py:63-98,129-169` (import + `write_report()` signature/body)
- Modify: `src/lalo/report/markdown.py:40,143-186` (import + `render_report_md()` signature/Executive Summary block)
- Modify: `src/lalo/report/html.py:33,137-179` (import + `render_report_html()` signature/Executive Summary block)
- Modify: `src/lalo/scan.py:140,182,968,977-985,1261-1279` (import `Settings`/`ReportMetadata`, thread `settings` into `_run_inside`, build the real `ReportMetadata` at the `write_report()` call site)
- Test: `tests/lalo/test_report_markdown.py`
- Test: `tests/lalo/test_report_html.py`
- Test: `tests/lalo/test_report_writer.py`
- Test: `tests/lalo/test_scan.py`

**Interfaces:**
- Consumes: `Engagement.describe() -> str` (`src/lalo/execution/target.py:180`, already computed once per scan for the agent system prompt as `engagement_scope=engagement.describe()` at `src/lalo/scan.py:1017`); `Settings.resolved: tuple[ResolvedProvider, ...]` where `ResolvedProvider` has `.id: str`/`.model: str` (`src/lalo/core/config.py:132-138,184-189`), populated by `load_settings()` at `src/lalo/scan.py:886` and guaranteed non-empty by the precondition check at `:887-891`; the current `write_report(run_dir, graph, skills, *, overrides=None, generated_at=None, status=None, usage: ReportUsage | None = None) -> dict[str, Path]` signature (`src/lalo/report/writer.py:89-98`).
- Produces: `ReportMetadata` — a new frozen dataclass in `lalo.report.collect` with `engagement_scope: str` and `model_provider: str` (both required, no defaults — both are always real values by the time `write_report()` is ever called). `write_report(..., metadata: ReportMetadata | None = None)`, `render_report_md(..., metadata: ReportMetadata | None = None)`, `render_report_html(..., metadata: ReportMetadata | None = None)`. The JSON report gains a top-level `"engagement"` key: `asdict(metadata)` or `None`.

**Scope/design correction found while reading the real code** (see notes to assembler): `ScanConfig` and `AgentConfig` (`src/lalo/scan.py:198-296`, `src/lalo/agent/loop.py:329-357`) have **no** model/provider field at all — model resolution is multi-provider/failover (`ModelRouter`, `src/lalo/core/model_router.py:91-133`) resolved once per scan via `load_settings()`/`Settings`/`ResolvedProvider` in `src/lalo/core/config.py`. And `ReportUsage` is the wrong place for target/scope/model: it is only ever populated when the operator opts into `usage_path` tracking (`ScanConfig.usage_path: Path | None = None`, off by default — see its own docstring, "None (the default) keeps a caller hermetic"), so bundling engagement/model into it would silently hide them from the Executive Summary on most real scans. `ReportMetadata` is therefore a genuine sibling, always built, independent of usage tracking.

- [ ] **Step 1: Write the failing tests**

  In `tests/lalo/test_report_markdown.py` (add `ReportMetadata` to the existing `from lalo.report.collect import (...)` block at the top of the file):

  ```python
  def test_render_report_md_shows_engagement_scope_and_model_in_the_executive_summary() -> None:
      coverage = CoverageSummary(assessed=[], not_assessed=[])
      summary = ExecutiveSummary(
          total_findings=1,
          by_severity={"high": 1},
          by_vuln_class={"sql-injection": 1},
          highest_severity="high",
      )
      metadata = ReportMetadata(
          engagement_scope="- example.com\n- *.internal.example.com",
          model_provider="anthropic:claude-sonnet-5",
      )
      rendered = render_report_md([], coverage, summary=summary, metadata=metadata)
      assert "## Executive Summary" in rendered
      assert "**Model / Provider:** anthropic:claude-sonnet-5" in rendered
      assert "**Target / Scope:**" in rendered
      assert "- example.com\n- *.internal.example.com" in rendered


  def test_render_report_md_with_no_metadata_has_no_scope_or_model_lines() -> None:
      coverage = CoverageSummary(assessed=[], not_assessed=[])
      summary = ExecutiveSummary(
          total_findings=0, by_severity={}, by_vuln_class={}, highest_severity=None
      )
      rendered = render_report_md([], coverage, summary=summary)
      assert "Model / Provider" not in rendered
      assert "Target / Scope" not in rendered
  ```

  In `tests/lalo/test_report_html.py` (add `ReportMetadata` to the existing `from lalo.report.collect import (...)` block):

  ```python
  def test_render_report_html_shows_engagement_scope_and_model_in_the_executive_summary() -> None:
      coverage = CoverageSummary(assessed=[], not_assessed=[])
      summary = ExecutiveSummary(
          total_findings=1,
          by_severity={"high": 1},
          by_vuln_class={"sql-injection": 1},
          highest_severity="high",
      )
      metadata = ReportMetadata(
          engagement_scope="- example.com", model_provider="anthropic:claude-sonnet-5"
      )
      rendered = render_report_html([], coverage, summary=summary, metadata=metadata)
      assert "<h2>Executive Summary</h2>" in rendered
      assert "<strong>Model / Provider:</strong> anthropic:claude-sonnet-5" in rendered
      assert "<strong>Target / Scope:</strong>" in rendered
      assert "<pre>- example.com</pre>" in rendered


  def test_render_report_html_with_no_metadata_has_no_scope_or_model_lines() -> None:
      coverage = CoverageSummary(assessed=[], not_assessed=[])
      summary = ExecutiveSummary(
          total_findings=0, by_severity={}, by_vuln_class={}, highest_severity=None
      )
      rendered = render_report_html([], coverage, summary=summary)
      assert "Model / Provider" not in rendered
      assert "Target / Scope" not in rendered
  ```

  In `tests/lalo/test_report_writer.py` (add `ReportMetadata` to the existing `from lalo.report.collect import ReportUsage` line):

  ```python
  def test_write_report_threads_engagement_metadata_into_json_and_markdown(tmp_path: Path) -> None:
      """Closes the sibling gap to ReportUsage: an operator reading a report
      days later, or handing it to someone who never saw the launch command,
      previously had no way to tell which engagement/target or which model
      produced it - write_report() never threaded either through."""
      graph, _ = _graph_with_finding()
      metadata = ReportMetadata(
          engagement_scope="- https://x.example.com", model_provider="anthropic:claude-sonnet-5"
      )
      paths = write_report(tmp_path, graph, _SKILLS, metadata=metadata)

      doc = json.loads(paths["json"].read_text(encoding="utf-8"))
      assert doc["engagement"] == {
          "engagement_scope": "- https://x.example.com",
          "model_provider": "anthropic:claude-sonnet-5",
      }
      markdown = paths["markdown"].read_text(encoding="utf-8")
      assert "**Model / Provider:** anthropic:claude-sonnet-5" in markdown
      assert "- https://x.example.com" in markdown


  def test_write_report_with_no_metadata_omits_it_from_json(tmp_path: Path) -> None:
      graph, _ = _graph_with_finding()
      paths = write_report(tmp_path, graph, _SKILLS)
      doc = json.loads(paths["json"].read_text(encoding="utf-8"))
      assert doc["engagement"] is None
  ```

  In `tests/lalo/test_scan.py` (uses only fixtures/imports already present in the file — `scan_module`, `ModelRouter`, `_FakeContainer`, `_ScriptedProvider`, `_respond`, `ScanConfig`, `ScanRunner`, `json`, `Path`, `pytest` — no new imports needed):

  ```python
  def test_scan_runner_threads_real_engagement_scope_and_model_into_the_report(
      tmp_path: Path, monkeypatch: pytest.MonkeyPatch
  ) -> None:
      """End-to-end: the real write_report() call site in _run_inside must
      build ReportMetadata from the SAME engagement.describe() already
      computed for the agent prompt, and from the resolved provider chain -
      never a second, independently-guessed value. Deliberately does NOT set
      usage_path, to prove engagement/model metadata appears even when the
      operator never opted into usage tracking (unlike ReportUsage, which is
      absent here on purpose)."""
      monkeypatch.setattr(scan_module, "docker_available", lambda: True)
      monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
      router = ModelRouter(
          providers={"fake": _ScriptedProvider(_respond)},
          routes={"reasoning": ("fake",), "review": ("fake",)},
          default_route=("fake",),
      )
      monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

      config = ScanConfig(
          mission="find a bug", target_specs=["example.com"], run_dir=tmp_path / "run"
      )
      outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

      report_json = json.loads(outcome.report_paths["json"].read_text())
      assert report_json["engagement"] == {
          "engagement_scope": "- example.com",
          "model_provider": "anthropic:claude-sonnet-5",
      }
      markdown = outcome.report_paths["markdown"].read_text()
      assert "**Model / Provider:** anthropic:claude-sonnet-5" in markdown
      assert "- example.com" in markdown
  ```

  (`env={"ANTHROPIC_API_KEY": "sk-test"}` with no `ANTHROPIC_MODEL` set resolves, via the real `load_settings()`, to `ResolvedProvider(id="anthropic", model="claude-sonnet-5", ...)` per the curated table's `default_model` in `src/lalo/core/config.py:87-94` — confirmed by reading that table directly, not assumed.)

- [ ] **Step 2: Run the tests to verify they fail**

  ```
  uv run pytest tests/lalo/test_report_markdown.py -k engagement_scope_and_model -v
  uv run pytest tests/lalo/test_report_html.py -k engagement_scope_and_model -v
  uv run pytest tests/lalo/test_report_writer.py -k engagement_metadata -v
  uv run pytest tests/lalo/test_scan.py -k threads_real_engagement_scope_and_model -v
  ```

  Expected failure (all four): `TypeError: render_report_md() got an unexpected keyword argument 'metadata'` (and the same for `render_report_html`/`write_report`); the `test_scan.py` one fails as `ImportError`/`NameError` at collection once `ReportMetadata` doesn't exist yet, or `AssertionError: assert None == {...}` on `report_json["engagement"]` (`KeyError` if the key is entirely absent) once the dataclass exists but nothing threads it through yet.

- [ ] **Step 3: Write the minimal implementation**

  `src/lalo/report/collect.py` — insert after `ReportUsage` (line 173), before `ChainRecord` (line 176):

  ```python
  @dataclass(frozen=True)
  class ReportMetadata:
      """Which engagement and which model actually produced this report.

      Unlike :class:`ReportUsage` (populated only when the operator opts into
      usage_path tracking - off by default), both fields here are always real
      and available at the one real write_report() call site: the engagement
      scope is already computed for the agent system prompt
      (``Engagement.describe()``, see scan.py's own render_prompt call), and
      the resolved provider chain is already a precondition of starting the
      scan at all (load_settings() is checked non-empty before anything else
      runs). Kept as its own dataclass rather than folded into ReportUsage -
      target/scope has nothing to do with LLM token spend, and bundling them
      would silently hide the engagement/model info on every scan that
      doesn't opt into usage tracking, which is most of them.
      """

      engagement_scope: str
      model_provider: str
  ```

  `src/lalo/report/writer.py`:

  ```python
  from .collect import (
      ReportMetadata,
      ReportUsage,
      build_chain_records,
      build_executive_summary,
      collect_findings,
      sort_findings,
  )
  ```

  ```python
  def write_report(
      run_dir: Path,
      graph: ReachabilityGraph,
      skills: list[Skill],
      *,
      overrides: list[SeverityOverride] | None = None,
      generated_at: str | None = None,
      status: RunStatus | None = None,
      usage: ReportUsage | None = None,
      metadata: ReportMetadata | None = None,
  ) -> dict[str, Path]:
  ```

  (docstring gains one paragraph: ```"``metadata`` (optional) surfaces which engagement/target and which model produced the run - always available at the real scan.py call site, independent of whether usage_path tracking is configured."```)

  Both render calls gain `metadata=metadata`:

  ```python
      markdown = render_report_md(
          records, coverage, chains=chains, generated_at=generated_at,
          status=status_value, summary=summary, usage=usage, metadata=metadata,
      )
  ```
  ```python
      html = render_report_html(
          records, coverage, chains=chains, generated_at=generated_at,
          status=status_value, summary=summary, usage=usage, metadata=metadata,
      )
  ```

  `json_document` gains a sibling key to `"usage"`:

  ```python
      json_document = {
          "generated_at": generated_at,
          "status": status_value,
          "executive_summary": asdict(summary),
          "findings": [asdict(record) for record in records],
          "coverage": asdict(coverage),
          "chains": [asdict(chain) for chain in chains],
          "usage": asdict(usage) if usage is not None else None,
          "engagement": asdict(metadata) if metadata is not None else None,
      }
  ```

  `src/lalo/report/markdown.py` — import gains `ReportMetadata`:

  ```python
  from .collect import ChainRecord, ExecutiveSummary, FindingRecord, ReportMetadata, ReportUsage
  ```

  Signature gains `metadata`, and the Executive Summary block prints it:

  ```python
  def render_report_md(
      records: list[FindingRecord],
      coverage: CoverageSummary,
      *,
      chains: Sequence[ChainRecord] = (),
      generated_at: str | None = None,
      status: str | None = None,
      summary: ExecutiveSummary | None = None,
      usage: ReportUsage | None = None,
      metadata: ReportMetadata | None = None,
  ) -> str:
  ```

  ```python
      if summary is not None:
          lines.append("## Executive Summary\n")
          ...
          if summary.highest_severity:
              lines.append(f"**Highest severity:** {summary.highest_severity.upper()}")
          if metadata is not None:
              lines.append(f"**Model / Provider:** {metadata.model_provider}")
              lines.append("**Target / Scope:**")
              lines.append(metadata.engagement_scope)
          lines.append("")
  ```

  `src/lalo/report/html.py` — import gains `ReportMetadata`:

  ```python
  from .collect import ChainRecord, ExecutiveSummary, FindingRecord, ReportMetadata, ReportUsage
  ```

  Signature gains `metadata`, and the Executive Summary block prints it (using `<pre>` for the multi-line scope text, the same convention `render_finding_html` already uses for multi-line evidence blobs):

  ```python
  def render_report_html(
      records: list[FindingRecord],
      coverage: CoverageSummary,
      *,
      chains: Sequence[ChainRecord] = (),
      generated_at: str | None = None,
      status: str | None = None,
      summary: ExecutiveSummary | None = None,
      usage: ReportUsage | None = None,
      metadata: ReportMetadata | None = None,
  ) -> str:
  ```

  ```python
      if summary is not None:
          parts.append("<h2>Executive Summary</h2>")
          ...
          if summary.highest_severity:
              parts.append(
                  f"<p><strong>Highest severity:</strong> {_e(summary.highest_severity.upper())}</p>"
              )
          if metadata is not None:
              parts.append(
                  f"<p><strong>Model / Provider:</strong> {_e(metadata.model_provider)}</p>"
              )
              parts.append("<p><strong>Target / Scope:</strong></p>")
              parts.append(f"<pre>{_e(metadata.engagement_scope)}</pre>")
  ```

  `src/lalo/report/pdf.py` and `src/lalo/report/docx.py`: **no change** — both render from the same already-escaped HTML string `render_report_html` produces (`render_report_pdf(html)`/`render_report_docx(html)`), so the Executive Summary metadata added above reaches PDF/DOCX automatically, matching this module's existing "assemble once, write many formats" contract stated in `writer.py`'s own module docstring.

  `src/lalo/report/sarif.py`: **no change** — confirmed by reading the whole module: SARIF here has no Executive Summary/narrative-summary equivalent at all (it's rules+results+`invocations[].executionSuccessful` only; even the existing `ExecutiveSummary` roll-up is never threaded into it today). Adding one would be new, unrequested SARIF surface, not "the equivalent section this task already targets."

  `src/lalo/scan.py`:

  ```python
  from .core.config import Settings, load_settings
  ```
  ```python
  from .report.collect import ReportMetadata, ReportUsage
  ```

  `_run_inside` signature and its one call site both gain `settings`:

  ```python
      def _run_inside(
          self,
          router: ModelRouter,
          settings: Settings,
          scope: ScopeGuard,
          engagement: Engagement,
          container: RuntimeContainer,
          oast: OASTServer,
          browser: BrowserSession,
      ) -> ScanOutcome:
  ```

  ```python
                  return self._run_inside(
                      router, settings, scope, engagement, container, oast, browser
                  )
  ```

  And immediately before the `write_report(...)` call inside `_run_inside`:

  ```python
          # Always built (unlike report_usage above, gated on the operator
          # opting into usage_path tracking) - the engagement scope is already
          # computed for the agent system prompt (engagement.describe(), see
          # the render_prompt call above), and settings.resolved is already a
          # precondition of starting the scan at all (checked non-empty in
          # run()), so both are always real values by the time a report is
          # ever written.
          metadata = ReportMetadata(
              engagement_scope=engagement.describe(),
              model_provider=", ".join(f"{p.id}:{p.model}" for p in settings.resolved),
          )
          report_paths = write_report(
              self.config.run_dir,
              graph,
              skills,
              status=status,
              usage=report_usage,
              metadata=metadata,
          )
      ```

- [ ] **Step 4: Run the tests to verify they pass**

  ```
  uv run pytest tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py tests/lalo/test_report_writer.py -v
  uv run pytest tests/lalo/test_scan.py -k engagement_scope_and_model -v
  ```

  All listed tests green, including the two "with no metadata" regression tests confirming the feature stays fully additive (no output changes for an existing caller that never passes `metadata`).

- [ ] **Step 5: Commit**

  ```
  git add src/lalo/report/collect.py src/lalo/report/writer.py src/lalo/report/markdown.py src/lalo/report/html.py src/lalo/scan.py tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py tests/lalo/test_report_writer.py tests/lalo/test_scan.py
  git commit -m "$(cat <<'EOF'
  feat(report): surface engagement scope and resolved model in every report's executive summary

  Reports previously carried no record of which target scope or which
  model/provider actually produced them once the scan finished - an
  operator reading one later, or forwarding it to someone who never saw
  the launch command, had no way to tell. ReportMetadata threads the same
  engagement.describe() already computed for the agent prompt, plus the
  resolved provider chain, into markdown/html/json (PDF/DOCX inherit it
  automatically via the shared HTML source). Kept separate from
  ReportUsage so it always renders, not only on scans that opt into
  usage-path tracking.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 6: Sanitize agent-supplied source_location before it reaches SARIF output

**Files:**
- Create: none — the validator is a small private helper added to the existing module that already owns `source_location` end to end; no new file earns its keep for one four-line shape check (there is no existing path-safety helper elsewhere in the codebase shaped for this — `gui/app.py`'s traversal guard is a strict *allowlist* for an internal run-id used in real filesystem access, a different trust boundary from this optional, freeform, agent-authored string that is never used for I/O).
- Modify: `src/lalo/findings/tool.py:43-46` (insert the new `_sanitize_source_location` helper immediately after `_as_str_dict`), `src/lalo/findings/tool.py:111-113` (the `source_location` assignment), `src/lalo/findings/tool.py:194-201` (the final `return ToolResult(...)`, to surface a drop as a note), `src/lalo/findings/tool.py:231-233` (the tool's own docstring, one added clause telling the agent this happens)
- Test: `tests/lalo/test_findings_tool.py` (append after the existing `test_record_finding_redacts_a_secret_embedded_in_source_location`, currently ending at line 253), `tests/lalo/test_report_sarif.py` (append after the existing `test_render_sarif_result_degrades_gracefully_on_a_malformed_source_location`, currently ending at line 213)

**Interfaces:**
- Consumes: none — standalone against already-existing code (`redact()` from `..core.redaction`, already imported in `findings/tool.py`; the `args.get("source_location")` shape already accepted by `record_finding`). No other plan task needs to precede this one.
- Produces: `_sanitize_source_location(value: str) -> str | None` in `src/lalo/findings/tool.py` — pure, no I/O, returns `value` unchanged if it contains no `".."`, doesn't start with `"/"`, and contains no `"\\"`, else `None`. Behavior change other tasks must know about: a `Finding` graph node's `source_location` attribute (read today only by `report/collect.py:112` into `FindingRecord.source_location`, already typed `str | None`) is now `None` for a malformed value instead of the raw/redacted string — callers already handle `None` since the field was already optional, so this is not a new nullability case. `record_finding`'s `ToolResult.observation` string may now additionally contain a `"...looked like a path-escape attempt - dropped..."` substring when this happens (same non-blocking-note style already used for the grounding and chain-predecessor warnings in this file); `ok` stays `True` in every case. `report/sarif.py` is **not modified** — by the time `_build_result` ever sees a finding, a malformed `source_location` has already been reduced to `None` upstream, so its existing `if record.source_location and ":" in record.source_location:` guard simply never fires for one; this is a deliberate single-point-of-truth fix (the one and only producer of the `source_location` graph attribute, confirmed by grepping the whole `src/lalo` tree) rather than a second, duplicate check at the one current consumer.

- [ ] **Step 1: Write the failing test**

  Append to `tests/lalo/test_findings_tool.py` (after the existing `test_record_finding_redacts_a_secret_embedded_in_source_location`):

  ```python
  def test_record_finding_drops_a_path_traversal_shaped_source_location() -> None:
      graph = ReachabilityGraph()
      result = _registry(graph).dispatch(
          "record_finding", _args(source_location="../../etc/hostname:5")
      )
      assert result.ok is True
      assert "recorded finding-" in result.observation
      assert "dropped" in result.observation
      node = graph.node(graph.nodes_of_kind(NodeKind.FINDING)[0])
      assert node["source_location"] is None
      # everything else about the finding still landed, untouched
      assert node["vuln_class"] == "sql-injection"
      assert node["cvss_severity"] == "high"


  def test_record_finding_drops_an_absolute_path_source_location() -> None:
      graph = ReachabilityGraph()
      _registry(graph).dispatch("record_finding", _args(source_location="/etc/hostname:3"))
      node = graph.node(graph.nodes_of_kind(NodeKind.FINDING)[0])
      assert node["source_location"] is None


  def test_record_finding_drops_a_windows_drive_letter_source_location() -> None:
      graph = ReachabilityGraph()
      _registry(graph).dispatch(
          "record_finding", _args(source_location="C:\\Windows\\System32\\config\\SAM:1")
      )
      node = graph.node(graph.nodes_of_kind(NodeKind.FINDING)[0])
      assert node["source_location"] is None
  ```

  Append to `tests/lalo/test_report_sarif.py` (after the existing `test_render_sarif_result_degrades_gracefully_on_a_malformed_source_location`):

  ```python
  def test_render_sarif_drops_traversal_source_location_but_keeps_sibling_result_intact() -> None:
      graph = ReachabilityGraph()
      _file(graph, source_location="app/routes.py:42")
      _file(graph, target="https://x.example.com/other", source_location="../../etc/hostname:5")
      doc = render_sarif(_records(graph))
      good_locations, bad_locations = (r["locations"] for r in doc["runs"][0]["results"])
      physical = next(loc["physicalLocation"] for loc in good_locations if "physicalLocation" in loc)
      assert physical["artifactLocation"]["uri"] == "app/routes.py"
      assert physical["region"]["startLine"] == 42
      assert all("physicalLocation" not in loc for loc in bad_locations)
  ```

  This last test proves both halves the task asks for in one shot: the well-formed sibling still round-trips its real path/line into `artifactLocation`, and rendering the malformed one alongside it neither crashes `render_sarif` nor leaks a `physicalLocation` for it. The `"../../etc/hostname:5"` / `"/etc/hostname:3"` / `"C:\\Windows\\System32\\config\\SAM:1"` values were picked deliberately over the obvious `"../../etc/passwd:1"` example: that string is accidentally swallowed whole by the *existing*, unrelated `redact()` credential-pattern (`(?i)\b(?:...|password|passwd|pwd)\b\s*[=:]\s*\S+` treats literal `passwd:1` as a `password:value` credential and blanks it to `«REDACTED»`, which incidentally also removes the trailing digit and colon) — that would make this test pass for the wrong reason and prove nothing about the traversal check itself. Confirmed live: `redact("../../etc/passwd:1")` → `'../../etc/«REDACTED»'`, while `redact("../../etc/hostname:5")` → unchanged.

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_findings_tool.py::test_record_finding_drops_a_path_traversal_shaped_source_location tests/lalo/test_findings_tool.py::test_record_finding_drops_an_absolute_path_source_location tests/lalo/test_findings_tool.py::test_record_finding_drops_a_windows_drive_letter_source_location tests/lalo/test_report_sarif.py::test_render_sarif_drops_traversal_source_location_but_keeps_sibling_result_intact -v
  ```

  All four fail before the fix (verified live). The representative failure:

  ```
  FAILED tests/lalo/test_findings_tool.py::test_record_finding_drops_a_path_traversal_shaped_source_location
  AssertionError: assert 'dropped' in 'recorded finding-7f61f8c5ddf7: sql-injection on https://x.example.com/search - cvss=7.5 (high)'

  FAILED tests/lalo/test_findings_tool.py::test_record_finding_drops_an_absolute_path_source_location
  AssertionError: assert '/etc/hostname:3' is None

  FAILED tests/lalo/test_findings_tool.py::test_record_finding_drops_a_windows_drive_letter_source_location
  AssertionError: assert 'C:\\Windows\\System32\\config\\SAM:1' is None

  FAILED tests/lalo/test_report_sarif.py::test_render_sarif_drops_traversal_source_location_but_keeps_sibling_result_intact
  assert False
   +  where False = all(<generator object ...>)
  ```

  (The last failure is the live proof of the actual gap: today, `../../etc/hostname:5` sails through `rpartition(":")` + `isdigit()` in `sarif.py`'s `_build_result` and lands in `physicalLocation.artifactLocation.uri` verbatim.)

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/findings/tool.py`, insert a new helper right after `_as_str_dict` (currently ending at line 46):

  ```python
  def _sanitize_source_location(value: str) -> str | None:
      """Reject a ``source_location`` shaped like a path-traversal or
      filesystem-escape attempt rather than an ordinary repo-relative
      ``path/to/file.py:123`` reference: a ``..`` segment, a leading ``/``
      (absolute path), or a backslash (a Windows drive-letter/UNC path).

      This is report-output data integrity, not a testing restriction: it never
      rejects the finding, never blocks the agent, and carries no allowlist of
      "acceptable" paths - it only stops :mod:`~lalo.report.sarif` from ever
      embedding an escape-shaped string verbatim into SARIF's
      ``artifactLocation.uri``. A value that fails this shape check is simply
      dropped by the caller; every other field the agent reported still lands.
      """
      if ".." in value or value.startswith("/") or "\\" in value:
          return None
      return value
  ```

  Replace the current `source_location` assignment (lines 111-113):

  ```python
  # before
  source_location = (
      redact(str(args["source_location"])) if args.get("source_location") else None
  )
  ```

  ```python
  # after
  source_location = None
  source_location_note = ""
  if args.get("source_location"):
      candidate = redact(str(args["source_location"]))
      source_location = _sanitize_source_location(candidate)
      if source_location is None:
          source_location_note = (
              f" (WARNING: source_location {candidate!r} looked like a path-escape "
              "attempt - dropped, finding recorded without it)"
          )
  ```

  Update the final `return` (lines 194-201) to surface the note, same style as the existing `grounding_note`/`chain_note`:

  ```python
  # before
  grounding_note = "" if grounded else " (WARNING: evidence_excerpt not found in evidence)"
  chain_note = _link_enabling_finding(graph, finding_id, args)
  return ToolResult(
      observation=(
          f"recorded {finding_id}: {vuln_class} on {target} - "
          f"cvss={cvss.score:.1f} ({cvss.severity}){grounding_note}{chain_note}"
      ),
      ok=True,
  )
  ```

  ```python
  # after
  grounding_note = "" if grounded else " (WARNING: evidence_excerpt not found in evidence)"
  chain_note = _link_enabling_finding(graph, finding_id, args)
  return ToolResult(
      observation=(
          f"recorded {finding_id}: {vuln_class} on {target} - "
          f"cvss={cvss.score:.1f} ({cvss.severity}){grounding_note}"
          f"{source_location_note}{chain_note}"
      ),
      ok=True,
  )
  ```

  And extend the tool's own docstring (lines 231-233) so the agent knows this happens:

  ```python
  # before
  '"source_location": str (optional, "path/to/file.py:123" - set this when '
  "you traced the vulnerability to a specific line in a source repository "
  "you were given access to; omit it entirely when working black-box), "
  ```

  ```python
  # after
  '"source_location": str (optional, "path/to/file.py:123" - set this when '
  "you traced the vulnerability to a specific line in a source repository "
  "you were given access to; omit it entirely when working black-box; a value "
  "shaped like a path escape - containing '..', starting with '/', or containing "
  "a backslash - is dropped rather than recorded, the rest of the finding is "
  "unaffected), "
  ```

  No changes to `report/sarif.py`, `report/collect.py`, or `findings/model.py` — `source_location` was already `str | None` everywhere downstream, and `sarif.py`'s existing `if record.source_location and ":" in record.source_location:` / `line_str.isdigit()` guard already degrades gracefully when the field is absent, which is now also true whenever it was malformed.

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_findings_tool.py tests/lalo/test_report_sarif.py -v
  ```

  Verified live: `39 passed` — the 4 new tests plus every pre-existing test in both files, including the pre-existing well-formed-round-trip test (`test_render_sarif_result_includes_physical_location_when_source_location_present`) and the pre-existing redaction test on `source_location`, both unaffected. Also verified clean on this change: `uv run ruff check src/lalo/findings/tool.py tests/lalo/test_findings_tool.py tests/lalo/test_report_sarif.py` ("All checks passed!"), `uv run ruff format --check` (already formatted), and `uv run mypy src/lalo/findings/tool.py` ("Success: no issues found in 1 source file").

- [ ] **Step 5: Commit**

  ```
  git add src/lalo/findings/tool.py tests/lalo/test_findings_tool.py tests/lalo/test_report_sarif.py
  git commit -m "$(cat <<'EOF'
  fix(findings): sanitize agent-supplied source_location before SARIF export

  record_finding only ran source_location through secret redaction, with no
  shape check before report/sarif.py embedded the path half verbatim into
  SARIF's artifactLocation.uri. A value shaped like a path-traversal or
  filesystem-escape attempt (a .. segment, a leading /, a backslash) now gets
  dropped at record time instead - the finding still lands unconditionally
  with every other field intact, and the drop is noted, never hidden or
  blocking.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 7: Wire the existing cost_limit_usd mechanism end-to-end as an opt-in ScanConfig field

**Files:**
- Modify: `src/lalo/orchestrator/budget.py:37-47` (`RunStatus` enum — add `COST_EXCEEDED`)
- Modify: `src/lalo/agent/loop.py:188` (import), `:415-431` (`AgentLoop.__init__` signature), `:459-467` (store new attr), `:510-543` (`_complete` docstring + try/except)
- Modify: `src/lalo/scan.py:249-265` (`ScanConfig` new field), `:677-706` (`ScanRunner.__init__`), `:713-728` (`_should_stop`), `:836-840` (`_on_agent_event`), `:1056-1069` (child `AgentLoop(...)`), `:1190-1203` (root `AgentLoop(...)`), `:1251-1255` (status mapping)
- Test: `tests/lalo/test_scan.py` (new test added near the existing `max_duration_s`/wall-clock block, `:1565-1636`)

**Interfaces:**
- Consumes: `lalo.core.usage.record_usage(response, *, path, pricing_table=None, cost_limit_usd=None, agent_id=None, step_key=None) -> UsageStats` (already fully built/tested in isolation — only its `cost_limit_usd` parameter was ever unwired from a live caller); `lalo.core.errors.CostLimitExceededError(message="", *, total_cost_usd=0.0, limit_usd=0.0)` (already built, carries `.total_cost_usd`/`.limit_usd`); the existing `ScanConfig.max_duration_s` / `ScanRunner._should_stop` / `ScanRunner._wall_clock_exceeded` / `RunStatus.WALL_CLOCK_EXCEEDED` opt-in-ceiling pattern this task copies exactly.
- Produces: `ScanConfig.cost_limit_usd: float | None = None` (new field, default `None` = no limit); `AgentLoop.__init__(..., cost_limit_usd: float | None = None)` and `self.cost_limit_usd` (new constructor param/attr, same shape as the existing `pricing_table` param); `RunStatus.COST_EXCEEDED` (new enum member, value `"cost_exceeded"`); `ScanRunner._cost_limit_exceeded: bool` (new instance flag, mirrors `_wall_clock_exceeded`) settable via a new `"cost_limit_exceeded"` event name that `AgentLoop._complete` emits and `ScanRunner._on_agent_event` observes. Any later task reading final scan status can now check for `RunStatus.COST_EXCEEDED` the same way it already checks `RunStatus.WALL_CLOCK_EXCEEDED`.

- [ ] **Step 1: Write the failing test**

  Add to `tests/lalo/test_scan.py`, right after `test_should_stop_is_false_before_run_has_ever_started` (line 1636), reusing the file's already-imported `scan_module`, `_FakeContainer`, `_ScriptedProvider`, `_respond`, `ModelRouter`, `ScanConfig`, `ScanRunner`, `RunStatus` — no new imports needed:

  ```python
  def test_cost_limit_usd_kills_a_run_and_reports_cost_exceeded(
      tmp_path: Path, monkeypatch: pytest.MonkeyPatch
  ) -> None:
      """cost_limit_usd threads all the way through to record_usage's own
      cost_limit_usd parameter (core/usage.py) and back out as its own
      honest RunStatus - not the ambiguous UNVERIFIED_STOP a plain
      cooperative stop gets folded into by _terminal_status alone."""
      monkeypatch.setattr(scan_module, "docker_available", lambda: True)
      monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
      provider = _ScriptedProvider(_respond)
      router = ModelRouter(
          providers={"fake": provider}, routes={"reasoning": ("fake",)}, default_route=("fake",)
      )
      monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

      config = ScanConfig(
          mission="find a bug",
          target_specs=["example.com"],
          run_dir=tmp_path / "run",
          usage_path=tmp_path / "usage.json",
          # Already "exceeded" the instant a single completion is recorded:
          # a fresh usage.json ledger starts at total_cost_usd == 0.0, and
          # record_usage's own check is a strict `>`, so any negative
          # ceiling trips on the very first LLM completion regardless of
          # real token counts - the same pre-tripped-ceiling trick
          # test_max_duration_s_kills_a_run_and_reports_wall_clock_exceeded
          # uses with max_duration_s=0.0.
          cost_limit_usd=-1.0,
      )
      outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

      assert outcome.status is RunStatus.COST_EXCEEDED
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_scan.py::test_cost_limit_usd_kills_a_run_and_reports_cost_exceeded -v
  ```

  Expected failure today: `TypeError: ScanConfig.__init__() got an unexpected keyword argument 'cost_limit_usd'` — `ScanConfig` (confirmed by reading `src/lalo/scan.py:198-296` in full) has `usage_path`, `pricing_table`, and `max_duration_s` fields but no `cost_limit_usd`; `record_usage`'s `cost_limit_usd` parameter (confirmed in `src/lalo/core/usage.py:157-236`) is real and already raises `CostLimitExceededError`, but nothing in `scan.py` or `agent/loop.py` ever passes it a live value — confirming the audit's claim exactly.

- [ ] **Step 3: Write minimal implementation**

  **1. `src/lalo/orchestrator/budget.py`** — add a new `RunStatus` member, copying `WALL_CLOCK_EXCEEDED`'s exact comment style:
  ```python
      # An opt-in wall-clock ceiling (ScanConfig.max_duration_s) tripped - a
      # distinct reason from UNVERIFIED_STOP: the step/budget loop was
      # otherwise healthy and cooperating normally with should_stop(), this
      # was a real-time deadline, not an unconfirmed/ambiguous termination.
      WALL_CLOCK_EXCEEDED = "wall_clock_exceeded"
      # An opt-in lifetime-spend ceiling (ScanConfig.cost_limit_usd) tripped -
      # same reasoning as WALL_CLOCK_EXCEEDED immediately above: the step/
      # budget loop was otherwise healthy and cooperating normally with
      # should_stop(), this was a real-dollar spend ceiling crossed by
      # core.usage.record_usage's own cost_limit_usd check, not an
      # unconfirmed/ambiguous termination.
      COST_EXCEEDED = "cost_exceeded"
  ```

  **2. `src/lalo/agent/loop.py`** — thread `cost_limit_usd` through `AgentLoop` exactly like the existing `pricing_table` parameter, and stop silently swallowing the one exception `record_usage` can now genuinely raise:

  Import (line 188):
  ```python
  from ..core.errors import AllProvidersFailedError, CostLimitExceededError
  ```

  Constructor signature (was lines 415-431) — add one new keyword-only param after `pricing_table`:
  ```python
          get_steering: Callable[[], list[str]] | None = None,
          pricing_table: PricingTable | None = None,
          cost_limit_usd: float | None = None,
      ) -> None:
  ```

  Constructor body — after the existing `self.pricing_table = pricing_table` line:
  ```python
          # None (the default) means record_usage's own cost_limit_usd check
          # never fires - every existing caller that doesn't opt in keeps
          # today's unbounded-spend behavior, the exact same opt-in shape as
          # usage_path/pricing_table above and ScanConfig.max_duration_s.
          # ScanRunner is the one real caller that threads a live value
          # through, from ScanConfig.cost_limit_usd.
          self.cost_limit_usd = cost_limit_usd
  ```

  `_complete`'s docstring — replace the closing paragraph (was: `"...Never allowed to affect the agent's own control flow: a usage-recording failure (a disk error, a future cost-limit raise) is logged and swallowed, not propagated -- this is a best-effort side observation, not a correctness path."`) with:
  ```
          Recording happens
          HERE (not per-role, not per-agent) since this is the one place every
          real completion response, root or child, already passes through.
          ``usage_path`` defaults to ``None`` (recording off) so every existing
          caller that doesn't opt in stays hermetic; :class:`~lalo.scan.
          ScanRunner` opts in for a real run. A plain usage-recording failure
          (a disk error) is logged and swallowed, not propagated -- a
          best-effort side observation must never crash the agent's own
          control flow. :class:`~lalo.core.errors.CostLimitExceededError` is
          the one exception NOT swallowed the same way: it means the ledger
          write already succeeded and the operator's own ``cost_limit_usd``
          ceiling was genuinely crossed, so it's turned into a
          ``cost_limit_exceeded`` event instead (see :meth:`_emit`) --
          :class:`~lalo.scan.ScanRunner` listens for exactly that event to
          set its own stop flag, the same "flag set somewhere, read back once
          run() returns" shape ``_should_stop``'s wall-clock check already
          uses. The triggering step still completes normally (the API call
          already happened and already cost real money - see
          :class:`~lalo.core.errors.CostLimitExceededError`'s own docstring);
          only the NEXT step boundary actually stops the loop, the identical
          cooperative should_stop() contract every other ceiling in this loop
          already honors.
          """
  ```

  `_complete`'s try/except (was lines 532-543):
  ```python
          if self.usage_path is not None:
              try:
                  record_usage(
                      response,
                      path=self.usage_path,
                      agent_id=self.agent_id,
                      pricing_table=self.pricing_table,
                      cost_limit_usd=self.cost_limit_usd,
                      step_key=step_key,
                  )
              except CostLimitExceededError as exc:
                  self._emit(
                      "cost_limit_exceeded",
                      {"total_cost_usd": exc.total_cost_usd, "limit_usd": exc.limit_usd},
                  )
              except Exception:
                  _log.exception("usage recording failed; continuing without it")
          return response
  ```

  **3. `src/lalo/scan.py`**

  New `ScanConfig` field, inserted between the existing `pricing_table` and `fail_on_unreachable_targets` fields (was lines 257-258):
  ```python
      pricing_table: PricingTable | None = None
      # None (the default) preserves today's unbounded-spend behavior, the
      # exact same opt-in shape as max_duration_s below: nothing else
      # anywhere enforces a real-dollar ceiling on a scan, only max_steps/
      # budget_ceiling (turn counts) and max_duration_s (wall-clock) can ever
      # stop one on their own terms. Set to opt into a hard cost-based kill,
      # threaded straight through to core.usage.record_usage's own
      # cost_limit_usd parameter (built and unit-tested there since Phase 0,
      # never actually passed a real value by any live caller until now) --
      # compared against record_usage's own LIFETIME ledger total at
      # usage_path, so this is meaningless without usage_path also being
      # set, same as pricing_table above; a stale ledger from an earlier run
      # sharing that same usage_path can make this trip before this run has
      # spent anything itself. Reuses the SAME cooperative should_stop() kill
      # switch max_duration_s already shares across every AgentLoop in the
      # spawn tree (see ScanRunner._should_stop). Deliberately excluded from
      # _ResumeManifest and NOT persisted across a resume, same reasoning as
      # max_duration_s: an operational spend knob an operator may
      # deliberately raise to resume a cost-stopped scan, not a locked
      # scope/safety field.
      cost_limit_usd: float | None = None
      # False (the default) preserves probe_reachability's own advisory-only
  ```

  `ScanRunner.__init__` (was lines 704-705) — add the new flag next to `_wall_clock_exceeded`:
  ```python
          self._start_time: float | None = None
          self._wall_clock_exceeded = False
          # Set from _on_agent_event, not here in _should_stop unlike
          # _wall_clock_exceeded above - a cost crossing is only known once
          # record_usage() has actually persisted a completion's usage, deep
          # inside some AgentLoop._complete() call (root's or a spawned
          # child's), which reports it back out as a "cost_limit_exceeded"
          # event through the same on_event pipeline every agent already
          # uses.
          self._cost_limit_exceeded = False
  ```

  `_should_stop` (was lines 713-728) — add one check, ahead of the wall-clock one:
  ```python
      def _should_stop(self) -> bool:
          if self._cancelled:
              return True
          if self._cost_limit_exceeded:
              return True
          max_duration = self.config.max_duration_s
          if (
              max_duration is not None
              and self._start_time is not None
              and time.monotonic() - self._start_time >= max_duration
          ):
              # A plain bool write, not a read-modify-write - concurrently
              # spawned children (spawn_agents) may all observe and set this
              # at once; redundant writes of the same value are harmless,
              # unlike the counter/dict races elsewhere in this phase.
              self._wall_clock_exceeded = True
              return True
          return False
  ```

  `_on_agent_event` (was lines 836-840) — observe the new event name:
  ```python
      def _on_agent_event(self, agent_id: str, event: str, payload: dict[str, object]) -> None:
          if event == "cost_limit_exceeded":
              # Same "flag set somewhere, read back once run() returns" shape
              # _wall_clock_exceeded already uses in _should_stop() - the
              # only difference is WHERE the crossing is detected: a
              # wall-clock check runs inline inside _should_stop() itself,
              # but a cost crossing is only known once some AgentLoop (root
              # or a spawned child - this method is shared by both, see
              # _on_root_event) has actually persisted a completion's usage
              # via record_usage(), so its own on_event pipeline is what
              # carries the crossing back out here. Still falls through to
              # the generic "status" emit below - nothing about this is
              # hidden from the operator.
              self._cost_limit_exceeded = True
          if event in ("tool_call", "tool_result"):
              self._emit("log", {"agent_id": agent_id, "event": event, **payload})
          else:
              self._emit("status", {"agent_id": agent_id, "event": event, **payload})
  ```

  Both `AgentLoop(...)` construction sites — add one line to each, matching the existing `pricing_table=self.config.pricing_table,` line already there (child at line 1068, root at line 1202):
  ```python
                      pricing_table=self.config.pricing_table,
                      cost_limit_usd=self.config.cost_limit_usd,
                  )
  ```
  (and identically for the root construction).

  Status mapping (was lines 1251-1255) — extend the wall-clock special case to also check the cost flag:
  ```python
          if self._wall_clock_exceeded:
              status = RunStatus.WALL_CLOCK_EXCEEDED
          elif self._cost_limit_exceeded:
              status = RunStatus.COST_EXCEEDED
          else:
              status = _terminal_status(result.stop_reason)
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_scan.py::test_cost_limit_usd_kills_a_run_and_reports_cost_exceeded tests/lalo/test_scan.py -k "cost_limit or wall_clock or should_stop" tests/lalo/test_usage.py -k cost_limit -v
  ```

  All of the above must pass, in particular the pre-existing `test_max_duration_s_kills_a_run_and_reports_wall_clock_exceeded`, `test_max_duration_s_defaults_to_no_wall_clock_limit`, `test_should_stop_does_not_trigger_before_max_duration_s_elapses`, and `test_should_stop_is_false_before_run_has_ever_started` (regression check that the new `_cost_limit_exceeded` branch in `_should_stop`/`_on_agent_event`/the status mapping didn't disturb the wall-clock path it sits next to), plus `test_usage.py`'s existing isolated `cost_limit_usd` tests (unmodified — confirms the underlying mechanism this task wires up is untouched).

- [ ] **Step 5: Commit**

  ```
  git add src/lalo/orchestrator/budget.py src/lalo/agent/loop.py src/lalo/scan.py tests/lalo/test_scan.py
  git commit -m "$(cat <<'EOF'
  feat(L4L0): wire cost_limit_usd end-to-end as an opt-in ScanConfig ceiling

  record_usage's own cost_limit_usd parameter and CostLimitExceededError
  were built and unit-tested in isolation but no live caller ever passed
  a real value through - ScanConfig had no such field, and AgentLoop's one
  real record_usage call site silently swallowed the exception it would
  have raised. Threads a new opt-in ScanConfig.cost_limit_usd (default
  None, same shape as max_duration_s) through AgentLoop to every real
  completion, and adds RunStatus.COST_EXCEEDED so a tripped ceiling is
  reported the same honest way an opt-in wall-clock ceiling already is,
  via the same cooperative should_stop() kill switch every other ceiling
  in the loop shares.
  EOF
  )"
  ```

---

### Task 8: Add four skill-content methodology enrichments

**Files:**
- Modify: `src/lalo/skills/content/vulnerabilities/jwt.md:85-90`
- Modify: `src/lalo/skills/content/methodology/source-aware-review.md:62-74`
- Modify: `src/lalo/skills/content/methodology/severity-calibration.md:44-56`
- Modify: `src/lalo/prompts/content/review.txt:1-23`
- Test: `tests/lalo/test_skills_loader.py` (existing, unmodified — regression floor)
- Test: `tests/lalo/test_prompts.py` (existing, unmodified — regression floor)

**Interfaces:**
- Consumes: none. Standalone doc-only content addition; does not depend on any other task's code.
- Produces: none for other tasks to call. The new prose becomes part of the `Skill.body` string returned by the existing `lalo.skills.loader.load_skills()` for skills named `jwt`, `source-aware-review`, and `severity-calibration` (read at runtime by the agent's `recall` tool), and part of the string returned by the existing `lalo.prompts.loader.render_prompt("review")` (read by `lalo.findings.review.run_adversarial_review`). No new function/class signatures. Confirmed by reading `src/lalo/findings/review.py` in full: `_parse_review_response`/`_compute_review` read `parsed.get("verdict")`, `.get("proof_level")`, `.get("reasoning")` only — an added `"checklist"` key in the model's JSON reply is silently ignored by existing code, so this sub-step needs zero code changes to stay non-breaking.

This is 4 independent doc-only sub-steps bundled as one task. All four were verified against the actual current file contents below (not the audit's assumed paths/line numbers — `source-aware-review.md` and `severity-calibration.md` filenames were confirmed to exist exactly as guessed via `find`).

- [ ] **Step 1: Establish the regression floor (no new test — pure content change)**

  None of the four additions changes any code behavior, so there is no new pytest test to write. Per this project's own test-discipline convention (confirmed by reading `tests/lalo/test_skills_loader.py` and `tests/lalo/test_prompts.py` in full), two *existing* structural tests already assert something about these exact files and must still pass after the edits:
  - `tests/lalo/test_skills_loader.py::test_every_vulnerability_skill_states_a_proof_ladder` — every `category: vulnerability` skill body (this includes `jwt.md`) must contain the literal string `"Proof Ladder"`.
  - `tests/lalo/test_skills_loader.py::test_every_vulnerability_skill_cites_closure_discipline` — every vulnerability skill body must contain the literal string `"closure-discipline"`.
  - `tests/lalo/test_prompts.py::test_render_prompt_for_review_needs_no_variables` — `render_prompt("review")` must still contain `"adversarial reviewer"`.
  - `tests/lalo/test_prompts.py::test_validate_template_rejects_malformed_placeholder_syntax` — confirms `_validate_template` still rejects a bad `$`-placeholder; run alongside the others as a reminder that `review.txt` is loaded through `string.Template` (`src/lalo/prompts/loader.py:132-160`, `REQUIRED_PLACEHOLDERS["review"] = frozenset()`), so the new checklist text added to `review.txt` in sub-step (d) below **must contain no literal `$` character anywhere** — any `$name` in that file is treated as an unsupported extra placeholder and any bare `$` fails template validation at load time, which would break the built-in prompt outright (this is the built-in, not an operator override, so there is no fallback).

  `source-aware-review.md` and `severity-calibration.md` carry no per-file structural test today (only the vulnerability-category ones do), which is consistent with them being `category: methodology` rather than `category: vulnerability`.

- [ ] **Step 2: Run the regression floor now, before editing, to confirm it is currently green**

  ```
  uv run pytest tests/lalo/test_skills_loader.py::test_every_vulnerability_skill_states_a_proof_ladder tests/lalo/test_skills_loader.py::test_every_vulnerability_skill_cites_closure_discipline tests/lalo/test_prompts.py::test_render_prompt_for_review_needs_no_variables tests/lalo/test_prompts.py::test_validate_template_rejects_malformed_placeholder_syntax -v
  ```
  Expected (already confirmed by actually running this exact command against the current tree): `4 passed`. There is no red step here — the point of this step is only to record the pre-edit baseline so Step 4's re-run is a genuine regression check, not a first-time pass.

- [ ] **Step 3: Make the four content additions**

  **(a) `src/lalo/skills/content/vulnerabilities/jwt.md`** — append a new numbered technique `8` after the existing `7. **Refresh-token reuse.**` item (the file's most recent edit today added item `1`, the weak-secret technique, using this same bold-lead-sentence-then-paragraph style with em-dashes and backtick-quoted claim/op names; this addition matches that convention and is appended rather than inserted at the front, since — unlike the weak-secret check — it is not a "try this first" technique but a further escalation requiring IdP-tenant setup):

  Exact insertion (before the blank line that precedes `## Proof Ladder`):
  ```diff
   7. **Refresh-token reuse.** If refresh tokens are in scope, test whether a
      previously-used refresh token is still accepted (no rotation
      enforcement) — this is a durable-access finding distinct from anything
      about the access token itself.
  +8. **OIDC identity binding to a mutable claim ("nOAuth"-style account
  +   takeover).** Applies wherever the target lets an operator or user
  +   register or link an arbitrary external OIDC tenant as a trusted
  +   identity provider (a "bring your own IdP" / social-login SSO model).
  +   Check which claim the relying party actually uses to look up or
  +   provision the local account on login: `email` and `preferred_username`
  +   are values the ATTACKER fully controls inside a tenant they administer,
  +   while `sub` is scoped to that specific issuer and tenant and is not. To
  +   test: register a self-service tenant on the same IdP family the target
  +   trusts, issue yourself an ID token whose `sub` is attacker-chosen but
  +   whose `email`/`preferred_username` is set to a known victim's real
  +   address, and present that token at the target's SSO callback. The
  +   finding is confirmed when this authenticates you AS the victim's
  +   existing account — an established session, the victim's own private
  +   data visible — purely because the mutable claim matched, not because
  +   you merely created a new account under that address. Before calling it
  +   confirmed, rule out a relying party that keys the account on the
  +   immutable `issuer + sub` pair instead, or that requires a separate
  +   email-ownership verification step (a confirmation link, an OTP) before
  +   granting the session — either one defeats this specific variant even
  +   though the claim itself is still technically attacker-controlled.
  
   ## Proof Ladder
  ```

  **(b) `src/lalo/skills/content/methodology/source-aware-review.md`** — insert two new heuristics inside "Step Two: Dangerous-Sink Patterns Are Leads, Never Verdicts", between its intro paragraph and the "Starting patterns, by category" list, framed as filters to run *before* triaging by sink category:

  ```diff
   here it runs in the other direction — a scary-looking grep hit is not
   evidence of a real bug until you confirm the specific call, with real
   input, in context.
  
  +Two checks decide whether a hit is even worth tracing, before you look at
  +what category of sink it is:
  +
  +- **Production code vs. test fixture.** A dangerous-looking pattern living
  +  under an `examples/`, `fixtures/`, `test/`, or `tests/` directory may
  +  belong to code that never runs in the deployed application at all — a
  +  sample script, a database seed fixture, a demo the README points at.
  +  Confirm the file is actually reachable from the running application (it
  +  is imported by real application code, registered as a route, or built
  +  into the shipped artifact) before treating a hit found under one of
  +  these directories as a production finding — a vulnerable-looking
  +  snippet that only ever runs under a test runner is, at most, a note
  +  about development posture, not a finding against the deployed target.
  +- **Git-tracked vs. untracked.** A naive grep sweep for a hardcoded secret
  +  cannot tell a real, committed-and-shipped value from a local
  +  `.env`/config file a developer created on their own machine that the
  +  repository's own `.gitignore` deliberately excludes — both read
  +  identically to `grep`. Run `git ls-files` (scoped to the relevant path
  +  if the repo is large) and check the hit's path against it, and read
  +  `.gitignore` directly, before reporting a hardcoded secret found on
  +  disk: a value git has never tracked was never actually shipped, and
  +  finding it only proves you have local filesystem access to a clone, not
  +  that the deployed target embeds it.
  +
   Starting patterns, by category (adapt exact syntax to the actual language/
   framework — these are shapes, not literal strings to `grep -F`):
  ```

  **(c) `src/lalo/skills/content/methodology/severity-calibration.md`** — insert a new section between "## Marginal Capability" and "## Critical" (same "cap severity for a specific structural reason" shape as Marginal Capability), cross-referencing `llm-prompt-injection.md`'s existing reproducibility-testing bullet (`"A single anomalous response with no repeated trial and no matched baseline is not sufficient — prompt injection is often stochastic; run the same probe more than once..."`) rather than restating it:

  ```diff
     any of those is a real boundary crossing, not a self-contained effect.
  
  +## Stochastic / Non-Reproducible Findings
  +
  +Some classes — prompt injection and jailbreaking chief among them — do not
  +reproduce on every attempt even when the underlying gap is real; see
  +[[llm-prompt-injection]]'s own reproducibility-testing guidance for how to
  +actually run that test before you get here (this section is about the
  +severity consequence, not a restatement of that method). Cap the default
  +severity of a finding you could only trigger some fraction of the time,
  +UNLESS the attacker can retry the same technique against the same target
  +with no rate limit or concurrency limit standing in the way — an attacker
  +free to simply retry until it lands is not meaningfully slowed by low
  +per-attempt reproducibility, so the cap does not apply once you have
  +confirmed retries are unconstrained. Confirm which case you are actually
  +in rather than assuming one: whether "sometimes works" means "rare and
  +hard to land twice" or "trivially automatable to a near-certain eventual
  +success" changes the honest severity, and only testing at the target's
  +real allowed concurrency tells you which.
  +
   ## Critical
  ```

  **(d) `src/lalo/prompts/content/review.txt`** — add a `"checklist"` object to the required JSON reply, with one boolean key per named non-counterevidence pattern from `closure-discipline.md`'s "What Does NOT Rule Out a Candidate" section (`Generic trust in a library or framework feature`, `A control on a different path`, `A control at the wrong time`, `A control that can fail open`, `A safe sibling`, `Missing information`, `Difficulty`, `"An operator could configure this differently."`, `Being internal-only or requiring authentication` — nine bullets, confirmed by reading the file in full; no new pattern names invented). This is additive: the existing free-text `"reasoning"` field is untouched, and `src/lalo/findings/review.py`'s `_parse_review_response`/`_compute_review` only ever read `verdict`/`proof_level`/`reasoning` off the parsed dict via `.get()`, so an unread `"checklist"` key changes no runtime behavior — this stays a pure prompt-content change with no code diff required. **No `$` character appears anywhere in the new text** (verified against `_validate_template`'s `string.Template` parsing, which would otherwise reject the built-in outright since `review`'s `REQUIRED_PLACEHOLDERS` is the empty set).

  Full new file content (replaces the current 23-line file):
  ```
  You are an independent adversarial reviewer of a security finding.

  Assume the finding is a false positive by default. Your job is to disprove it.
  Evaluate the claim based ONLY on the vuln_class/target/param identity and the raw
  captured evidence shown below. You are NOT shown the finder's own description or
  counterevidence text - it may be hallucinated, so do not ask for it and do not
  assume anything it might have said.

  Reply with a single JSON object and nothing else:
  {"verdict": "confirmed" | "ruled_out" | "open_proof_gap",
   "proof_level": "L1" | "L2" | "L3" | "L4",
   "checklist": {"generic_library_trust": true | false,
                 "control_on_different_path": true | false,
                 "control_at_wrong_time": true | false,
                 "control_that_fails_open": true | false,
                 "safe_sibling": true | false,
                 "missing_information": true | false,
                 "difficulty": true | false,
                 "operator_could_configure_differently": true | false,
                 "internal_only_or_authenticated": true | false},
   "reasoning": "one or two sentences, grounded only in the evidence shown"}

  - "confirmed": the evidence shown directly demonstrates the claimed vulnerability.
  - "ruled_out": the evidence shown does not support the claim, or actively
    contradicts it (e.g. the excerpt is not present in the evidence, or the
    evidence shows a control working correctly).
  - "open_proof_gap": the evidence is suggestive but insufficient to confirm or
    rule out - name the specific gap in your reasoning.
  - proof_level is your assessment of how far the evidence goes, independent of
    verdict (L1 = anomaly only, L2 = confirmed but low-value, L3 = real impact,
    L4 = durable/systemic).

  The "checklist" keys each name one specific pattern that does NOT, by itself,
  justify "ruled_out" or a downgraded proof_level. Set a key to true only when
  that exact pattern is present in the evidence AND it is part of what is
  tempting you toward "ruled_out" - a true value is a flag for you to scrutinize
  that reasoning, never a license to use it as-is:
  - generic_library_trust: the evidence shows a framework/library call and you
    are tempted to assume it is safe without the specific call, arguments, and
    context in the evidence actually confirming that.
  - control_on_different_path: a guard or check visible in the evidence runs on
    a different route, handler, or context than the one the finding is actually
    about.
  - control_at_wrong_time: a check in the evidence runs after the dangerous
    effect rather than before it.
  - control_that_fails_open: a control in the evidence has a visible fail-open
    branch and the evidence does not show that branch is unreachable.
  - safe_sibling: the evidence shows a different, correctly-guarded call site
    than the one the finding is actually about.
  - missing_information: the evidence is silent on reachability or deployment,
    and you are tempted to read that silence as "therefore safe."
  - difficulty: the evidence shows a failed or incomplete attempt (a setup
    error, a timeout, a missing precondition) and you are tempted to read that
    as the surface being clean rather than as an open gap.
  - operator_could_configure_differently: you are tempted to rule this out
    because a stricter configuration is hypothetically possible, not because
    the evidence shows that configuration is what actually runs.
  - internal_only_or_authenticated: the evidence shows internal-only
    reachability or a required authentication step, and you are tempted to
    treat that as proof the finding is unreal rather than only a reason to
    weigh severity differently (which is not your call to make here).

  If any checklist key is true, you MUST answer "open_proof_gap" rather than
  "ruled_out" for this finding, and your "reasoning" must state the specific
  counterevidence that survives after discounting that tempting-but-invalid
  pattern.
  ```

  **No validation/limit/warning added anywhere in this task is a default restriction** — all four changes are pure methodology/prose read by the agent or the reviewer LLM at its own discretion; sub-step (d)'s checklist is advisory self-check text inside a prompt (a non-blocking review layer per CLAUDE.md's "Confidence, not gates" section already), not a code-enforced gate — nothing in `src/lalo/findings/review.py` reads or enforces the new `"checklist"` key, so it cannot block, withhold, or downgrade a finding's presence in the report.

- [ ] **Step 4: Run the regression floor again to confirm nothing broke**

  ```
  uv run pytest tests/lalo/test_skills_loader.py::test_every_vulnerability_skill_states_a_proof_ladder tests/lalo/test_skills_loader.py::test_every_vulnerability_skill_cites_closure_discipline tests/lalo/test_prompts.py::test_render_prompt_for_review_needs_no_variables tests/lalo/test_prompts.py::test_validate_template_rejects_malformed_placeholder_syntax -v
  ```
  Expected: `4 passed` — identical outcome to Step 2, confirming `jwt.md` still contains `"Proof Ladder"` and `"closure-discipline"`, and `review.txt` still loads and validates (still contains `"adversarial reviewer"`, still has no stray `$`). Also run the full skills/prompts suites once, since four files that are loaded by shared loader code changed:
  ```
  uv run pytest tests/lalo/test_skills_loader.py tests/lalo/test_prompts.py -v
  ```
  Expected: all passing, same count as before the edit (no test added or removed).

- [ ] **Step 5: Commit**

  ```
  git add src/lalo/skills/content/vulnerabilities/jwt.md src/lalo/skills/content/methodology/source-aware-review.md src/lalo/skills/content/methodology/severity-calibration.md src/lalo/prompts/content/review.txt
  git commit -m "$(cat <<'EOF'
  docs(L4L0): four skill-content enrichments - nOAuth, source-review heuristics, stochastic-severity cap, review checklist

  Adds an OIDC mutable-claim identity-binding technique to the jwt skill;
  a production-vs-fixture and git-tracked-vs-untracked filter pair to
  source-aware-review; a stochastic/non-reproducible severity cap to
  severity-calibration (cross-referencing the existing prompt-injection
  reproducibility guidance instead of duplicating it); and named
  non-counterevidence checklist keys, pulled directly from
  closure-discipline's own prose, added to the adversarial-review prompt
  alongside its existing free-text reasoning field. Pure content - no
  runtime code reads the new prompt field, so this cannot become a gate.
  EOF
  )"
  ```

**Note on the "TDD shape" for this task:** per the assignment's own carve-out, this bundle is pure documentation content with no new code behavior, so Steps 1/2/4 are a regression check against two already-existing structural test files rather than a genuine red→green cycle — there is no failing test to write because nothing here changes what the loader, the prompt renderer, or any assertion checks for. This was a deliberate scope read of the assignment text ("No new pytest test is needed for pure content changes UNLESS a structural test already asserts something about these files ... confirm the new content still satisfies them"), not an oversight.

---

### Task 9: Report polish: verdict-grouped sections, OWASP taxonomy, cover page, category quick-index

**Files:**
- Modify: `src/lalo/report/collect.py:38-40` (imports), append new functions after line 198 (end of file)
- Modify: `src/lalo/report/taxonomy.py` (append after line 65, end of file)
- Modify: `src/lalo/report/sarif.py:24-26,28-30,59-79,155-171`
- Modify: `src/lalo/report/markdown.py:40-42,81-96,174-187,211-219`
- Modify: `src/lalo/report/html.py:33-35,37-59,81-87,147-156,167-181,212-221`
- Modify: `src/lalo/report/pdf.py:66-77`
- Test: `tests/lalo/test_report_collect.py`
- Test: `tests/lalo/test_report_taxonomy.py`
- Test: `tests/lalo/test_report_sarif.py`
- Test: `tests/lalo/test_report_markdown.py`
- Test: `tests/lalo/test_report_html.py`
- Test: `tests/lalo/test_report_pdf.py`

**Interfaces:**
- Consumes: `lalo.findings.review.ReviewVerdict` (`StrEnum`, real values confirmed by reading `src/lalo/findings/review.py:98-101`: `CONFIRMED = "confirmed"`, `RULED_OUT = "ruled_out"`, `OPEN_PROOF_GAP = "open_proof_gap"`) — `FindingRecord.review_verdict: str | None` already stores exactly one of these three raw strings, or `None` for a finding the opt-in review step never ran on (confirmed by reading `src/lalo/report/collect.py:69` and `src/lalo/findings/review.py:178`). `ExecutiveSummary.by_vuln_class: dict[str, int]` (existing, from `build_executive_summary`) is reused for the quick-index counts. `lalo.report.collect.ReportMetadata` (`engagement_scope: str`, `model_provider: str`) from the sibling "report metadata" task, threaded via the `metadata: ReportMetadata | None = None` parameter that task adds to `render_report_html`/`render_report_md`.
- Produces: `lalo.report.collect.VERDICT_SECTIONS: list[tuple[str | None, str]]`, `group_by_verdict(records: list[FindingRecord]) -> list[tuple[str, list[FindingRecord]]]`, `first_finding_id_by_vuln_class(records: list[FindingRecord]) -> dict[str, str]`; `lalo.report.taxonomy.OWASP_API_TOP10_NAMES: dict[str, str]`, `OWASP_API_BY_VULN_CLASS: dict[str, str]`, `owasp_api_for(vuln_class: str) -> str | None`, `owasp_api_name_for(vuln_class: str) -> str | None`; `lalo.report.sarif._OWASP_API_TAXONOMY_NAME: str` and the resulting `run["taxonomies"]` SARIF key (present only when at least one rule maps); every rendered finding heading now carries an anchor keyed on `record.finding_id` (`<a id="...">` in Markdown, `<h2 id="...">` in HTML) that any later cross-referencing task can link to via `#{finding_id}`.

- [ ] **Step 1: Write the failing tests**

  `tests/lalo/test_report_collect.py` (add, using the file's existing `_file_finding`/`ReachabilityGraph` helpers already at the top of the file):
  ```python
  from dataclasses import replace

  from lalo.findings.review import ReviewVerdict
  from lalo.report.collect import first_finding_id_by_vuln_class, group_by_verdict

  def test_group_by_verdict_buckets_every_real_verdict_plus_not_reviewed() -> None:
      graph = ReachabilityGraph()
      _file_finding(graph, target="https://x.example.com/a")
      _file_finding(graph, target="https://x.example.com/b")
      records = collect_findings(graph)
      confirmed = replace(records[0], review_verdict=ReviewVerdict.CONFIRMED.value)
      not_reviewed = replace(records[1], review_verdict=None)
      groups = group_by_verdict([confirmed, not_reviewed])
      assert [label for label, _ in groups] == [
          "Confirmed", "Not Reviewed", "Open Proof Gap", "Ruled Out",
      ]
      by_label = dict(groups)
      assert by_label["Confirmed"] == [confirmed]
      assert by_label["Not Reviewed"] == [not_reviewed]
      assert by_label["Open Proof Gap"] == []
      assert by_label["Ruled Out"] == []

  def test_group_by_verdict_preserves_input_order_within_a_bucket() -> None:
      graph = ReachabilityGraph()
      _file_finding(graph, target="https://x.example.com/a")
      _file_finding(graph, target="https://x.example.com/b")
      records = collect_findings(graph)
      first = replace(records[0], review_verdict=ReviewVerdict.RULED_OUT.value, finding_id="f-first")
      second = replace(records[1], review_verdict=ReviewVerdict.RULED_OUT.value, finding_id="f-second")
      groups = dict(group_by_verdict([first, second]))
      assert [r.finding_id for r in groups["Ruled Out"]] == ["f-first", "f-second"]

  def test_first_finding_id_by_vuln_class_keeps_the_first_occurrence() -> None:
      graph = ReachabilityGraph()
      _file_finding(graph, target="https://x.example.com/a", vuln_class="xss")
      _file_finding(graph, target="https://x.example.com/b", vuln_class="xss")
      records = collect_findings(graph)
      anchors = first_finding_id_by_vuln_class(records)
      assert anchors["xss"] == records[0].finding_id
  ```

  `tests/lalo/test_report_taxonomy.py` (add):
  ```python
  from lalo.report.taxonomy import (
      OWASP_API_BY_VULN_CLASS,
      OWASP_API_TOP10_NAMES,
      owasp_api_for,
      owasp_api_name_for,
  )

  def test_owasp_api_for_known_vuln_class_returns_the_2023_category_id() -> None:
      assert owasp_api_for("idor") == "API1:2023"

  def test_owasp_api_for_unmapped_vuln_class_returns_none() -> None:
      assert owasp_api_for("sql-injection") is None  # dropped from the 2023 API edition

  def test_owasp_api_for_is_case_and_whitespace_insensitive() -> None:
      assert owasp_api_for("  IDOR  ") == "API1:2023"

  def test_owasp_api_name_for_returns_the_human_readable_category_name() -> None:
      assert owasp_api_name_for("idor") == "Broken Object Level Authorization"

  def test_owasp_api_name_for_unmapped_vuln_class_returns_none() -> None:
      assert owasp_api_name_for("sql-injection") is None

  def test_owasp_api_by_vuln_class_values_are_all_real_2023_category_ids() -> None:
      for category_id in OWASP_API_BY_VULN_CLASS.values():
          assert category_id in OWASP_API_TOP10_NAMES
  ```

  `tests/lalo/test_report_sarif.py` (add):
  ```python
  from lalo.report.sarif import _OWASP_API_TAXONOMY_NAME  # noqa: SLF001 - same pattern as pdf_module._deny_all_external_resources in test_report_pdf.py

  def test_render_sarif_rule_includes_an_owasp_relationship_when_mapped() -> None:
      graph = ReachabilityGraph()
      _file(graph, vuln_class="idor")
      doc = render_sarif(_records(graph))
      rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
      owasp_rel = next(
          r for r in rule["relationships"]
          if r["target"]["toolComponent"]["name"] == _OWASP_API_TAXONOMY_NAME
      )
      assert owasp_rel == {
          "target": {"id": "API1:2023", "toolComponent": {"name": _OWASP_API_TAXONOMY_NAME}},
          "kinds": ["relevant"],
      }

  def test_render_sarif_rule_keeps_the_cwe_relationship_alongside_owasp() -> None:
      graph = ReachabilityGraph()
      _file(graph, vuln_class="idor")  # idor maps to both CWE-639 and API1:2023
      doc = render_sarif(_records(graph))
      rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
      names = {r["target"]["toolComponent"]["name"] for r in rule["relationships"]}
      assert names == {"CWE", _OWASP_API_TAXONOMY_NAME}

  def test_render_sarif_omits_owasp_relationship_when_unmapped() -> None:
      graph = ReachabilityGraph()
      _file(graph, vuln_class="sql-injection")  # has a CWE but no 2023 API category
      doc = render_sarif(_records(graph))
      rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
      names = {r["target"]["toolComponent"]["name"] for r in rule["relationships"]}
      assert names == {"CWE"}

  def test_render_sarif_declares_the_owasp_taxonomy_only_when_used() -> None:
      graph = ReachabilityGraph()
      _file(graph, vuln_class="sql-injection")  # never touches OWASP
      doc = render_sarif(_records(graph))
      assert "taxonomies" not in doc["runs"][0]

  def test_render_sarif_declares_the_owasp_taxonomy_component_when_a_rule_uses_it() -> None:
      graph = ReachabilityGraph()
      _file(graph, vuln_class="idor")
      doc = render_sarif(_records(graph))
      taxonomies = doc["runs"][0]["taxonomies"]
      assert len(taxonomies) == 1
      assert taxonomies[0]["name"] == _OWASP_API_TAXONOMY_NAME
      assert {"id": "API1:2023", "name": "Broken Object Level Authorization"} in taxonomies[0]["taxa"]
  ```

  `tests/lalo/test_report_markdown.py` (add):
  ```python
  from lalo.findings.review import ReviewVerdict

  def test_render_finding_md_includes_the_owasp_line_when_mapped() -> None:
      record = replace(_record(), vuln_class="idor")
      rendered = render_finding_md(record)
      assert "**OWASP API Top 10:** API1:2023 — Broken Object Level Authorization" in rendered

  def test_render_finding_md_omits_the_owasp_line_when_unmapped() -> None:
      rendered = render_finding_md(_record())  # sql-injection has a CWE but no 2023 API category
      assert "OWASP API Top 10" not in rendered

  def test_render_finding_md_has_an_anchor_for_the_quick_index_to_target() -> None:
      record = _record()
      assert f'<a id="{record.finding_id}"></a>' in render_finding_md(record)

  def test_render_report_md_groups_findings_by_review_verdict() -> None:
      confirmed = replace(_record(), review_verdict=ReviewVerdict.CONFIRMED.value)
      not_reviewed = replace(
          _record(evidence=["e2"]), review_verdict=None, finding_id="f-not-reviewed"
      )
      coverage = CoverageSummary(assessed=["sql-injection"], not_assessed=[])
      rendered = render_report_md([confirmed, not_reviewed], coverage)
      assert "### Verdict: Confirmed (1)" in rendered
      assert "### Verdict: Not Reviewed (1)" in rendered
      assert "### Verdict: Open Proof Gap (0)" in rendered
      assert "### Verdict: Ruled Out (0)" in rendered
      assert "f-not-reviewed" in rendered

  def test_render_report_md_with_no_findings_has_no_verdict_sections() -> None:
      coverage = CoverageSummary(assessed=[], not_assessed=[])
      assert "Verdict:" not in render_report_md([], coverage)

  def test_render_report_md_quick_index_links_to_the_first_finding_of_each_category() -> None:
      record = _record()
      coverage = CoverageSummary(assessed=["sql-injection"], not_assessed=[])
      summary = ExecutiveSummary(
          total_findings=1, by_severity={"high": 1},
          by_vuln_class={"sql-injection": 1}, highest_severity="high",
      )
      rendered = render_report_md([record], coverage, summary=summary)
      assert "## Summary by Vulnerability Type" in rendered
      assert f"- [sql-injection (1)](#{record.finding_id})" in rendered
  ```

  `tests/lalo/test_report_html.py` (add):
  ```python
  from lalo.findings.review import ReviewVerdict

  def test_render_finding_html_includes_the_owasp_line_when_mapped() -> None:
      record = replace(_record(), vuln_class="idor")
      rendered = render_finding_html(record)
      assert "<dt>OWASP API Top 10</dt><dd>API1:2023" in rendered
      assert "Broken Object Level Authorization" in rendered

  def test_render_finding_html_omits_the_owasp_line_when_unmapped() -> None:
      assert "OWASP API Top 10" not in render_finding_html(_record())

  def test_render_finding_html_heading_carries_an_id_anchor() -> None:
      record = _record()
      assert f'<h2 id="{record.finding_id}">' in render_finding_html(record)

  def test_render_report_html_groups_findings_by_review_verdict() -> None:
      confirmed = replace(_record(), review_verdict=ReviewVerdict.CONFIRMED.value)
      coverage = CoverageSummary(assessed=["sql-injection"], not_assessed=[])
      rendered = render_report_html([confirmed], coverage)
      assert "<h3>Verdict: Confirmed (1)</h3>" in rendered
      assert "<h3>Verdict: Ruled Out (0)</h3>" in rendered
      assert "<p><em>None.</em></p>" in rendered

  def test_render_report_html_with_no_findings_has_no_verdict_sections() -> None:
      coverage = CoverageSummary(assessed=[], not_assessed=[])
      assert "Verdict:" not in render_report_html([], coverage)

  def test_render_report_html_quick_index_links_to_the_first_finding_of_each_category() -> None:
      record = _record()
      coverage = CoverageSummary(assessed=["sql-injection"], not_assessed=[])
      summary = ExecutiveSummary(
          total_findings=1, by_severity={"high": 1},
          by_vuln_class={"sql-injection": 1}, highest_severity="high",
      )
      rendered = render_report_html([record], coverage, summary=summary)
      assert "<h2>Summary by Vulnerability Type</h2>" in rendered
      assert f'<li><a href="#{record.finding_id}">sql-injection (1)</a></li>' in rendered

  def test_render_report_html_includes_a_cover_page_ahead_of_the_executive_summary() -> None:
      coverage = CoverageSummary(assessed=[], not_assessed=[])
      summary = ExecutiveSummary(
          total_findings=0, by_severity={}, by_vuln_class={}, highest_severity=None
      )
      rendered = render_report_html([], coverage, generated_at="2026-09-08", summary=summary)
      assert 'class="cover-page"' in rendered
      assert "2026-09-08" in rendered
      assert "Confidential" in rendered
      assert rendered.index('class="cover-page"') < rendered.index("<h2>Executive Summary</h2>")

  def test_render_report_html_cover_page_falls_back_when_engagement_metadata_is_absent() -> None:
      coverage = CoverageSummary(assessed=[], not_assessed=[])
      assert "(not recorded)" in render_report_html([], coverage)

  def test_render_report_html_cover_page_surfaces_engagement_scope_and_model_once_that_metadata_exists() -> None:
      """engagement_scope/model_provider come from the sibling report-metadata
      task's ReportMetadata, threaded in via the `metadata` parameter that
      task adds to render_report_html - a confirmed, real cross-task
      interface, not a forward guess."""
      from lalo.report.collect import ReportMetadata

      metadata = ReportMetadata(
          engagement_scope="https://x.example.com", model_provider="opencodex:gpt-5.6"
      )
      coverage = CoverageSummary(assessed=[], not_assessed=[])
      rendered = render_report_html([], coverage, metadata=metadata)
      assert "https://x.example.com" in rendered
      assert "opencodex:gpt-5.6" in rendered
  ```

  `tests/lalo/test_report_pdf.py` (add):
  ```python
  def test_render_report_pdf_puts_the_cover_page_on_its_own_page() -> None:
      html = (
          "<!doctype html><html><head><style>body{color:#000;}</style></head>"
          '<body><div class="cover-page"><h1>L4L0 Security Assessment Report</h1>'
          "<p>cover-marker-abc</p></div>"
          "<h2>Executive Summary</h2><p>findings-marker-xyz</p></body></html>"
      )
      pdf_bytes = render_report_pdf(html)
      reader = PdfReader(BytesIO(pdf_bytes))
      assert len(reader.pages) >= 2
      assert "cover-marker-abc" in reader.pages[0].extract_text()
      assert "findings-marker-xyz" not in reader.pages[0].extract_text()
      assert "findings-marker-xyz" in reader.pages[1].extract_text()
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```
  uv run pytest tests/lalo/test_report_collect.py tests/lalo/test_report_taxonomy.py tests/lalo/test_report_sarif.py tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py tests/lalo/test_report_pdf.py -q
  ```
  Expected: collection errors for the three files whose new tests import symbols that don't exist yet —
  `ImportError: cannot import name 'group_by_verdict' from 'lalo.report.collect'` (test_report_collect.py),
  `ImportError: cannot import name 'OWASP_API_BY_VULN_CLASS' from 'lalo.report.taxonomy'` (test_report_taxonomy.py),
  `ImportError: cannot import name '_OWASP_API_TAXONOMY_NAME' from 'lalo.report.sarif'` (test_report_sarif.py) —
  and real `AssertionError`s for the other three, which collect fine but fail on content, e.g.
  `assert "OWASP API Top 10" not in rendered` failing is not the issue — rather `assert '**OWASP API Top 10:** API1:2023 — Broken Object Level Authorization' in rendered` raises `AssertionError` (the line doesn't exist yet), `assert '<h3>Verdict: Confirmed (1)</h3>' in rendered` raises `AssertionError` (no verdict grouping yet), and `assert len(reader.pages) >= 2` raises `AssertionError` (no page-break CSS yet, so the whole document renders as one page).

- [ ] **Step 3: Write minimal implementation**

  **(a) verdict-grouped sections — `src/lalo/report/collect.py`**

  Current imports (lines 38-40):
  ```python
  from ..findings.confidence import ConfidenceScore, compute_confidence
  from ..findings.dedup import dedup_key
  from ..graph.model import Chain, NodeKind, ReachabilityGraph
  ```
  Add the review import:
  ```python
  from ..findings.confidence import ConfidenceScore, compute_confidence
  from ..findings.dedup import dedup_key
  from ..findings.review import ReviewVerdict
  from ..graph.model import Chain, NodeKind, ReachabilityGraph
  ```
  Append at the end of the file (after `build_chain_records`, currently ending at line 198):
  ```python


  # One section per real ReviewVerdict value, plus a 4th bucket for a finding
  # that was never reviewed at all (review_verdict is None - the review step
  # is opt-in and non-blocking per CLAUDE.md, so plenty of real findings will
  # never carry one). Order is "most immediately actionable first": CONFIRMED,
  # then the ones the review step never weighed in on, then the two verdicts a
  # reviewer actually returned doubt about - RULED_OUT last since CLAUDE.md's
  # "neither layer ever removes a finding" means it still has to be shown,
  # just not first.
  VERDICT_SECTIONS: list[tuple[str | None, str]] = [
      (ReviewVerdict.CONFIRMED.value, "Confirmed"),
      (None, "Not Reviewed"),
      (ReviewVerdict.OPEN_PROOF_GAP.value, "Open Proof Gap"),
      (ReviewVerdict.RULED_OUT.value, "Ruled Out"),
  ]


  def group_by_verdict(
      records: list[FindingRecord],
  ) -> list[tuple[str, list[FindingRecord]]]:
      """Bucket ``records`` by ``review_verdict``, in :data:`VERDICT_SECTIONS`
      order - every section is present in the result even when its bucket is
      empty, so a renderer can print its header unconditionally and nothing
      ever looks silently hidden. Filtering (not re-sorting) preserves
      whatever order ``records`` already came in - callers that pre-sort via
      :func:`sort_findings` keep that severity ordering within each bucket."""
      return [
          (label, [record for record in records if record.review_verdict == verdict_value])
          for verdict_value, label in VERDICT_SECTIONS
      ]


  def first_finding_id_by_vuln_class(records: list[FindingRecord]) -> dict[str, str]:
      """The id of the first (in ``records`` order) finding for each
      ``vuln_class`` - the anchor target a "Summary by Vulnerability Type"
      quick-index link jumps to. Only ever the first occurrence: once
      :func:`group_by_verdict` scatters same-category findings across
      different verdict sections, a single in-page anchor can't reach all of
      them at once - landing on the first is enough for a reader to find the
      rest from there."""
      first_id: dict[str, str] = {}
      for record in records:
          first_id.setdefault(record.vuln_class, record.finding_id)
      return first_id
  ```

  **(b) OWASP API Top 10 taxonomy — `src/lalo/report/taxonomy.py`**

  Append after the existing `cwe_for` function (line 65). Category names verified against OWASP's own published 2023 edition (owasp.org/API-Security/editions/2023/en/0x11-t10), not recalled from memory:
  ```python


  # --- OWASP API Security Top 10 (2023 edition) ---------------------------
  # Curated the same way as CWE_BY_VULN_CLASS above: only vuln_class slugs
  # with a genuinely clean fit to a real 2023 category are mapped - BOLA is
  # textbook IDOR, "mass assignment" was folded into "Broken Object Property
  # Level Authorization" by name in the 2023 edition, SSRF keeps its own
  # dedicated category unchanged, and so on. The 2023 edition dropped the old
  # 2019 catch-all "Injection" category entirely, so sql-injection/
  # command-injection/ssti/xxe/nosql-injection - a real, accurate CWE match
  # each - have no honest 2023 API-Top-10 home and are deliberately left
  # unmapped here, exactly like subdomain-takeover is left unmapped in
  # CWE_BY_VULN_CLASS above.
  OWASP_API_TOP10_NAMES: dict[str, str] = {
      "API1:2023": "Broken Object Level Authorization",
      "API2:2023": "Broken Authentication",
      "API3:2023": "Broken Object Property Level Authorization",
      "API4:2023": "Unrestricted Resource Consumption",
      "API5:2023": "Broken Function Level Authorization",
      "API6:2023": "Unrestricted Access to Sensitive Business Flows",
      "API7:2023": "Server Side Request Forgery",
      "API8:2023": "Security Misconfiguration",
      "API9:2023": "Improper Inventory Management",
      "API10:2023": "Unsafe Consumption of APIs",
  }

  OWASP_API_BY_VULN_CLASS: dict[str, str] = {
      "idor": "API1:2023",
      "authentication-bypass": "API2:2023",
      "weak-credentials": "API2:2023",
      "jwt": "API2:2023",
      "mass-assignment": "API3:2023",
      "broken-access-control": "API5:2023",
      "access-control": "API5:2023",
      "ssrf": "API7:2023",
      "cors-misconfiguration": "API8:2023",
      "cloud-iam-storage-misconfiguration": "API8:2023",
      "kubernetes-serverless-assessment": "API8:2023",
      "graphql": "API9:2023",
      "subdomain-takeover": "API9:2023",
  }


  def owasp_api_for(vuln_class: str) -> str | None:
      """Best-effort OWASP API Security Top 10 (2023) category id for a
      vuln_class slug (e.g. "API1:2023"), or None if unmapped - same
      degrade-to-nothing contract as cwe_for above."""
      return OWASP_API_BY_VULN_CLASS.get(vuln_class.strip().lower())


  def owasp_api_name_for(vuln_class: str) -> str | None:
      """The mapped category's human-readable name (e.g. "Broken Object Level
      Authorization"), or None if unmapped."""
      category = owasp_api_for(vuln_class)
      return OWASP_API_TOP10_NAMES.get(category) if category else None
  ```

  **(b) SARIF taxonomies block — `src/lalo/report/sarif.py`**

  Imports (lines 24-26):
  ```python
  from ..findings.dedup import dedup_key
  from .collect import FindingRecord
  from .taxonomy import cwe_for
  ```
  becomes:
  ```python
  from ..findings.dedup import dedup_key
  from .collect import FindingRecord
  from .taxonomy import OWASP_API_BY_VULN_CLASS, OWASP_API_TOP10_NAMES, cwe_for, owasp_api_for
  ```
  After `TOOL_NAME = "L4L0"` (line 30), add:
  ```python
  # The one taxonomy this project's own curated OWASP_API_BY_VULN_CLASS
  # mapping ever references - declared in SARIF's own run-level "taxonomies"
  # array (added by render_sarif, only when at least one rule actually uses
  # it) so every OWASP relationship a rule emits below resolves against
  # something real, mirroring the existing CWE relationship shape exactly.
  _OWASP_API_TAXONOMY_NAME = "OWASP-API-Security-Top-10-2023"
  ```
  `_build_rule` (lines 59-79) — replace the CWE-only tail with both relationships, plus a new helper:
  ```python
  def _build_rule(record: FindingRecord) -> dict[str, Any]:
      rule_id = _rule_id(record)
      rule: dict[str, Any] = {
          "id": rule_id,
          "name": record.vuln_class or rule_id,
          "shortDescription": {"text": record.title or rule_id},
          "fullDescription": {"text": record.description or record.title or rule_id},
          "help": {"text": record.remediation or "(no remediation stated)"},
          "defaultConfiguration": {"level": _sarif_level(record)},
          "properties": {"security-severity": _security_severity(record)},
      }
      # Only added when a mapping actually exists - an unmapped vuln_class
      # must never render as a fabricated/empty relationship, per
      # lalo.report.taxonomy's own "degrades to no CWE line, never an error"
      # contract. Same contract now applies to the OWASP relationship below.
      relationships: list[dict[str, Any]] = []
      cwe = cwe_for(record.vuln_class)
      if cwe:
          relationships.append(
              {"target": {"id": cwe, "toolComponent": {"name": "CWE"}}, "kinds": ["relevant"]}
          )
      owasp = owasp_api_for(record.vuln_class)
      if owasp:
          relationships.append(
              {
                  "target": {"id": owasp, "toolComponent": {"name": _OWASP_API_TAXONOMY_NAME}},
                  "kinds": ["relevant"],
              }
          )
      if relationships:
          rule["relationships"] = relationships
      return rule


  def _owasp_taxonomy_component() -> dict[str, Any]:
      """The run-level ToolComponent every OWASP relationship above resolves
      against - SARIF's own ``run.taxonomies`` array. Declares only the
      category ids this project's curated OWASP_API_BY_VULN_CLASS mapping can
      ever emit, not the full external OWASP list - an undeclared
      relationship would be as misleading as a fabricated one, but so is
      declaring ten taxa when this codebase's own mapping only ever points at
      a handful of them."""
      used_ids = sorted(set(OWASP_API_BY_VULN_CLASS.values()))
      return {
          "name": _OWASP_API_TAXONOMY_NAME,
          "organization": "OWASP",
          "informationUri": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
          "taxa": [{"id": cat_id, "name": OWASP_API_TOP10_NAMES[cat_id]} for cat_id in used_ids],
      }
  ```
  `render_sarif`'s build loop (lines 155-171) — track whether OWASP was used and declare the taxonomy only then:
  ```python
      rule_index_by_id: dict[str, int] = {}
      rules: list[dict[str, Any]] = []
      results: list[dict[str, Any]] = []
      owasp_taxonomy_used = False
      for record in records:
          rule_id = _rule_id(record)
          if rule_id not in rule_index_by_id:
              rule_index_by_id[rule_id] = len(rules)
              rules.append(_build_rule(record))
              if owasp_api_for(record.vuln_class):
                  owasp_taxonomy_used = True
          results.append(_build_result(record, rule_index_by_id[rule_id]))

      run: dict[str, Any] = {
          "tool": {"driver": {"name": TOOL_NAME, "rules": rules}},
          "results": results,
          "invocations": [{"executionSuccessful": execution_successful}],
      }
      if owasp_taxonomy_used:
          run["taxonomies"] = [_owasp_taxonomy_component()]
      if automation_id:
          run["automationDetails"] = {"id": automation_id}
  ```

  **(a)+(b)+(d) — `src/lalo/report/markdown.py`**

  Imports (lines 40-42):
  ```python
  from .collect import ChainRecord, ExecutiveSummary, FindingRecord, ReportUsage
  from .coverage import CoverageSummary
  from .taxonomy import cwe_for
  ```
  becomes:
  ```python
  from .collect import (
      ChainRecord,
      ExecutiveSummary,
      FindingRecord,
      ReportUsage,
      first_finding_id_by_vuln_class,
      group_by_verdict,
  )
  from .coverage import CoverageSummary
  from .taxonomy import cwe_for, owasp_api_for, owasp_api_name_for
  ```
  `render_finding_md` (lines 81-89) — add the anchor (d) and the OWASP line (b), keeping every other line unchanged:
  ```python
  def render_finding_md(record: FindingRecord) -> str:
      lines = [
          f'<a id="{record.finding_id}"></a>',
          f"## {record.title or record.finding_id}",
          f"**ID:** {record.finding_id}",
          f"**Class:** {record.vuln_class}",
      ]
      cwe = cwe_for(record.vuln_class)
      if cwe:
          lines.append(f"**CWE:** {cwe}")
      owasp = owasp_api_for(record.vuln_class)
      if owasp:
          owasp_name = owasp_api_name_for(record.vuln_class)
          lines.append(f"**OWASP API Top 10:** {owasp}" + (f" — {owasp_name}" if owasp_name else ""))
      lines += [
  ```
  `render_report_md`'s Executive Summary block (lines 174-187) — add the quick index (d) right after it, still gated on `summary is not None`:
  ```python
      if summary is not None:
          lines.append("## Executive Summary\n")
          severity_line = (
              ", ".join(f"{sev}: {count}" for sev, count in summary.by_severity.items()) or "(none)"
          )
          category_line = (
              ", ".join(f"{cls}: {count}" for cls, count in summary.by_vuln_class.items()) or "(none)"
          )
          lines.append(f"**By severity:** {severity_line}")
          lines.append(f"**By category:** {category_line}")
          if summary.highest_severity:
              lines.append(f"**Highest severity:** {summary.highest_severity.upper()}")
          lines.append("")

          lines.append("## Summary by Vulnerability Type\n")
          if not summary.by_vuln_class:
              lines.append("(none)")
          else:
              anchor_by_class = first_finding_id_by_vuln_class(records)
              for cls, count in summary.by_vuln_class.items():
                  anchor = anchor_by_class.get(cls)
                  label = f"{cls} ({count})"
                  lines.append(f"- [{label}](#{anchor})" if anchor else f"- {label}")
          lines.append("")

      lines.append("## Coverage\n")
  ```
  `render_report_md`'s flat Findings loop (lines 211-219) — wrap in verdict-grouped iteration (a), keeping `render_finding_md` itself and its per-finding try/except completely unchanged:
  ```python
      lines.append("## Findings\n")
      if not records:
          lines.append("No findings recorded.")
      else:
          for label, group in group_by_verdict(records):
              lines.append(f"### Verdict: {label} ({len(group)})\n")
              if not group:
                  lines.append("_None._\n")
                  continue
              for record in group:
                  try:
                      lines.append(render_finding_md(record))
                  except Exception as exc:  # noqa: BLE001 - one malformed finding must not blank the report
                      lines.append(f"## {record.finding_id}\n\n_Failed to render this finding: {exc}_\n")

      return "\n".join(lines)
  ```

  **(a)+(b)+(c)+(d) — `src/lalo/report/html.py`**

  Imports (lines 33-35):
  ```python
  from .collect import ChainRecord, ExecutiveSummary, FindingRecord, ReportUsage
  from .coverage import CoverageSummary
  from .taxonomy import cwe_for
  ```
  becomes:
  ```python
  from .collect import (
      ChainRecord,
      ExecutiveSummary,
      FindingRecord,
      ReportUsage,
      first_finding_id_by_vuln_class,
      group_by_verdict,
  )
  from .coverage import CoverageSummary
  from .taxonomy import cwe_for, owasp_api_for, owasp_api_name_for
  ```
  `_STYLE` (line 56, just before the closing `"""` on line 57) — add cover-page CSS (c), visually consistent with the existing chip/warning palette (reusing the `.warning`/`#a33` red already defined in `_STYLE` for the confidentiality line):
  ```python
  .stat-chip.sev-info { background: #f1f5f9; color: #475569; }
  .cover-page { border: 1px solid #ccc; border-radius: 6px; padding: 12px 16px;
    margin: 12px 0 24px; background: #fafafa; }
  .cover-page p { margin: 4px 0; }
  .confidentiality { color: #a33; font-weight: bold; font-style: italic; }
  """
  ```
  After `_KNOWN_SEVERITIES` (line 59), add:
  ```python
  _CONFIDENTIALITY_NOTICE = "Confidential — authorized engagement only."
  ```
  `render_finding_html` (lines 82-87) — add the id anchor (d) and OWASP line (b):
  ```python
  def render_finding_html(record: FindingRecord) -> str:
      parts = [f'<h2 id="{_e(record.finding_id)}">{_e(record.title or record.finding_id)}</h2>', "<dl>"]
      parts.append(f"<dt>ID</dt><dd>{_e(record.finding_id)}</dd>")
      parts.append(f"<dt>Class</dt><dd>{_e(record.vuln_class)}</dd>")
      cwe = cwe_for(record.vuln_class)
      if cwe:
          parts.append(f"<dt>CWE</dt><dd>{_e(cwe)}</dd>")
      owasp = owasp_api_for(record.vuln_class)
      if owasp:
          owasp_name = owasp_api_name_for(record.vuln_class)
          label = f"{owasp} — {owasp_name}" if owasp_name else owasp
          parts.append(f"<dt>OWASP API Top 10</dt><dd>{_e(label)}</dd>")
  ```
  `render_report_html`'s opening (lines 147-156) — insert the cover page (c) ahead of everything, including the existing Generated/Scan Status/Findings/Usage lines (which stay exactly as they are — this is an additional block, not a replacement):
  ```python
      parts = [
          "<!doctype html>",
          f"<html><head><meta charset='utf-8'><style>{_STYLE}</style></head><body>",
          "<h1>L4L0 Security Assessment Report</h1>",
      ]
      # Cover page. engagement_scope/model_provider come straight off the
      # ReportMetadata the sibling report-metadata task threads onto this
      # same signature as `metadata: ReportMetadata | None = None` (this
      # diff only reads it, it doesn't redeclare the signature) - degrades
      # to "(not recorded)" when metadata is None, same as every other
      # optional Executive Summary block here.
      engagement_scope = metadata.engagement_scope if metadata is not None else None
      model_provider = metadata.model_provider if metadata is not None else None
      parts.append('<section class="cover-page">')
      parts.append(
          f"<p><strong>Target / Engagement Scope:</strong> {_e(engagement_scope or '(not recorded)')}</p>"
      )
      parts.append(f"<p><strong>Report Date:</strong> {_e(generated_at or '(not recorded)')}</p>")
      parts.append(
          f"<p><strong>Model / Provider:</strong> {_e(model_provider or '(not recorded)')}</p>"
      )
      parts.append(f'<p class="confidentiality">{_e(_CONFIDENTIALITY_NOTICE)}</p>')
      parts.append("</section>")
      if generated_at:
          parts.append(f"<p><strong>Generated:</strong> {_e(generated_at)}</p>")
  ```
  `render_report_html`'s Executive Summary block (lines 167-179) — add the quick index (d):
  ```python
      if summary is not None:
          parts.append("<h2>Executive Summary</h2>")
          if summary.by_severity:
              parts.append(_stat_chips(summary.by_severity))
          category_line = (
              ", ".join(f"{_e(cls)}: {count}" for cls, count in summary.by_vuln_class.items())
              or "(none)"
          )
          parts.append(f"<p><strong>By category:</strong> {category_line}</p>")
          if summary.highest_severity:
              parts.append(
                  f"<p><strong>Highest severity:</strong> {_e(summary.highest_severity.upper())}</p>"
              )

          parts.append("<h2>Summary by Vulnerability Type</h2>")
          if not summary.by_vuln_class:
              parts.append("<p>(none)</p>")
          else:
              anchor_by_class = first_finding_id_by_vuln_class(records)
              parts.append("<ul>")
              for cls, count in summary.by_vuln_class.items():
                  anchor = anchor_by_class.get(cls)
                  label = f"{_e(cls)} ({count})"
                  parts.append(
                      f'<li><a href="#{_e(anchor)}">{label}</a></li>' if anchor else f"<li>{label}</li>"
                  )
              parts.append("</ul>")

      parts.append("<h2>Coverage</h2>")
  ```
  `render_report_html`'s flat Findings loop (lines 212-221) — wrap in verdict-grouped iteration (a):
  ```python
      parts.append("<h2>Findings</h2>")
      if not records:
          parts.append("<p>No findings recorded.</p>")
      else:
          for label, group in group_by_verdict(records):
              parts.append(f"<h3>Verdict: {_e(label)} ({len(group)})</h3>")
              if not group:
                  parts.append("<p><em>None.</em></p>")
                  continue
              for record in group:
                  try:
                      parts.append(render_finding_html(record))
                  except Exception as exc:  # noqa: BLE001 - malformed finding must not blank the report
                      parts.append(
                          f"<h2>{_e(record.finding_id)}</h2><p>Failed to render this finding: {_e(exc)}</p>"
                      )
  ```

  **(c) PDF page-break — `src/lalo/report/pdf.py`**

  `_PAGE_STYLE` (lines 66-77) — add one PDF-only rule, injected the same way the existing header/footer rule already is:
  ```python
  _PAGE_STYLE = """
  @page {
    size: A4;
    margin: 2.4cm 1.6cm 2.2cm 1.6cm;
    @top-center {
      content: "L4L0 Security Assessment Report"; font-size: 8pt; color: #888;
    }
    @bottom-center {
      content: "Page " counter(page) " of " counter(pages); font-size: 8pt; color: #888;
    }
  }
  /* The cover page (report/html.py's own .cover-page section) is a PDF-paged
     -medium concept - on its own page in the PDF, exactly one on-screen HTML
     block everywhere else. PDF-only, same reasoning as the rest of this
     file's own @page rule: html2docx has no notion of CSS pagination. */
  .cover-page { page-break-after: always; }
  """
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```
  uv run pytest tests/lalo/test_report_collect.py tests/lalo/test_report_taxonomy.py tests/lalo/test_report_sarif.py tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py tests/lalo/test_report_pdf.py -q
  uv run ruff check src/lalo/report tests/lalo/test_report_collect.py tests/lalo/test_report_taxonomy.py tests/lalo/test_report_sarif.py tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py tests/lalo/test_report_pdf.py
  uv run ruff format src/lalo/report tests/lalo/test_report_collect.py tests/lalo/test_report_taxonomy.py tests/lalo/test_report_sarif.py tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py tests/lalo/test_report_pdf.py
  uv run mypy
  ```
  All new and existing tests in the six touched test files pass; `mypy` stays clean (every new function is fully typed, and the cover page's `metadata.engagement_scope`/`metadata.model_provider` reads type-check directly against the real `ReportMetadata` dataclass the sibling report-metadata task adds).

- [ ] **Step 5: Commit**
  ```
  git add src/lalo/report/collect.py src/lalo/report/taxonomy.py src/lalo/report/sarif.py src/lalo/report/markdown.py src/lalo/report/html.py src/lalo/report/pdf.py tests/lalo/test_report_collect.py tests/lalo/test_report_taxonomy.py tests/lalo/test_report_sarif.py tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py tests/lalo/test_report_pdf.py

  git commit -m "$(cat <<'EOF'
  feat(report): verdict-grouped sections, OWASP API taxonomy, cover page, category quick-index

  Groups the Markdown/HTML Findings section by review verdict, with a header
  for every section (including a Not Reviewed bucket) even when empty, so
  nothing is silently hidden. Adds a curated vuln_class to OWASP API
  Security Top 10 (2023) mapping, surfaced in SARIF's own taxonomies block
  alongside the existing CWE relationship and printed next to the CWE line
  in Markdown/HTML. Gives the HTML/PDF report a cover page (target, date,
  model/provider, a confidentiality marking) ahead of the Executive
  Summary, on its own PDF page. Adds a Summary by Vulnerability Type quick
  index with in-page anchors down to each category's first finding.
  EOF
  )"
  git status
  ```

---

### Task 10: Opt-in `keep_on_failure` flag for the disposable runtime container

**Files:**
- Modify: `src/lalo/runtime/container.py:163-173` (add `RuntimeConfig.keep_on_failure` field), `:386-396` (`RuntimeContainer.stop()`)
- Modify: `src/lalo/scan.py:120-122` (add `import sys`), `:973-975` (the `finally: container.stop()` block in `ScanRunner.run()`)
- Modify: `tests/lalo/test_scan.py:282-295` (`_FakeContainer` test double — must accept/record the new `stop(failed=...)` kwarg or every one of the ~40 existing tests that use it breaks)
- Test: `tests/lalo/test_runtime_keep_on_failure.py` (new, hermetic — mocks `subprocess.run` like `tests/lalo/test_runtime_timeout.py`, no live Docker needed), plus one new test function appended to `tests/lalo/test_scan.py`

**Interfaces:**
- Consumes: none — this modifies code that already exists on `project-lalo`: `lalo.runtime.container.RuntimeConfig`/`RuntimeContainer.stop()` and `lalo.scan.ScanRunner.run()`'s teardown `finally` block. No earlier task in this plan is required.
- Produces:
  - `RuntimeConfig.keep_on_failure: bool = False` (new dataclass field, opt-in, off by default).
  - `RuntimeContainer.stop(self, *, failed: bool = False) -> None` (new keyword-only param on an existing method; the old zero-arg call shape still works everywhere unchanged).
  - Test double `_FakeContainer.stop(self, *, failed: bool = False) -> None` and a new `_FakeContainer.stopped_with_failed: bool | None` attribute — later tests in `tests/lalo/test_scan.py` can assert on this to check teardown behavior without touching real Docker.

- [ ] **Step 1: Write the failing test**

  First, current behavior confirmed by reading both files in full: `RuntimeContainer.stop()` (`src/lalo/runtime/container.py:386-396`) unconditionally runs `docker rm -f` whenever `self._started`, on every code path including one where the caller is mid-exception-unwind. `ScanRunner.run()`'s `finally: container.stop()` (`src/lalo/scan.py:973-975`) is the last of four nested `try/finally` blocks wrapping `container.start()` through `self._run_inside(...)`; it has no `except` clause of its own, so it currently has no way to tell a normal `return` apart from a raised exception. Verified empirically that `sys.exc_info()` is still populated inside a bare `finally:` clause while an exception is propagating through it (and is `(None, None, None)` on a normal `return`), so that's usable here without restructuring the whole nested chain into try/except/else. Also confirmed `_FakeContainer.stop(self) -> None` (`tests/lalo/test_scan.py:291-292`) is the test double swapped in via `monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)` at ~40 call sites in that file — any change to the real `stop()` signature has to be mirrored there or every one of those breaks with `TypeError: stop() got an unexpected keyword argument 'failed'`.

  First, update the fake in `tests/lalo/test_scan.py` (necessary test scaffolding — the real test below can't observe the new behavior without it):

  ```python
  # tests/lalo/test_scan.py — inside class _FakeContainer (was lines 282-295)
  class _FakeContainer:
      """Stands in for RuntimeContainer - no real docker daemon required."""

      def __init__(self, config: object = None) -> None:
          self.started = False
          self.stopped_with_failed: bool | None = None

      def start(self) -> None:
          self.started = True

      def stop(self, *, failed: bool = False) -> None:
          self.started = False
          self.stopped_with_failed = failed

      def exec(self, command: object, *, timeout: float = 120.0) -> SimpleNamespace:
          return SimpleNamespace(exit_code=0, stdout="", stderr="", ok=True, timed_out=False)

      def exec_streaming(
          self, command: object, on_chunk, *, timeout: float = 120.0
      ) -> SimpleNamespace:
          on_chunk("stdout", "")
          return SimpleNamespace(exit_code=0, stdout="", stderr="", ok=True, timed_out=False)
  ```

  New hermetic file `tests/lalo/test_runtime_keep_on_failure.py` (mirrors `tests/lalo/test_runtime_timeout.py`'s mocking pattern exactly — no Docker daemon required, runs unconditionally):

  ```python
  """Hermetic tests for RuntimeContainer's opt-in keep-on-failure teardown.

  No real Docker daemon needed -- subprocess.run itself is mocked, like
  test_runtime_timeout.py's suite.
  """

  from __future__ import annotations

  import subprocess
  from unittest.mock import patch

  import lalo.runtime.container as container_module
  from lalo.runtime import RuntimeConfig, RuntimeContainer


  def _completed(
      returncode: int = 0, stdout: str = "", stderr: str = ""
  ) -> subprocess.CompletedProcess[str]:
      return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


  def test_stop_after_failure_skips_removal_and_logs_a_hint_when_keep_on_failure_is_set() -> None:
      calls: list[list[str]] = []
      warnings: list[str] = []

      def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
          calls.append(argv)
          return _completed()

      def fake_warning(msg: str, *args: object) -> None:
          warnings.append(msg % args)

      with (
          patch("lalo.runtime.container._docker_bin", return_value="docker"),
          patch("lalo.runtime.container.subprocess.run", side_effect=fake_run),
          patch.object(container_module._log, "warning", side_effect=fake_warning),
      ):
          container = RuntimeContainer(RuntimeConfig(keep_on_failure=True))
          container._started = True  # noqa: SLF001 - simulate an already-started container
          container.stop(failed=True)

      assert not any(c[1] == "rm" for c in calls), "docker rm must be skipped when keep_on_failure fires"
      assert container.started is False
      assert any(
          container._name in w and "docker logs" in w and "docker rm" in w for w in warnings  # noqa: SLF001
      ), f"expected a docker logs/docker rm hint naming the container, got: {warnings!r}"


  def test_stop_after_failure_still_removes_when_keep_on_failure_is_left_at_its_default() -> None:
      calls: list[list[str]] = []

      def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
          calls.append(argv)
          return _completed()

      with (
          patch("lalo.runtime.container._docker_bin", return_value="docker"),
          patch("lalo.runtime.container.subprocess.run", side_effect=fake_run),
      ):
          container = RuntimeContainer(RuntimeConfig())  # keep_on_failure defaults to False
          container._started = True  # noqa: SLF001
          container.stop(failed=True)

      assert any(c[1] == "rm" for c in calls), "a failed run must still be removed when the flag is off"
      assert container.started is False


  def test_stop_after_success_always_removes_regardless_of_keep_on_failure() -> None:
      calls: list[list[str]] = []

      def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
          calls.append(argv)
          return _completed()

      with (
          patch("lalo.runtime.container._docker_bin", return_value="docker"),
          patch("lalo.runtime.container.subprocess.run", side_effect=fake_run),
      ):
          container = RuntimeContainer(RuntimeConfig(keep_on_failure=True))
          container._started = True  # noqa: SLF001
          container.stop()  # failed defaults to False -- a normal, successful teardown

      assert any(c[1] == "rm" for c in calls), "a successful run's container removal must be unaffected"
      assert container.started is False
  ```

  And one new end-to-end test appended to `tests/lalo/test_scan.py` (models the existing crash-injection shape already used by `test_resume_after_a_crash_does_not_redispatch_the_completed_step` at line ~1802, reusing the file's own `_CrashingProvider`/`ModelRouter`/`ScanConfig` — proves `ScanRunner.run()`'s `finally` block itself derives `failed` correctly from a real raised exception, not just that `RuntimeContainer.stop()` behaves correctly in isolation):

  ```python
  def test_scan_runner_stops_the_container_with_failed_true_when_the_run_raises(
      tmp_path: Path, monkeypatch: pytest.MonkeyPatch
  ) -> None:
      monkeypatch.setattr(scan_module, "docker_available", lambda: True)
      created: list[_FakeContainer] = []

      class _TrackingContainer(_FakeContainer):
          def __init__(self, config: object = None) -> None:
              super().__init__(config)
              created.append(self)

      monkeypatch.setattr(scan_module, "RuntimeContainer", _TrackingContainer)

      def _crash_on_the_first_mission_turn(_call_index: int, prompt: str) -> str:
          if "MISSION:" not in prompt:
              return "ok"  # the preflight verify_router() health-check call
          return "CRASH"  # well after container.start() -- inside the real mission

      router = ModelRouter(
          providers={"fake": _CrashingProvider(_crash_on_the_first_mission_turn)},
          routes={"reasoning": ("fake",)},
          default_route=("fake",),
      )
      monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

      config = ScanConfig(mission="find a bug", target_specs=["example.com"], run_dir=tmp_path / "run")
      with pytest.raises(RuntimeError, match="simulated crash"):
          ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

      assert len(created) == 1
      assert created[0].stopped_with_failed is True
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_runtime_keep_on_failure.py tests/lalo/test_scan.py::test_scan_runner_stops_the_container_with_failed_true_when_the_run_raises -v
  ```

  Expected failures before any implementation change:
  - `test_stop_after_failure_skips_removal_and_logs_a_hint_when_keep_on_failure_is_set` and `test_stop_after_success_always_removes_regardless_of_keep_on_failure` both fail at `RuntimeConfig(keep_on_failure=True)` with `TypeError: RuntimeConfig.__init__() got an unexpected keyword argument 'keep_on_failure'`.
  - `test_stop_after_failure_still_removes_when_keep_on_failure_is_left_at_its_default` fails at `container.stop(failed=True)` with `TypeError: RuntimeContainer.stop() got an unexpected keyword argument 'failed'`.
  - `test_scan_runner_stops_the_container_with_failed_true_when_the_run_raises` fails with `AssertionError: assert False is True` (`ScanRunner.run()` still calls the old zero-arg `container.stop()`, so the now-updated `_FakeContainer` fixture records `stopped_with_failed=False` — the fixture works, but nothing production-side sets it to `True` yet).

  (A regression test proving the success path stays unaffected is already covered at the unit level by `test_stop_after_success_always_removes_regardless_of_keep_on_failure`, which is genuinely red for the right reason above — a parallel scan.py-level "success" test was deliberately not added since it would pass even against the unmodified code, which isn't a valid TDD red step; see notes.)

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/runtime/container.py`, add the field next to `enable_vpn` (both are opt-in container-lifecycle toggles) and extend the class docstring:

  ```python
      cap_add: tuple[str, ...] = ()
      enable_vpn: bool = False
      keep_on_failure: bool = False
      log_max_size: str = "10m"
  ```

  Docstring addition, inserted right before the existing closing paragraph ("No restart policy is set on purpose..."):

  ```python
      ``keep_on_failure`` is a separate opt-in, read by :meth:`RuntimeContainer.stop`
      only when its caller passes ``failed=True`` (i.e. the run being torn down
      actually raised): skips the ``docker rm -f`` and logs a hint with the real
      container name instead of destroying the only copy of whatever was on disk
      or in the process list at failure time. Off by default, and irrelevant to a
      normal, successful ``stop()`` -- a run that completes cleanly is always
      removed exactly as before, regardless of this flag. Doesn't touch host
      isolation: the container still has zero bind-mounts, no Docker socket, and
      every cap-drop/cap-add rule this module already enforces -- this only
      delays removal of an already-isolated container, and only when explicitly
      asked for.
  ```

  Replace `stop()` (was lines 386-396):

  ```python
      def stop(self, *, failed: bool = False) -> None:
          if self._started:
              if failed and self.config.keep_on_failure:
                  # Opt-in (RuntimeConfig.keep_on_failure): the caller is telling
                  # us the run being torn down actually raised, so skip the
                  # removal and leave the container up for post-mortem
                  # inspection instead of destroying the only copy of whatever
                  # was on disk/running at failure time. A normal, successful
                  # stop() never passes failed=True, so this branch never fires
                  # on a healthy run -- that path always removes, unchanged.
                  _log.warning(
                      "runtime container %s kept alive after a failed run (keep_on_failure=True) -- "
                      "inspect with `docker logs %s`, remove with `docker rm -f %s` when done",
                      self._name,
                      self._name,
                      self._name,
                  )
              else:
                  try:
                      self._run(["rm", "-f", self._name], timeout=30)
                  except subprocess.TimeoutExpired:
                      _log.warning("removal of %s timed out; it may be orphaned", self._name)
                  _log.info("runtime container %s removed", self._name)
              # Either way, this wrapper no longer treats the container as usable —
              # a timed-out removal leaves its actual state unknown (and a
              # kept-alive container is intentionally off-limits to further
              # exec() calls too), and retrying exec() against it would be worse
              # than refusing further use.
              self._started = False
  ```

  In `src/lalo/scan.py`, add the import (alphabetical among the existing stdlib imports, was lines 120-122):

  ```python
  import json
  import sys
  import threading
  import time
  ```

  And change the teardown `finally` block (was lines 973-975):

  ```python
          finally:
              # sys.exc_info() is populated here whenever an exception is still
              # propagating through this finally clause (a plain `return` from
              # _run_inside() above clears it first) -- verified empirically,
              # this is the only signal available at this point for "did the
              # run actually fail" without restructuring the whole nested
              # try/finally chain into try/except/else. A successful run always
              # passes failed=False and is completely unaffected: container.stop()
              # always removes then, exactly as before. keep_on_failure itself is
              # an opt-in RuntimeConfig field the operator sets on
              # container_config (off by default) -- see RuntimeContainer.stop().
              container.stop(failed=sys.exc_info()[0] is not None)
              self._container = None
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_runtime_keep_on_failure.py tests/lalo/test_scan.py::test_scan_runner_stops_the_container_with_failed_true_when_the_run_raises tests/lalo/test_scan.py -v
  ```

  (The final bare `tests/lalo/test_scan.py` run is the regression check that the `_FakeContainer.stop()` signature change didn't break any of the ~40 other tests using that fixture.) All must pass; then run the project's own quality gates on the touched files:

  ```
  uv run ruff check src/lalo/runtime/container.py src/lalo/scan.py tests/lalo/test_scan.py tests/lalo/test_runtime_keep_on_failure.py
  uv run ruff format src/lalo/runtime/container.py src/lalo/scan.py tests/lalo/test_scan.py tests/lalo/test_runtime_keep_on_failure.py
  uv run mypy
  ```

- [ ] **Step 5: Commit**

  ```
  git add src/lalo/runtime/container.py src/lalo/scan.py tests/lalo/test_scan.py tests/lalo/test_runtime_keep_on_failure.py
  git commit -m "$(cat <<'EOF'
  feat(L4L0): opt-in flag to keep a failed run's container for post-mortem debugging

  RuntimeConfig.keep_on_failure (off by default) lets an operator skip the
  automatic docker rm -f when the run tearing a container down actually
  raised, logging a docker logs/docker rm hint with the real container name
  instead. A successful run is completely unaffected -- always removed, same
  as before. No change to host isolation: still zero bind-mounts, no docker
  socket, dropped caps -- this only delays removal of an already-isolated
  container, and only when explicitly asked for.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 11: Multi-hop, role-tagged `source_location` in SARIF code flows

**Files:**
- Modify: `src/lalo/findings/model.py:72` (the `Finding.source_location` field)
- Modify: `src/lalo/report/collect.py:73` (the parallel `FindingRecord.source_location` field — kept in lockstep so mypy strict has one consistent type across the pipeline; `collect_findings()` itself needs no logic change, it already passes the value through untouched)
- Modify: `src/lalo/report/sarif.py:101-136` (rewrite `_build_result`; add two new module-level helpers, `_physical_location` and `_code_flow`, immediately above it)
- Test: `tests/lalo/test_report_sarif.py` (append new tests after the existing `test_render_sarif_result_degrades_gracefully_on_a_malformed_source_location`, line 213)

**Interfaces:**
- Consumes: none (standalone; reads the existing `Finding`/`FindingRecord` dataclasses and `render_sarif`/`_build_result` in `report/sarif.py` as they exist today)
- Produces: `Finding.source_location: str | list[dict[str, str]] | None` and `FindingRecord.source_location: str | list[dict[str, str]] | None` — the hop shape any future caller (e.g. a source-aware-review tool) must use is `{"role": "<source|sink|guard|...>", "location": "path/to/file.py:123"}`. `report.sarif._build_result` now emits `result["codeFlows"]` (a `list[dict[str, Any]]`, one entry shaped `{"threadFlows": [{"locations": [...]}]}`) whenever ≥2 hops parse successfully; absent entirely otherwise. No other task depends on this yet — noted in the assembler notes as a natural extension point for `findings/tool.py`'s `record_finding` argument parsing, which is explicitly NOT touched by this task.

- [ ] **Step 1: Write the failing test**

  Append to `tests/lalo/test_report_sarif.py` (uses the file's existing `_file`/`_records` helpers and `replace` import, already present):

  ```python
  def test_render_sarif_result_has_no_code_flows_key_for_a_single_string_source_location() -> None:
      """Zero behavior change for the existing, common case."""
      graph = ReachabilityGraph()
      _file(graph, source_location="app/routes.py:42")
      doc = render_sarif(_records(graph))
      assert "codeFlows" not in doc["runs"][0]["results"][0]


  def test_render_sarif_result_emits_a_code_flow_for_a_multi_hop_source_location() -> None:
      graph = ReachabilityGraph()
      _file(graph)
      hops = [
          {"role": "source", "location": "app/routes.py:10"},
          {"role": "guard", "location": "app/auth.py:55"},
          {"role": "sink", "location": "app/db.py:88"},
      ]
      record = replace(_records(graph)[0], source_location=hops)
      doc = render_sarif([record])
      result = doc["runs"][0]["results"][0]

      thread_locations = result["codeFlows"][0]["threadFlows"][0]["locations"]
      assert [loc["location"]["message"]["text"] for loc in thread_locations] == [
          "source",
          "guard",
          "sink",
      ]
      first_physical = thread_locations[0]["location"]["physicalLocation"]
      assert first_physical["artifactLocation"]["uri"] == "app/routes.py"
      last_physical = thread_locations[-1]["location"]["physicalLocation"]
      assert last_physical["region"]["startLine"] == 88

      # the primary result location still gets a physicalLocation, pointing at
      # the last hop (the sink) - the same convention the single-string case
      # has always used for "the one point of interest"
      physical = next(
          loc["physicalLocation"] for loc in result["locations"] if "physicalLocation" in loc
      )
      assert physical["artifactLocation"]["uri"] == "app/db.py"


  def test_render_sarif_result_drops_an_unparseable_hop_from_the_code_flow() -> None:
      graph = ReachabilityGraph()
      _file(graph)
      hops = [
          {"role": "source", "location": "app/routes.py:10"},
          {"role": "sink", "location": "app/db.py:not-a-line-number"},
      ]
      record = replace(_records(graph)[0], source_location=hops)
      doc = render_sarif([record])
      result = doc["runs"][0]["results"][0]
      # only one hop survived parsing - no flow worth showing
      assert "codeFlows" not in result
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_report_sarif.py::test_render_sarif_result_emits_a_code_flow_for_a_multi_hop_source_location -v
  ```

  Fails today with `KeyError: 'codeFlows'` on the `result["codeFlows"][0]...` line — the current `_build_result` only ever checks `if record.source_location and ":" in record.source_location:`; against a `list[dict]` value, `":" in <list>` evaluates to `False` (no `TypeError` — Python's `in` just checks list membership), so the whole block is silently skipped and no `codeFlows` key is ever added. (Verified directly: probing the current code with a 2-hop list produces `locations == [{"logicalLocations": [...]}]` and `"codeFlows" in result == False`.)

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/findings/model.py`, widen the field (line 72):

  ```python
      identities_confirmed: list[str] = field(default_factory=list)
      # Either the single "path:line" case (unchanged since introduction), or,
      # for a traced multi-hop path, an ordered list of hops from source to
      # sink: [{"role": "source", "location": "app/routes.py:10"}, ...]. See
      # report/sarif.py, which renders a single string as one physicalLocation
      # (today's behavior, unchanged) and a multi-hop list as an additional
      # SARIF codeFlows/threadFlows block.
      source_location: str | list[dict[str, str]] | None = None
  ```

  In `src/lalo/report/collect.py`, widen the parallel field (line 73) the same way:

  ```python
      dedup_key: str = ""
      status: str = "open"
      source_location: str | list[dict[str, str]] | None = None
  ```

  In `src/lalo/report/sarif.py`, replace the existing `_build_result` (lines 101-136) with two new helpers plus the rewritten function:

  ```python
  def _physical_location(location: str) -> dict[str, Any] | None:
      """Parse a "path:line" string into a SARIF physicalLocation, or None if
      it doesn't parse - the same graceful-degrade the single-string case has
      always had, now shared by every hop in a multi-hop list too."""
      if ":" not in location:
          return None
      path, _, line_str = location.rpartition(":")
      if not line_str.isdigit():
          return None
      return {"artifactLocation": {"uri": path}, "region": {"startLine": int(line_str)}}


  def _code_flow(hops: list[dict[str, str]]) -> dict[str, Any] | None:
      """One SARIF codeFlow with a single threadFlow carrying every hop in
      order, source to sink - each hop's role becomes its threadFlowLocation's
      message so a viewer can label the step. A hop whose location doesn't
      parse is dropped (the same degrade-gracefully rule as everywhere else in
      this module); if fewer than two hops survive that there is no flow worth
      showing, so this returns None rather than emit a single-location "flow"."""
      thread_locations: list[dict[str, Any]] = []
      for hop in hops:
          physical = _physical_location(str(hop.get("location", "")))
          if physical is None:
              continue
          thread_locations.append(
              {
                  "location": {
                      "physicalLocation": physical,
                      "message": {"text": str(hop.get("role", ""))},
                  }
              }
          )
      if len(thread_locations) < 2:
          return None
      return {"threadFlows": [{"locations": thread_locations}]}


  def _build_result(record: FindingRecord, rule_index: int) -> dict[str, Any]:
      logical_name = record.target + (f"#{record.param}" if record.param else "")
      message = f"{record.title}\n\n{record.description}" if record.description else record.title
      locations: list[dict[str, Any]] = [
          {"logicalLocations": [{"fullyQualifiedName": logical_name, "kind": "target"}]}
      ]
      code_flows: list[dict[str, Any]] = []
      source_location = record.source_location
      if isinstance(source_location, list):
          # Multi-hop: the primary result location is still the last hop (by
          # convention the sink - the same point a single "path:line" string
          # has always pointed at), plus the full source-to-sink path as a
          # codeFlow for viewers that render one.
          flow = _code_flow(source_location)
          if flow is not None:
              code_flows.append(flow)
          if source_location:
              physical = _physical_location(str(source_location[-1].get("location", "")))
              if physical is not None:
                  locations.append({"physicalLocation": physical})
      elif source_location:
          physical = _physical_location(source_location)
          if physical is not None:
              locations.append({"physicalLocation": physical})

      result: dict[str, Any] = {
          "ruleId": _rule_id(record),
          "ruleIndex": rule_index,
          "level": _sarif_level(record),
          "message": {"text": message or record.finding_id, "markdown": _result_markdown(record)},
          "locations": locations,
          "partialFingerprints": {
              "lalo/dedupKey": dedup_key(record.vuln_class, record.target, record.param)
          },
          "properties": {
              "security-severity": _security_severity(record),
              "lalo": {
                  "confidence": record.confidence.score,
                  "cvss_vector": record.cvss_vector,
                  "evidence_grounded": record.evidence_grounded,
                  "review_verdict": record.review_verdict,
              },
          },
      }
      if code_flows:
          result["codeFlows"] = code_flows
      return result
  ```

  This is purely additive: the single-string branch (`elif source_location:`) runs the exact same two lines of logic the old code ran, so the three pre-existing source_location tests (`..._includes_physical_location_when_..._present`, `..._has_no_physical_location_when_..._absent`, `..._degrades_gracefully_on_a_malformed_...`) still pass unchanged with zero behavior difference.

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_report_sarif.py -q
  ```

  Expected: `21 passed` (the 18 pre-existing tests plus the 3 new ones added in Step 1). Also confirm no regressions in the two other modules whose dataclasses changed:

  ```
  uv run pytest tests/lalo/test_findings_model.py tests/lalo/test_findings_tool.py tests/lalo/test_report_collect.py -q
  ```

  Expected: all passing (41 tests across the three files, unaffected — no logic in `findings/tool.py`, `findings/model.py`'s validation, or `report/collect.py` changed, only two type annotations widened).

  Then the standing project gates:

  ```
  uv run ruff check src/lalo/findings/model.py src/lalo/report/collect.py src/lalo/report/sarif.py tests/lalo/test_report_sarif.py
  uv run ruff format --check src/lalo/findings/model.py src/lalo/report/collect.py src/lalo/report/sarif.py tests/lalo/test_report_sarif.py
  uv run mypy src/lalo/findings/model.py src/lalo/report/collect.py src/lalo/report/sarif.py
  ```

  Expected: all three clean (`All checks passed!`, `4 files already formatted`, `Success: no issues found in 3 source files`).

- [ ] **Step 5: Commit**

  ```
  git add src/lalo/findings/model.py src/lalo/report/collect.py src/lalo/report/sarif.py tests/lalo/test_report_sarif.py
  git commit -m "$(cat <<'EOF'
  feat(report): multi-hop role-tagged source_location renders as a SARIF code flow

  source_location on a Finding/FindingRecord can now optionally be an
  ordered list of {role, path:line} hops instead of a single string; the
  SARIF exporter renders two or more hops as a codeFlows/threadFlows block
  labeled by role, while the existing single-string case keeps rendering
  exactly one physicalLocation with no behavior change.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 12: Warn (never block) on merging credentials into a loosely-permissioned existing .env

**Files:**
- Modify: `src/lalo/setup.py:25-26` (add `import os` to the stdlib import block)
- Modify: `src/lalo/setup.py:58-59` (insert a new `_warn_if_permissive` helper between `_collect_env` and `main`)
- Modify: `src/lalo/setup.py:80` (call the helper immediately before the existing `merge_env_file(_ENV_PATH, env)` line)
- Test: `tests/lalo/test_setup.py:13` (add `_warn_if_permissive` to the existing `from lalo.setup import ...` line) and new test functions appended at the end of the file

**Interfaces:**
- Consumes: `lalo.setup._ENV_PATH` (existing module-level `Path`, already monkeypatched by other tests in this file), `lalo.core.env_file.merge_env_file(path: Path, values: dict[str, str]) -> None` (existing, unchanged — this task never touches its body)
- Produces: `lalo.setup._warn_if_permissive(path: Path) -> None` — stat's `path`, prints one informational line to stdout via `print()` (matching this file's existing style) when `os.stat(path).st_mode & 0o077 != 0`, otherwise prints nothing and returns. Pure side-effecting function, no return value, never raises for a permissive mode (only propagates if `os.stat` itself fails, e.g. the path vanishing mid-race — which callers already only invoke under `.exists()`).

- [ ] **Step 1: Write the failing test**

  Add `_warn_if_permissive` to the existing import line in `tests/lalo/test_setup.py`:
  ```python
  from lalo.setup import _collect_env, _prompt_provider, _warn_if_permissive, main
  ```
  Append these three tests to `tests/lalo/test_setup.py`:
  ```python
  def test_warn_if_permissive_prints_a_warning_for_a_group_readable_env_file(
      tmp_path: Path, capsys: pytest.CaptureFixture[str]
  ) -> None:
      path = tmp_path / ".env"
      path.write_text("ANTHROPIC_API_KEY=sk-ant-existing\n", encoding="utf-8")
      path.chmod(0o644)

      _warn_if_permissive(path)

      captured = capsys.readouterr()
      assert "chmod 600" in captured.out
      assert str(path) in captured.out


  def test_warn_if_permissive_is_silent_for_an_owner_only_env_file(
      tmp_path: Path, capsys: pytest.CaptureFixture[str]
  ) -> None:
      path = tmp_path / ".env"
      path.write_text("ANTHROPIC_API_KEY=sk-ant-existing\n", encoding="utf-8")
      path.chmod(0o600)

      _warn_if_permissive(path)

      captured = capsys.readouterr()
      assert captured.out == ""


  def test_main_warns_but_still_merges_into_a_loosely_permissioned_existing_env_file(
      tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
  ) -> None:
      env_path = tmp_path / ".env"
      env_path.write_text("OTHER=kept\n", encoding="utf-8")
      env_path.chmod(0o646)
      monkeypatch.setattr(lalo_setup, "_ENV_PATH", env_path)
      monkeypatch.setattr("builtins.input", lambda _prompt="": _menu_index_of("anthropic"))
      monkeypatch.setattr(lalo_setup.getpass, "getpass", lambda _prompt="": "sk-ant-real-key")
      monkeypatch.setattr(lalo_setup, "build_router", lambda _settings: object())
      monkeypatch.setattr(lalo_setup, "verify_router", lambda _router: {"anthropic": (True, "ok")})

      main()

      captured = capsys.readouterr()
      assert "chmod 600" in captured.out
      content = env_path.read_text(encoding="utf-8")
      assert "OTHER=kept" in content
      assert "ANTHROPIC_API_KEY=sk-ant-real-key" in content
      assert stat.S_IMODE(env_path.stat().st_mode) == 0o600
  ```
  The third test is the non-blocking proof: it starts from a `0o646` (group+other writable/readable) pre-existing `.env`, asserts the warning fired, and asserts the merge happened exactly as it does today (unrelated line preserved, new key written, final mode `0600` — that last part already comes for free from `atomic_write_verified`'s `os.replace` semantics, documented in `src/lalo/core/atomic_io.py:38-40`, and is asserted here only to prove the new check didn't change that behavior).

- [ ] **Step 2: Run test to verify it fails**
  ```
  uv run pytest tests/lalo/test_setup.py -v
  ```
  Expected failure (collection error, since the name doesn't exist yet):
  ```
  ImportError: cannot import name '_warn_if_permissive' from 'lalo.setup'
  ```

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/setup.py`, change the import block (current lines 25-26):
  ```python
  import getpass
  from pathlib import Path
  ```
  to:
  ```python
  import getpass
  import os
  from pathlib import Path
  ```

  Insert a new function after `_collect_env` (which currently ends at line 57) and before `def main()` (currently line 60):
  ```python
  def _warn_if_permissive(path: Path) -> None:
      """Informational only - never blocks or delays the merge that follows.

      A pre-existing ``.env`` that is group/other-readable may already have
      exposed whatever credentials it held before this run. The merge itself
      always ends up owner-only (0600) regardless, via
      ``atomic_write_verified``'s own os.replace semantics - but that doesn't
      undo any exposure that already happened, so we tell the operator and
      keep going exactly as before.
      """
      mode = os.stat(path).st_mode
      if mode & 0o077:
          print(
              f"! {path} is readable by group/other (mode {oct(mode & 0o777)}) - "
              f"run `chmod 600 {path}` to keep credentials private (continuing anyway)"
          )
  ```

  In `main()`, change the current line 80 from:
  ```python
      merge_env_file(_ENV_PATH, env)
  ```
  to:
  ```python
      if _ENV_PATH.exists():
          _warn_if_permissive(_ENV_PATH)
      merge_env_file(_ENV_PATH, env)
  ```
  This is the only call site touched. It runs strictly before the existing merge call, adds one stat() and (at most) one print(), and changes no other control flow — a fresh `.env` (the common first-run case) skips the check entirely via the `.exists()` guard, exactly as `merge_env_file` itself already special-cases "no file yet" internally.

- [ ] **Step 4: Run test to verify it passes**
  ```
  uv run pytest tests/lalo/test_setup.py -v
  ```
  All tests in the file, including the three new ones, pass.

- [ ] **Step 5: Commit**
  ```bash
  git add src/lalo/setup.py tests/lalo/test_setup.py
  git commit -m "$(cat <<'EOF'
  feat(setup): warn, never block, when an existing .env is group/other-readable

  lalo-setup now stats a pre-existing .env before merging a verified
  credential into it and prints an informational chmod-600 suggestion if
  group/other bits are set - purely advisory, the merge proceeds exactly as
  before either way. The post-merge file already ends up 0600 via the
  shared atomic-write primitive; this only flags that the file may have
  been readable by other local accounts before this run.
  EOF
  )"
  ```

**Notes:**
- No default restriction was introduced anywhere: the check cannot fail the run, cannot delay the write (it's one `os.stat` + at most one `print`, no sleep/confirmation/retry), and has no opt-out flag because there is nothing to opt out of — it only ever adds a print statement, matching the letter of the "informational, never blocking" requirement without needing a new knob.
- The three new tests are correctly scoped and runnable via `uv run pytest tests/lalo/test_setup.py -v` per this repo's "run only tests related to the change" convention; no full-suite run is part of this task.

---

### Task 13: Add a curated xAI provider entry

**Files:**
- Create: none
- Modify: `src/lalo/core/config.py:102-118` (insert a new `ProviderSpec` block immediately after the existing `gemini` entry, before the `custom` generic-slot comment)
- Test: `tests/lalo/test_config.py`

**Interfaces:**
- Consumes: none from earlier tasks (standalone, LOW-priority row addition). Reuses existing project machinery only: the `ProviderSpec` dataclass, the `CURATED_PROVIDERS` tuple, `_resolve_one`/`load_settings`, and the generic `OpenAICompatibleProvider` adapter in `src/lalo/core/providers.py` (confirmed by reading it: it POSTs to `f"{base_url}{path}"` with `path="/v1/chat/completions"` — so `base_url` must NOT itself end in `/v1`, exactly like the existing `openai` entry's `https://api.openai.com`). No new adapter code is written.
- Produces: one new curated row —
  `ProviderSpec(id="xai", kind="openai_compatible", candidate_key_envs=("XAI_API_KEY",), credential_hint="XAI_API_KEY", default_model="grok-4.6", default_base_url="https://api.x.ai", model_env="XAI_MODEL")`
  appended to `CURATED_PROVIDERS`. Any later task reaches it exactly like every other curated provider: `load_settings(env).get("xai") -> ResolvedProvider | None`, and it participates automatically in `Settings.missing_credential_hints()` and the `LALO_MODEL="xai:<model>"` pin-to-front override — no new code path, since both are generic over `CURATED_PROVIDERS`.

- [ ] **Step 1: Write the failing test**

  Add to `tests/lalo/test_config.py` (mirrors the existing generic-assertion style the file already uses for `openai`/`gemini`/`custom` — this codebase has no per-provider-named test function, each curated provider is instead exercised through `load_settings(...)`/`.get(...)` assertions, so this new test follows that same shape):

  ```python
  def test_xai_provider_resolves_openai_compatible_with_curated_defaults() -> None:
      settings = load_settings({"XAI_API_KEY": "xai-test-key"})
      xai = settings.get("xai")
      assert xai is not None
      assert xai.kind == "openai_compatible"
      assert xai.model == "grok-4.6"
      assert xai.base_url == "https://api.x.ai"  # adapter appends /v1/chat/completions itself
      assert xai.auth_header == "Authorization"
      assert xai.auth_prefix == "Bearer "

      overridden = load_settings({"XAI_API_KEY": "xai-test-key", "XAI_MODEL": "grok-4-fast"})
      assert overridden.get("xai").model == "grok-4-fast"  # type: ignore[union-attr]

      unconfigured = load_settings({})
      assert unconfigured.get("xai") is None
      assert unconfigured.missing_credential_hints()["xai"] == "XAI_API_KEY"
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_config.py -k test_xai_provider_resolves_openai_compatible_with_curated_defaults -v
  ```

  Expected failure (no `xai` id exists in `CURATED_PROVIDERS` yet, so `XAI_API_KEY` resolves nothing and `.get("xai")` returns `None`):
  ```
  AssertionError: assert None is not None
  ```
  raised at the `assert xai is not None` line.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/core/config.py`, insert a new entry into `CURATED_PROVIDERS` right after the existing `gemini` `ProviderSpec` (currently lines 102-110) and before the `# Generic slot for anything not curated above` comment (currently line 111):

  ```python
      ProviderSpec(
          id="xai",
          kind="openai_compatible",
          candidate_key_envs=("XAI_API_KEY",),
          credential_hint="XAI_API_KEY",
          default_model="grok-4.6",
          default_base_url="https://api.x.ai",
          model_env="XAI_MODEL",
      ),
  ```

  Confirmed live (WebSearch/WebFetch against `docs.x.ai` and `x.ai/api`, September 2026) rather than assumed: xAI's OpenAI-compatible endpoint is `https://api.x.ai/v1/chat/completions`, the operator-facing key env var is `XAI_API_KEY`, and the current flagship default model — the one xAI's own docs point operators at for general use including code — is `grok-4.6` (not the older `grok-4`/`grok-4-0709` ids, which are still-valid-but-superseded pinned snapshots). `default_base_url` is set to `https://api.x.ai` **without** a trailing `/v1` — `OpenAICompatibleProvider._post` already appends the literal path `/v1/chat/completions`, so including `/v1` in the base URL would double it into `/v1/v1/chat/completions` and break every request. This is the same convention the existing `openai` entry already uses (`https://api.openai.com`, not `https://api.openai.com/v1`).

  This is a pure data-row addition — zero new adapter code, no new `ProviderKind`, no change to `_resolve_one`, `load_settings`, or `providers.py`. No default restriction is introduced: like every other curated provider, `xai` resolves opportunistically only when `XAI_API_KEY` is present in the environment (env-first, informational absence via `missing_credential_hints()`), it adds no allowlist/gate/confirmation of any kind, and an operator who wants xAI/Grok under a different model id or via a proxy already has that today through the pre-existing generic `custom` provider slot — this task only makes it a first-class curated shortcut.

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_config.py -v
  ```

  All tests in the file pass, including the new `test_xai_provider_resolves_openai_compatible_with_curated_defaults` (scoped to the changed file only, per this project's "don't run the full suite by default" test convention).

- [ ] **Step 5: Commit**

  ```
  git add src/lalo/core/config.py tests/lalo/test_config.py
  git commit -m "$(cat <<'EOF'
  feat(config): add curated xAI provider entry

  xAI's Grok API speaks the same OpenAI chat/completions wire shape every
  other curated openai_compatible entry does, so this is a pure data row on
  CURATED_PROVIDERS -- zero new adapter code. Uses XAI_API_KEY/XAI_MODEL,
  base_url https://api.x.ai (no /v1 -- the shared adapter appends
  /v1/chat/completions itself), and grok-4.6 as the curated default model,
  confirmed against xAI's current docs rather than assumed.
  EOF
  )"
  ```

---

### Task 14: Durable, per-agent-attributed narrative log

**Files:**
- Create: `src/lalo/orchestrator/narrative.py`
- Modify: `src/lalo/orchestrator/__init__.py:11-23` (add the three new exports)
- Modify: `src/lalo/scan.py:179` (import) and `src/lalo/scan.py:1281-1283` (call site, immediately after `_write_trace_file`)
- Test: `tests/lalo/test_orchestrator_narrative.py` (new)
- Test: `tests/lalo/test_scan.py` (append one integration test after `test_scan_runner_durably_persists_events_even_with_no_live_event_log`, currently ending at line 1289)

**Interfaces:**
- Consumes: `core.atomic_io.atomic_write_verified(path: Path, data: bytes) -> None` (existing); `core.redaction.redact(text: str) -> str` (existing, the project's one universal secret-masking entry point); the on-disk shape `{"category": str, "payload": dict}` per line of `events.jsonl`, already written by `ScanRunner._emit` at `src/lalo/scan.py:817-834`.
- Produces: `render_narrative_line(category: str, payload: dict[str, Any]) -> str`, `render_narrative(run_dir: Path) -> str`, `write_narrative_log(run_dir: Path) -> Path` — all in `lalo.orchestrator.narrative`, re-exported from `lalo.orchestrator`. `write_narrative_log` is what any later task (a GUI download endpoint, a CLI flag) should call to get/refresh `run_dir/narrative.log`.

**Corrections to the task's own framing, found by actually reading the code:**
- No existing "control_char"/"sanitize" helper exists anywhere in this codebase — I grepped every variant (`control_char`, `sanitize`, `cntrl`, `strip_control`, `\x00`, `unicodedata.category`, plus function-def scans for `_sanit*`/`_clean_text`/`strip_control`) across `src/` and `tests/`. What actually exists is: (a) `core/redaction.py`'s `redact()` — masks secret-*shaped* substrings, unrelated to control characters; (b) `report/html.py`'s `_e()` — `html.escape()`, an HTML-injection defense meaningless for a plaintext file; (c) `execution/target.py`'s `_canonical_path_segments` and `execution/firer.py`'s `_pinned_url_and_host_header` — control-character rejection/stripping, but embedded in URL/path-scope validation logic, not exported as a reusable text sanitizer. There is nothing to reuse for "strip control characters from arbitrary free text before writing it to a log" — this task adds a five-line one (`_sanitize_line`, stdlib `re` only) rather than reusing a nonexistent helper, while still reusing `redact()` for the secret-masking half.
- Not every event carries `agent_id`: `"finding"` and `"chain"` events are graph-level (emitted once, after the whole spawn tree finishes, from `ScanRunner._run_inside`'s own review loop at `scan.py:1221-1243`) and never carried an agent attribution to begin with — `findings/tool.py`'s `build_record_finding_tool` never stamps the recording agent onto the finding node. `"steering"` events (operator-typed text) also carry no `agent_id`. The renderer treats these three explicitly (`"system"` for finding/chain, `"operator"` for steering) rather than assuming a universal `agent_id`.
- The root agent's real `agent_id` is **not** the literal string `"root"` — `AgentCoordinator.register_root` (`src/lalo/agent/spawn.py:204-209`) always mints a numbered `agent-N` id (`agent-1` for the root of any given run); `"root"` is only ever the display *name* passed alongside it. A first draft of the integration test below asserted `"[root]"` and failed for exactly this reason (see Step 2's real output) — fixed to assert `"[agent-1]"`.

**Design choice — rendered once at scan completion, not incrementally per event:**
Mirrors the existing `trace.json` precedent exactly (`scan.py`'s `_write_trace_file`/`_trace_summary`, called once at the very end of `_run_inside`): a small, whole-file, *derived* artifact is written once after the source data (there, `Tracer` spans; here, `events.jsonl`) is already fully durable, via `atomic_write_verified` — the same primitive every other whole-file run-directory artifact (the graph, every report format) already uses. The tradeoff is the one the project already accepted for `trace.json`: a scan that crashes before this point has no `narrative.log` yet, only the still-fully-durable `events.jsonl` a future call can replay from — never a lost fact, only a not-yet-rendered one. The alternative (append one line per event, inside `ScanRunner._emit`) was rejected: it would add work to `_emit`'s own locked hot path — already shared by every concurrently spawned child in a `spawn_agents` fan-out (`self._emit_lock`, `scan.py:698`) — for a purely cosmetic artifact, when a one-shot render of data that's already durable does the identical job with a smaller, more isolated diff and zero new locking considerations.

**Non-blocking-constraint check (per CLAUDE.md's safety posture):** this task adds no new default restriction of any kind — no line-count/size cap on the *run*, no gate on what an agent can do, nothing withheld from any existing artifact. The one numeric constant (`_MAX_LINE_CHARS = 300`, a per-*rendered-line* display truncation) only affects how one already-fully-captured, already-uncapped-elsewhere event renders in this one cosmetic, human-readability file — `events.jsonl` itself (the actual evidence record) is completely untouched and un-truncated by this feature.

- [x] **Step 1: Write the failing tests**

  `tests/lalo/test_orchestrator_narrative.py` (new file):

  ```python
  """Unit coverage for the per-agent-attributed narrative renderer."""

  from __future__ import annotations

  from pathlib import Path

  from lalo.orchestrator.narrative import render_narrative, render_narrative_line, write_narrative_log


  def test_tool_call_renders_as_agent_attributed_method_and_url() -> None:
      line = render_narrative_line(
          "log",
          {
              "agent_id": "agent-3",
              "event": "tool_call",
              "tool": "http",
              "args": {"method": "GET", "url": "https://example.com/api"},
          },
      )
      assert line == "[agent-3] tool_call: http GET https://example.com/api"


  def test_embedded_newline_and_control_char_collapse_to_one_line() -> None:
      line = render_narrative_line(
          "log",
          {
              "agent_id": "agent-1",
              "event": "tool_result",
              "tool": "run_command",
              "ok": True,
              "observation": "line1\nline2\x07",
          },
      )
      assert "\n" not in line
      assert "\x07" not in line
      assert "line1" in line
      assert "line2" in line


  def test_a_secret_shaped_observation_is_redacted() -> None:
      jwt = (
          "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
          "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
      )
      line = render_narrative_line(
          "log",
          {
              "agent_id": "agent-2",
              "event": "tool_result",
              "tool": "http",
              "ok": True,
              "observation": f"set-cookie session={jwt}",
          },
      )
      assert jwt not in line
      assert "«REDACTED»" in line


  def test_a_finding_event_has_no_fabricated_agent_id() -> None:
      line = render_narrative_line(
          "finding",
          {
              "finding_id": "finding-1",
              "title": "SQLi in /login",
              "severity": "high",
              "confidence": 82,
              "verdict": "confirmed",
          },
      )
      assert line.startswith("[system] finding:")
      assert "finding-1" in line
      assert "SQLi in /login" in line


  def test_render_narrative_on_a_missing_events_file_is_empty(tmp_path: Path) -> None:
      assert render_narrative(tmp_path / "no-such-run") == ""


  def test_render_narrative_replays_real_events_jsonl_in_order(tmp_path: Path) -> None:
      run_dir = tmp_path / "run"
      run_dir.mkdir()
      (run_dir / "events.jsonl").write_text(
          '{"category": "status", "payload": {"event": "scan_started", "targets": ["x"]}}\n'
          '{"category": "log", "payload": {"agent_id": "root", "event": "tool_call", '
          '"tool": "http", "args": {"method": "GET", "url": "https://x/"}}}\n',
          encoding="utf-8",
      )
      rendered = render_narrative(run_dir)
      lines = rendered.splitlines()
      assert len(lines) == 2
      assert lines[0].startswith("[system] scan_started:")
      assert lines[1] == "[root] tool_call: http GET https://x/"


  def test_write_narrative_log_persists_owner_only_to_the_run_dir(tmp_path: Path) -> None:
      run_dir = tmp_path / "run"
      run_dir.mkdir()
      (run_dir / "events.jsonl").write_text(
          '{"category": "status", "payload": {"event": "scan_started", "targets": ["x"]}}\n',
          encoding="utf-8",
      )
      path = write_narrative_log(run_dir)
      assert path == run_dir / "narrative.log"
      assert path.exists()
      assert oct(path.stat().st_mode)[-3:] == "600"
      assert "scan_started" in path.read_text(encoding="utf-8")
  ```

  Append to `tests/lalo/test_scan.py` (right after `test_scan_runner_durably_persists_events_even_with_no_live_event_log`, before `test_load_run_events_on_a_missing_file_is_an_empty_log`):

  ```python
  def test_scan_runner_writes_a_per_agent_attributed_narrative_log(
      tmp_path: Path, monkeypatch: pytest.MonkeyPatch
  ) -> None:
      """A real scan's own tool_call/tool_result narration must land as a
      readable, agent-attributed plaintext file in the run directory - the
      only durable record of a run before this was raw events.jsonl."""
      monkeypatch.setattr(scan_module, "docker_available", lambda: True)
      monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)
      router = ModelRouter(
          providers={"fake": _ScriptedProvider(_respond)},
          routes={"reasoning": ("fake",), "review": ("fake",)},
          default_route=("fake",),
      )
      monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

      run_dir = tmp_path / "run"
      config = ScanConfig(mission="find a bug", target_specs=["example.com"], run_dir=run_dir)
      ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

      narrative_path = run_dir / "narrative.log"
      assert narrative_path.exists()
      assert oct(narrative_path.stat().st_mode)[-3:] == "600"
      narrative = narrative_path.read_text(encoding="utf-8")
      # The root agent's real agent_id is "agent-1" (AgentCoordinator.register_root
      # mints a numbered "agent-N" id for every node, root included - "root" is
      # only ever a display name, never an id) - asserting the real id, not the
      # display name, is the whole point of this feature.
      assert "[agent-1]" in narrative
      assert "scan_started" in narrative
  ```

- [x] **Step 2: Run tests to verify they fail**

  ```
  uv run pytest tests/lalo/test_orchestrator_narrative.py tests/lalo/test_scan.py::test_scan_runner_writes_a_per_agent_attributed_narrative_log -q
  ```

  Real captured output (module doesn't exist yet, so collection itself fails):
  ```
  ImportError while importing test module '.../tests/lalo/test_orchestrator_narrative.py'.
  Traceback:
  .../test_orchestrator_narrative.py:7: in <module>
      from lalo.orchestrator.narrative import render_narrative, render_narrative_line, write_narrative_log
  E   ModuleNotFoundError: No module named 'lalo.orchestrator.narrative'
  ```
  (The `test_scan.py` addition, run alone once the module exists but before scan.py is wired, fails differently and just as really — actually verified during drafting: `assert False\n where False = exists()\n where exists = PosixPath('.../run/narrative.log').exists` — i.e. `narrative_path.exists()` is `False` because nothing yet calls `write_narrative_log`.)

- [x] **Step 3: Write the minimal implementation**

  Create `src/lalo/orchestrator/narrative.py`:

  ```python
  """Render a run's durable ``events.jsonl`` into a plaintext, per-agent-
  attributed narrative log.

  Every event ``ScanRunner._emit`` durably persists already carries a real
  ``agent_id`` (or is unambiguously operator/system-scoped: ``finding``/
  ``chain`` are graph-level, not per-agent; ``steering`` is the operator's own
  text) — but the only durable record of a run today is the raw JSON stream
  itself. Nothing renders it as something a human can actually read top to
  bottom and know which agent did what. This module closes that gap with a
  pure rendering layer over already-captured data: it invents no new fact
  about a run, it only re-presents facts events.jsonl already recorded.

  **Timing: rendered once, at scan completion — not incrementally per event.**
  This mirrors ``trace.json``'s own precedent exactly (see ``scan.py``'s
  ``_write_trace_file``/``_trace_summary``): a small, whole-file, *derived*
  artifact written once after the run's own real-time data (there, Tracer
  spans; here, events.jsonl) is already fully captured, using
  ``atomic_write_verified`` like every other whole-file run-directory artifact,
  rather than an append-only per-line writer like ``events.jsonl``/
  ``journal.jsonl`` use. The tradeoff is the same one the project already
  accepted for trace.json: a scan that crashes before reaching this point
  has no narrative.log yet, only the still-durable events.jsonl a future
  render can replay — never a lost fact, only a not-yet-rendered one. An
  append-per-event alternative was considered and rejected: it would require
  touching ScanRunner._emit's own locked hot path (already shared by every
  concurrently spawned child in a spawn_agents fan-out) for a purely-cosmetic
  artifact, when a cheap, correct, one-shot render of already-durable data
  does the same job with a smaller, more isolated diff.

  **Sanitization.** ``core.redaction.redact`` (the project's one universal
  secret-masking entry point — see its own module docstring) is reused as-is
  for secret-shaped substrings. No existing helper anywhere in the codebase
  strips control characters or embedded newlines from arbitrary agent-
  controlled free text, though — ``core.redaction`` only recognizes secret
  *shapes*, and ``report/html.py``'s own ``html.escape``-based ``_e()`` is an
  HTML-injection defense meaningless for a plaintext file. A minimal one
  (``_sanitize_line``, five lines of stdlib ``re``) is added here rather than
  reused from elsewhere, because there is nowhere to reuse it from. It closes
  two real risks specific to a plaintext, one-line-per-event log: an
  attacker-controlled response body or header captured verbatim into a tool
  observation could otherwise embed its own ``\\n[agent-1] ...``-shaped text
  and forge what reads as a second, differently-attributed narrative line
  inside what is actually a single event; and a raw control/ANSI byte could
  corrupt a terminal a human later ``cat``s/``less``s this file in.
  """

  from __future__ import annotations

  import json
  import re
  from pathlib import Path
  from typing import Any

  from ..core.atomic_io import atomic_write_verified
  from ..core.redaction import redact

  _CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

  # One narrative line stays scannable rather than becoming its own multi-KB
  # blob - an observation is already capped well below this by
  # agent/loop.py's own _MAX_EMITTED_OBSERVATION_CHARS (2000) before it ever
  # reaches events.jsonl, but this line-level cap is what actually keeps a
  # *rendered* line skimmable regardless of what any given payload contains.
  _MAX_LINE_CHARS = 300

  # Categories with no real per-agent author (see this module's own docstring)
  # get an explicit, honest placeholder instead of a fabricated agent_id.
  _SYSTEM_CATEGORIES = frozenset({"finding", "chain"})


  def _sanitize_line(text: str) -> str:
      """Collapse embedded newlines/control characters and mask secret-shaped
      substrings — see this module's own docstring for why both are needed."""
      collapsed = text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " | ")
      collapsed = _CONTROL_CHARS_RE.sub("", collapsed)
      return redact(collapsed).strip()


  def _compact_args(args: dict[str, Any]) -> str:
      """``{"method": "GET", "url": "..."}`` -> ``"GET ..."`` (the common,
      HTTP-shaped tool-call case this project's own tools overwhelmingly use);
      any other shape falls back to plain, sorted ``key=value`` pairs."""
      if "method" in args and "url" in args:
          rest = {k: v for k, v in args.items() if k not in ("method", "url")}
          extra = " ".join(f"{k}={v}" for k, v in sorted(rest.items(), key=str))
          return f"{args['method']} {args['url']}" + (f" {extra}" if extra else "")
      return " ".join(f"{k}={v}" for k, v in sorted(args.items(), key=str))


  def _generic_detail(payload: dict[str, Any], *, skip: frozenset[str]) -> str:
      return " ".join(f"{k}={v}" for k, v in sorted(payload.items(), key=str) if k not in skip)


  def render_narrative_line(category: str, payload: dict[str, Any]) -> str:
      """One human-readable, agent-attributed line for a single durably-emitted
      ``(category, payload)`` event pair — the exact shape every line of
      ``events.jsonl`` stores under its own ``"category"``/``"payload"`` keys.

      Never raises on an unrecognized category or a missing expected field —
      an events.jsonl written by a future version of this codebase with a new
      event shape falls back to a plain, generic rendering rather than
      breaking every other line's narrative.
      """
      agent_id = (
          "system" if category in _SYSTEM_CATEGORIES else str(payload.get("agent_id", "system"))
      )
      if category == "steering":
          agent_id = "operator"
      event = str(payload.get("event", category))
      skip = frozenset({"agent_id", "event"})

      if category == "log" and event == "tool_call" and isinstance(payload.get("args"), dict):
          detail = f"{payload.get('tool', '?')} {_compact_args(payload['args'])}"
      elif category == "log" and event == "tool_result":
          detail = (
              f"{payload.get('tool', '?')} ok={payload.get('ok')} "
              f"{payload.get('observation', '')}"
          )
      elif category == "agent":
          detail = (
              f"{payload.get('name', '?')} status={payload.get('status', '?')} "
              f"task={payload.get('task', '')}"
          )
      elif category == "finding":
          detail = (
              f"{payload.get('finding_id', '?')} {payload.get('title', '')} "
              f"severity={payload.get('severity')} confidence={payload.get('confidence')} "
              f"verdict={payload.get('verdict')}"
          )
      elif category == "chain":
          detail = "nodes=" + ",".join(str(n) for n in payload.get("node_ids", []))
      elif category == "steering":
          detail = str(payload.get("text", ""))
      else:
          detail = _generic_detail(payload, skip=skip)

      line = _sanitize_line(f"[{agent_id}] {event}: {detail}".strip())
      if len(line) > _MAX_LINE_CHARS:
          line = line[: _MAX_LINE_CHARS - 1] + "…"
      return line


  def _events_path(run_dir: Path) -> Path:
      return run_dir / "events.jsonl"


  def _narrative_path(run_dir: Path) -> Path:
      return run_dir / "narrative.log"


  def render_narrative(run_dir: Path) -> str:
      """Replay ``run_dir``'s durable ``events.jsonl`` into a full plaintext
      narrative — one attributed line per event, in original emission order.

      A missing file or a torn final line from a crash mid-write are never
      fatal, mirroring ``DurableJournal``/``load_run_events``'s own already-
      established crash-tolerant reload behavior elsewhere in this codebase.
      """
      path = _events_path(run_dir)
      if not path.exists():
          return ""
      lines: list[str] = []
      for raw_line in path.read_text(encoding="utf-8").splitlines():
          raw_line = raw_line.strip()
          if not raw_line:
              continue
          try:
              record = json.loads(raw_line)
          except (json.JSONDecodeError, ValueError):
              continue
          if not isinstance(record, dict):
              continue
          category, payload = record.get("category"), record.get("payload")
          if isinstance(category, str) and isinstance(payload, dict):
              lines.append(render_narrative_line(category, payload))
      return "\n".join(lines) + ("\n" if lines else "")


  def write_narrative_log(run_dir: Path) -> Path:
      """Render and durably write ``run_dir / "narrative.log"``, replacing any
      prior version — called once, at scan completion (see
      ``ScanRunner._run_inside``), after ``events.jsonl`` already holds every
      event this run will ever emit.

      Routed through :func:`atomic_write_verified` like every other whole-file
      derived run-directory artifact (``trace.json``, the graph, every report
      format) — this file is fully regenerable from ``events.jsonl`` at any
      time, so a plain whole-file replace-and-verify is the right shape here,
      unlike ``events.jsonl``/``journal.jsonl`` themselves.
      """
      path = _narrative_path(run_dir)
      atomic_write_verified(path, render_narrative(run_dir).encode("utf-8"))
      return path
  ```

  Modify `src/lalo/orchestrator/__init__.py` — add the narrative import and its three exports:

  ```diff
   from .budget import Budget, BudgetBand, RunStatus
   from .journal import Checkpoint, DurableJournal
  +from .narrative import render_narrative, render_narrative_line, write_narrative_log
   from .scheduler import ScanSchedule, due_schedules

   __all__ = [
       "Budget",
       "BudgetBand",
       "Checkpoint",
       "DurableJournal",
       "RunStatus",
       "ScanSchedule",
       "due_schedules",
  +    "render_narrative",
  +    "render_narrative_line",
  +    "write_narrative_log",
   ]
  ```

  Modify `src/lalo/scan.py` — one import line (next to the other `orchestrator` imports, `scan.py:178-179`):

  ```diff
   from .orchestrator.budget import Budget, RunStatus
   from .orchestrator.journal import DurableJournal
  +from .orchestrator.narrative import write_narrative_log
  ```

  and one call, immediately after `_write_trace_file` (`scan.py:1281-1283`, right before `completed_payload` is built):

  ```diff
           graph.save(self.config.run_dir / "graph.json")
           _write_trace_file(self.config.run_dir, tracer)
  +        write_narrative_log(self.config.run_dir)
           completed_payload: dict[str, object] = {
  ```

- [x] **Step 4: Run tests to verify they pass**

  ```
  uv run pytest tests/lalo/test_orchestrator_narrative.py tests/lalo/test_scan.py::test_scan_runner_writes_a_per_agent_attributed_narrative_log -q
  ```

  Real captured output: `8 passed in 1.45s`

  Also verified the full related suite stays green and quality gates pass (all actually run, not assumed):
  ```
  uv run pytest tests/lalo/test_scan.py tests/lalo/test_orchestrator.py tests/lalo/test_orchestrator_narrative.py -q
  ```
  → `101 passed in 24.27s`
  ```
  uv run ruff check src/lalo/orchestrator/narrative.py src/lalo/orchestrator/__init__.py src/lalo/scan.py tests/lalo/test_orchestrator_narrative.py tests/lalo/test_scan.py
  ```
  → `All checks passed!` (after wrapping two lines that first came in at 101/102 chars over the project's 100-char limit)
  ```
  uv run mypy src/lalo/orchestrator/narrative.py src/lalo/scan.py src/lalo/orchestrator/__init__.py
  ```
  → `Success: no issues found in 3 source files`

- [x] **Step 5: Commit**

  ```
  git add src/lalo/orchestrator/narrative.py src/lalo/orchestrator/__init__.py src/lalo/scan.py tests/lalo/test_orchestrator_narrative.py tests/lalo/test_scan.py
  git commit -m "$(cat <<'EOF'
  feat(L4L0): durable, per-agent-attributed narrative log

  Renders every run's already-durable events.jsonl into a plaintext
  narrative.log at scan completion - one line per event, prefixed with
  its real agent_id, control characters and embedded newlines collapsed
  (closing a log-injection/terminal-corruption gap no existing helper
  covered), secret-shaped substrings redacted via the existing shared
  redactor. events.jsonl was previously the only durable per-run record,
  and nothing rendered it as something a human could actually read.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 15: `email_login` credential shape + IMAP-fetch agent tool for magic-link/OTP flows

**Files:**
- Create: `src/lalo/identity/email_tool.py`
- Create: `tests/lalo/test_email_tool.py`
- Modify: `src/lalo/identity/credentials.py:51-57` (insert a new `EmailAccount` dataclass between the existing `Identity` dataclass and `IdentityStore`)
- Modify: `src/lalo/identity/__init__.py:1-32` (re-export `EmailAccount` and `build_email_fetch_tool`, matching every other identity symbol's existing re-export)
- Modify: `src/lalo/scan.py:171-173` (imports), `src/lalo/scan.py:222-223` (new `ScanConfig.email_accounts` field), `src/lalo/scan.py:1158-1163` (tool wiring in `_build_registry`)
- Test: `tests/lalo/test_identity.py` (one new test, alongside the existing `test_adding_an_identity_registers_its_credential_for_universal_redaction`)

**Interfaces:**
- Consumes: `shared_redactor().register_secret(value: str) -> None` (existing, `lalo.core.redaction`) — the same construction-time registration guarantee Task 1 applied to `LoginScheme.totp_secret`, applied here to a different credential shape. `FunctionTool`, `ToolResult`, `str_arg(args, key, default="") -> str` (existing, `lalo.agent.tools`). None of this task's own code is consumed by Task 1 or vice versa — the two credential shapes are independent.
- Produces: `lalo.identity.credentials.EmailAccount` — a frozen dataclass `(address: str, password: str, imap_host: str, imap_port: int = 993)` whose `__post_init__` registers `self.password` with `shared_redactor()`. `lalo.identity.email_tool.build_email_fetch_tool(accounts: dict[str, EmailAccount]) -> FunctionTool`, producing a tool named `"fetch_email_code"`. `ScanConfig.email_accounts: dict[str, EmailAccount]` (new field, default `{}`). Both `EmailAccount` and `build_email_fetch_tool` are re-exported from `lalo.identity`.

**Design/scope notes (read before implementing):**

1. **Not routed through `Identity`/`IdentityStore`/`LoginScheme`.** An IMAP mailbox credential authenticates to a *mailbox*, not to the engagement target — folding it into `Credential`/`CredentialKind` (whose `Credential.value` is a single string) would either force a fake single-string encoding of four fields, or bloat `Credential` with IMAP-specific optional fields that every other kind (`PASSWORD`/`BEARER_TOKEN`/`API_KEY`/`COOKIE`) would carry unused. `EmailAccount` is the "or equivalent identity shape" the brief allows for, kept as its own small dataclass with its own `dict[str, EmailAccount]` map on `ScanConfig` — the identical independent-map convention `identities`/`login_schemes` already use (see `ScanConfig`'s own comment on why those two are separate maps rather than one). **`CredentialKind` is deliberately left untouched** — adding an `EMAIL_LOGIN` tag nothing ever reads would be exactly the unused-enum-member `Credential`/`CredentialKind` doesn't have room for and this design doesn't need.
2. **Only `password` is registered with the redactor — not `address`, `imap_host`, or `imap_port`.** The brief says "register every one of these (especially the password)"; the actual established precedent (re-read in `credentials.py`) only ever registers the *secret value*, never the identifying label next to it — `IdentityStore.add()` registers `identity.credential.value` but never `identity.username`. `address` here is the mailbox's username-equivalent (an operator needs to see which mailbox a `fetch_email_code` observation came from), and `imap_host`/`imap_port` are connection parameters, not secrets (registering a port number would also be a no-op: `register_secret` skips anything under 6 characters). Blanket-registering all four would make tool observations like `"connected to imap.gmail.com:993"` illegibly redacted for no security benefit. Only `password` is registered, matching the `Credential`/`Identity` precedent exactly.
3. **No new blocking validation.** Per the project's non-blocking-knobs constraint: an unknown `account`, an unparseable `pattern` regex, no matching message, a fetch/login failure, and an unmatched body are all reported as a normal failed `ToolResult` (`ok=False`) the agent can react to — never a raised exception that stops the loop, and nothing here gates whether the tool exists (it's simply absent from the registry when `self.config.email_accounts` is empty, exactly like `login_as`/`check_session_valid` are absent when `identities` is empty).
4. **Scan-wiring test scope call:** no sibling identity tool (`login_as`, `check_session_valid`) has a dedicated `test_scan.py` unit test asserting it appears in `_build_registry`'s tool list — `_build_registry` is a local closure, only exercised indirectly through full `ScanRunner.run()` runs. This task matches that existing precedent (a mechanical one-line `if self.config.email_accounts: tools.append(...)`, identical in shape to the `if identities.ids():` line right above it) rather than inventing new scan-level integration-test scaffolding no other identity tool has either. The full `tests/lalo/test_scan.py` suite still gets run in Step 4 as a non-breaking check.

- [ ] **Step 1: Write the failing tests**

  In `tests/lalo/test_identity.py`, change the existing imports and add one test:

  ```python
  from lalo.core.redaction import REDACTION_PLACEHOLDER, redact, shared_redactor
  from lalo.identity import Credential, CredentialKind, EmailAccount, Identity, IdentityStore, build_role_matrix
  ```

  ```python
  def test_constructing_an_email_account_registers_its_password_for_universal_redaction() -> None:
      EmailAccount(
          address="victim@example.com",
          password="MailboxSecretPass123456",
          imap_host="imap.example.com",
      )
      assert "MailboxSecretPass123456" not in shared_redactor().redact("MailboxSecretPass123456")
  ```

  Create `tests/lalo/test_email_tool.py`:

  ```python
  """Tests for the fetch_email_code agent tool: IMAP read for magic-link/OTP flows."""

  from __future__ import annotations

  import pytest

  from lalo.identity.credentials import EmailAccount
  from lalo.identity.email_tool import build_email_fetch_tool

  _RAW_MESSAGE = (
      b"From: noreply@example.com\r\n"
      b"To: victim@example.com\r\n"
      b"Subject: Your verification code\r\n"
      b"Content-Type: text/plain; charset=utf-8\r\n"
      b"\r\n"
      b"Your one-time code is 482913. It expires in 10 minutes.\r\n"
  )


  class _FakeImap4Ssl:
      """Stands in for imaplib.IMAP4_SSL -- same call surface, no real socket."""

      instances: list["_FakeImap4Ssl"] = []
      search_result: tuple[str, list[bytes]] = ("OK", [b"1 2 3"])

      def __init__(self, host: str, port: int) -> None:
          self.host = host
          self.port = port
          self.logged_in: tuple[str, str] | None = None
          self.logged_out = False
          type(self).instances.append(self)

      def login(self, user: str, password: str) -> tuple[str, list[bytes]]:
          self.logged_in = (user, password)
          return "OK", [b"LOGIN completed"]

      def select(self, mailbox: str) -> tuple[str, list[bytes]]:
          return "OK", [b"1"]

      def search(self, charset: str | None, *criteria: str) -> tuple[str, list[bytes]]:
          return type(self).search_result

      def fetch(self, msg_id: bytes, parts: str) -> tuple[str, list[object]]:
          return "OK", [(b"3 (RFC822 {%d}" % len(_RAW_MESSAGE), _RAW_MESSAGE)]

      def logout(self) -> tuple[str, list[bytes]]:
          self.logged_out = True
          return "BYE", [b"logging out"]


  class _EmptyMailboxImap4Ssl(_FakeImap4Ssl):
      search_result = ("OK", [b""])


  def _account() -> EmailAccount:
      return EmailAccount(
          address="victim@example.com",
          password="MailboxSecretPass123456",
          imap_host="imap.example.com",
      )


  @pytest.fixture(autouse=True)
  def _reset_fake_instances() -> None:
      _FakeImap4Ssl.instances.clear()
      yield


  def test_fetch_email_code_extracts_the_regex_match(monkeypatch: pytest.MonkeyPatch) -> None:
      import lalo.identity.email_tool as email_tool_module

      monkeypatch.setattr(email_tool_module.imaplib, "IMAP4_SSL", _FakeImap4Ssl)
      tool = build_email_fetch_tool({"victim": _account()})

      result = tool.run(
          {
              "account": "victim",
              "subject_contains": "verification",
              "pattern": r"one-time code is (\d+)",
          }
      )

      assert result.ok is True
      assert result.observation == "extracted: 482913"
      assert _FakeImap4Ssl.instances[0].logged_in == (
          "victim@example.com",
          "MailboxSecretPass123456",
      )
      assert _FakeImap4Ssl.instances[0].logged_out is True


  def test_fetch_email_code_reports_no_match_without_crashing(
      monkeypatch: pytest.MonkeyPatch,
  ) -> None:
      import lalo.identity.email_tool as email_tool_module

      monkeypatch.setattr(email_tool_module.imaplib, "IMAP4_SSL", _FakeImap4Ssl)
      tool = build_email_fetch_tool({"victim": _account()})

      result = tool.run({"account": "victim", "pattern": r"NOPE-(\d+)"})

      assert result.ok is False
      assert "did not match" in result.observation


  def test_fetch_email_code_reports_no_messages_matched(monkeypatch: pytest.MonkeyPatch) -> None:
      import lalo.identity.email_tool as email_tool_module

      monkeypatch.setattr(email_tool_module.imaplib, "IMAP4_SSL", _EmptyMailboxImap4Ssl)
      tool = build_email_fetch_tool({"victim": _account()})

      result = tool.run({"account": "victim", "pattern": r"(\d+)"})

      assert result.ok is False
      assert "no messages matched" in result.observation


  def test_fetch_email_code_rejects_an_unknown_account(monkeypatch: pytest.MonkeyPatch) -> None:
      import lalo.identity.email_tool as email_tool_module

      monkeypatch.setattr(email_tool_module.imaplib, "IMAP4_SSL", _FakeImap4Ssl)
      tool = build_email_fetch_tool({"victim": _account()})

      result = tool.run({"account": "nope", "pattern": r"(\d+)"})

      assert result.ok is False
      assert "unknown email account" in result.observation


  def test_fetch_email_code_requires_account_and_pattern() -> None:
      tool = build_email_fetch_tool({"victim": _account()})
      assert tool.run({"pattern": r"(\d+)"}).ok is False
      assert tool.run({"account": "victim"}).ok is False


  def test_fetch_email_code_rejects_an_invalid_regex() -> None:
      tool = build_email_fetch_tool({"victim": _account()})
      result = tool.run({"account": "victim", "pattern": "("})
      assert result.ok is False
      assert "invalid" in result.observation.lower()
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```
  uv run pytest tests/lalo/test_identity.py tests/lalo/test_email_tool.py -v
  ```

  Expected failure: `tests/lalo/test_identity.py` fails to collect with
  `ImportError: cannot import name 'EmailAccount' from 'lalo.identity'
  (.../src/lalo/identity/__init__.py)`; `tests/lalo/test_email_tool.py` fails to collect with
  `ModuleNotFoundError: No module named 'lalo.identity.email_tool'` (and, once that module exists
  but before `EmailAccount` does, `ImportError: cannot import name 'EmailAccount' from
  'lalo.identity.credentials'`).

- [ ] **Step 3: Write the minimal implementation**

  In `src/lalo/identity/credentials.py`, insert between the `Identity` dataclass (ends at line 56)
  and `class IdentityStore` (line 58):

  ```python
  @dataclass(frozen=True)
  class EmailAccount:
      """An IMAP mailbox an agent can read to complete a target's magic-link/OTP
      login flow.

      Deliberately NOT a `Credential`/`CredentialKind` pairing threaded through
      `Identity`: nothing here authenticates to the engagement target itself
      (it authenticates to a mailbox), so folding it into the target-login
      credential model would blur two genuinely different secrets under one
      shape. Kept on its own map (`ScanConfig.email_accounts`, the same
      independent-map convention `identities`/`login_schemes` already use) and
      consumed only by :func:`~lalo.identity.email_tool.build_email_fetch_tool`.

      Only `password` is registered with the shared redactor -- matching
      `Identity`/`Credential`'s own precedent of registering the secret value
      but never the identifying label next to it (`identity.username` is never
      registered either). `address` is this account's username-equivalent and
      `imap_host`/`imap_port` are connection parameters, not secrets.
      """

      address: str
      password: str  # noqa: S105 - a dataclass field name, not a literal secret
      imap_host: str
      imap_port: int = 993

      def __post_init__(self) -> None:
          # Registered at construction -- the same guarantee IdentityStore.add()
          # gives Credential.value, applied here since this shape has no
          # equivalent "add to a store" call of its own to hang the
          # registration off of.
          shared_redactor().register_secret(self.password)
  ```

  Create `src/lalo/identity/email_tool.py`:

  ```python
  """``fetch_email_code`` agent tool -- IMAP mailbox read for magic-link/OTP login flows.

  A target that emails a one-time code or a magic link instead of returning it in the HTTP
  response has no way to be automated through ``login_as`` (identity/tool.py), which only ever
  handles session material the target hands back in its own HTTP response. This closes that gap
  the same narrow way totp.py closes the TOTP-second-factor gap: one small, stdlib-only primitive
  wired in as its own tool, not a new pipeline stage.

  Deliberately stdlib-only (``imaplib``/``email``): basic IMAP4-over-SSL login/search/fetch needs
  nothing a third-party client would add for this tool's one job (most-recent-message-matching-a-
  filter), matching this project's own preference for the smallest dependency that does the job.

  Connects fresh per call and always logs out in a ``finally`` -- there is no long-lived mailbox
  session worth keeping around, unlike login.py's ``Session`` (which IS meant to be reused across
  many subsequent calls).
  """

  from __future__ import annotations

  import email
  import imaplib
  import re
  from email.message import Message

  from ..agent.tools import FunctionTool, ToolResult, str_arg
  from .credentials import EmailAccount


  def _plain_text_body(msg: Message) -> str:
      """The message's text/plain body, joining every such part of a multipart message (a real
      MIME message routinely carries both a text/plain and a text/html alternative -- only the
      former is worth regex-matching)."""
      if not msg.is_multipart():
          payload = msg.get_payload(decode=True)
          if not isinstance(payload, bytes):
              return ""
          return payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
      parts = []
      for part in msg.walk():
          if part.get_content_type() != "text/plain":
              continue
          payload = part.get_payload(decode=True)
          if isinstance(payload, bytes):
              parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
      return "\n".join(parts)


  def build_email_fetch_tool(accounts: dict[str, EmailAccount]) -> FunctionTool:
      def _fetch(args: dict[str, object]) -> ToolResult:
          account_name = str_arg(args, "account").strip()
          pattern = str_arg(args, "pattern").strip()
          if not account_name or not pattern:
              return ToolResult(observation="error: 'account' and 'pattern' are required", ok=False)
          account = accounts.get(account_name)
          if account is None:
              return ToolResult(
                  observation=(
                      f"error: unknown email account {account_name!r} (known: {sorted(accounts)})"
                  ),
                  ok=False,
              )
          try:
              regex = re.compile(pattern)
          except re.error as exc:
              return ToolResult(observation=f"error: invalid 'pattern' regex: {exc}", ok=False)

          subject_contains = str_arg(args, "subject_contains").strip()
          from_contains = str_arg(args, "from_contains").strip()
          criteria: list[str] = []
          if subject_contains:
              criteria += ["SUBJECT", f'"{subject_contains}"']
          if from_contains:
              criteria += ["FROM", f'"{from_contains}"']
          if not criteria:
              criteria = ["ALL"]

          conn: imaplib.IMAP4_SSL | None = None
          try:
              conn = imaplib.IMAP4_SSL(account.imap_host, account.imap_port)
              conn.login(account.address, account.password)
              conn.select("INBOX")
              status, data = conn.search(None, *criteria)
              if status != "OK" or not data or not data[0]:
                  return ToolResult(observation="no messages matched the filter", ok=False)
              # ponytail: takes the highest sequence number as "most recent" --
              # correct for every server returning SEARCH results in mailbox
              # (delivery) order, the common case; upgrade to sorting by each
              # message's own Date header if a target server ever doesn't.
              latest_id = data[0].split()[-1]
              status, msg_data = conn.fetch(latest_id, "(RFC822)")
              if status != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
                  return ToolResult(
                      observation="error: could not fetch the matched message", ok=False
                  )
              raw = msg_data[0][1]
              body = _plain_text_body(email.message_from_bytes(raw))
          except Exception as exc:  # noqa: BLE001 - report every IMAP failure, never crash the agent
              return ToolResult(observation=f"error: {type(exc).__name__}: {exc}", ok=False)
          finally:
              if conn is not None:
                  try:
                      conn.logout()
                  except Exception:  # noqa: BLE001 - best-effort cleanup, must never mask the real result
                      pass

          match = regex.search(body)
          if match is None:
              return ToolResult(
                  observation=f"message found but pattern {pattern!r} did not match its body",
                  ok=False,
              )
          extracted = match.group(1) if match.groups() else match.group(0)
          return ToolResult(observation=f"extracted: {extracted}")

      return FunctionTool(
          name="fetch_email_code",
          description=(
              "Read the most recent message in a pre-configured IMAP mailbox and extract a "
              "magic-link/OTP code or URL via your own regex, run against the message's "
              "plain-text body -- for target login flows that email a code instead of "
              "returning it in the HTTP response. Connects fresh per call and always logs "
              'out. args: {"account": str, "pattern": str (a regex; its first capture group '
              'is returned, or the whole match if it has none), "subject_contains": str '
              '(optional, an IMAP SUBJECT filter), "from_contains": str (optional, an IMAP '
              'FROM filter)}'
          ),
          func=_fetch,
      )
  ```

  In `src/lalo/identity/__init__.py`, change:

  ```python
  from .credentials import Credential, CredentialKind, Identity, IdentityStore
  ```

  to:

  ```python
  from .credentials import Credential, CredentialKind, EmailAccount, Identity, IdentityStore
  from .email_tool import build_email_fetch_tool
  ```

  and add `"EmailAccount"` and `"build_email_fetch_tool"` to `__all__` (alphabetically, next to
  `"DecodedJwt"`/`"Identity"` and next to `"build_jwt_tool"` respectively).

  In `src/lalo/scan.py`, change the import block (lines 171-173):

  ```python
  from .identity.credentials import Identity, IdentityStore
  from .identity.login import LoginScheme, SessionRegistry, login
  from .identity.tool import build_jwt_tool, build_login_tool, build_session_check_tool
  ```

  to:

  ```python
  from .identity.credentials import EmailAccount, Identity, IdentityStore
  from .identity.email_tool import build_email_fetch_tool
  from .identity.login import LoginScheme, SessionRegistry, login
  from .identity.tool import build_jwt_tool, build_login_tool, build_session_check_tool
  ```

  Add a new `ScanConfig` field right after `login_schemes` (line 223):

  ```python
      login_schemes: dict[str, LoginScheme] = field(default_factory=dict)
      # Keyed by account name, the same independent-map convention as
      # `identities`/`login_schemes` -- an IMAP mailbox isn't a target-login
      # identity, so it gets its own map rather than overloading either.
      email_accounts: dict[str, EmailAccount] = field(default_factory=dict)
  ```

  Wire the tool into `_build_registry`, right after the existing `identities.ids()` block
  (lines 1158-1162):

  ```python
              if identities.ids():
                  tools.append(
                      build_login_tool(firer, identities, sessions, self.config.login_schemes)
                  )
                  tools.append(build_session_check_tool(firer, sessions))
              if self.config.email_accounts:
                  tools.append(build_email_fetch_tool(self.config.email_accounts))
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```
  uv run pytest tests/lalo/test_identity.py tests/lalo/test_email_tool.py -v
  uv run pytest tests/lalo/test_scan.py -q
  ```

  The first command's new/modified tests should all pass; the second is a non-breaking check that
  adding `ScanConfig.email_accounts` and the new imports didn't disturb anything already covered
  by the scan-level suite (`_ResumeManifest` deliberately excludes `identities`/`login_schemes`
  already, so `email_accounts` needs no resume-manifest change either).

- [ ] **Step 5: Commit**

  ```
  git add src/lalo/identity/credentials.py src/lalo/identity/email_tool.py \
      src/lalo/identity/__init__.py src/lalo/scan.py \
      tests/lalo/test_identity.py tests/lalo/test_email_tool.py
  git commit -m "feat(L4L0): email_login credential shape + IMAP-fetch tool for magic-link/OTP flows

  EmailAccount (address/password/imap_host/imap_port) registers its password with the shared
  redactor at construction, kept independent of Identity/Credential since it authenticates to a
  mailbox rather than the engagement target. build_email_fetch_tool (fetch_email_code) connects
  via stdlib imaplib, reads the most recent message matching a caller-supplied subject/sender
  filter, and returns a caller-supplied regex's match -- wired into _build_registry alongside the
  other identity tools whenever ScanConfig.email_accounts is non-empty."
  ```

---

### Task 16: Investigate and (if reasonable) add an AWS Bedrock provider adapter

**Investigation result (do this before writing any code):** AWS Bedrock's general model-invocation surface (`InvokeModel`/`Converse` for Titan, Llama, Mistral, etc.) requires full AWS SigV4 request signing — a canonical-request + credential-scope + HMAC-SHA256 derived-key-chain scheme, confirmed via AWS's own docs (`docs.aws.amazon.com/bedrock/.../inference-messages-api.html`, `docs.aws.amazon.com/IAM/.../reference_sigv.html`, Sept 2026). Neither Python's stdlib nor any dependency already in this project (`httpx`, the only HTTP client `lalo.core.providers` uses) implements SigV4; the only thing that does is `botocore`/`boto3` or a hand-rolled signer, either of which is a real, separate piece of work — **that general path is correctly out of scope for this task and is not attempted here.**

However, a genuinely simple path *does* exist for one specific model family: Bedrock now has a **bearer-token API-key mode** (`AWS_BEARER_TOKEN_BEDROCK`, GA in commercial regions as of Sept 2026) and, for Claude models specifically, a dedicated **Anthropic-compatible route** — `POST https://bedrock-runtime.{region}.amazonaws.com/anthropic/v1/messages` — that speaks the *native Anthropic Messages API wire shape* (`x-api-key` header, `anthropic-version: 2023-06-01` header, `{"model", "max_tokens", "messages", ...}` body, `{"content":[...], "stop_reason", "usage"}` response) with **no SigV4 signing at all**. Read against the actual code: `AnthropicProvider` in `src/lalo/core/providers.py` already sends exactly that header set and body/response shape, and its constructor already accepts a `base_url` override (`base_url: str = "https://api.anthropic.com"`) that nothing currently threads through for `kind == "anthropic"`. So this is not a new adapter class or a new `ProviderKind` — it's one new curated `ProviderSpec` entry (`kind="anthropic"`) plus fixing one real bug: `_build_adapter` (`src/lalo/core/providers.py:304-306`) currently hardcodes `AnthropicProvider(resolved.api_key, model=resolved.model)` for every `"anthropic"`-kind provider, silently discarding `resolved.base_url` — which would have sent every Bedrock-routed request to `api.anthropic.com` instead, with no error at all.

This is scoped **only** to Claude-on-Bedrock via this bearer-token route; Bedrock's other model families are the deferred SigV4 case above and are not touched.

**Files:**
- Modify: `src/lalo/core/config.py:47` (the `default_base_url` field's trailing comment — currently says "openai_compatible only", no longer accurate once an `"anthropic"`-kind entry uses it too)
- Modify: `src/lalo/core/config.py:85-92` (insert a new `ProviderSpec` into the `CURATED_PROVIDERS` tuple, immediately after the native `"anthropic"` entry and before `"openai"`)
- Modify: `src/lalo/core/providers.py:304-306` (`_build_adapter`'s `"anthropic"` branch — forward `resolved.base_url`)
- Test: `tests/lalo/test_config.py` (append two tests)
- Test: `tests/lalo/test_providers.py` (append one test + one new import)

**Interfaces:**
- Consumes: none from earlier tasks (standalone, architectural). Uses pre-existing code only: `ProviderSpec`/`CURATED_PROVIDERS: tuple[ProviderSpec, ...]`/`ResolvedProvider`/`Settings.get(provider_id: str) -> ResolvedProvider | None`/`load_settings(env: Mapping[str, str] | None = None) -> Settings` (`src/lalo/core/config.py`), and `AnthropicProvider.__init__(self, api_key: str, *, model: str, client: httpx.Client | None = None, base_url: str = "https://api.anthropic.com", sleep: Callable[[float], None] = time.sleep) -> None` plus `_build_adapter(resolved: ResolvedProvider) -> Provider` (`src/lalo/core/providers.py`).
- Produces: a new curated entry `ProviderSpec(id="bedrock_anthropic", kind="anthropic", ...)` in `CURATED_PROVIDERS` — any later task can do `load_settings(env).get("bedrock_anthropic") -> ResolvedProvider | None` once `AWS_BEARER_TOKEN_BEDROCK` is set in the environment. Also: `_build_adapter` now honors `resolved.base_url` for **every** `kind == "anthropic"` provider (previously silently ignored it), so `build_router(settings).providers["bedrock_anthropic"]` is an `AnthropicProvider` instance actually pointed at the Bedrock endpoint, not `api.anthropic.com`.

- [ ] **Step 1: Write the failing tests**

  In `tests/lalo/test_config.py`, append:
  ```python
  def test_bedrock_anthropic_curated_entry_resolves_via_the_aws_bearer_token_env() -> None:
      settings = load_settings({"AWS_BEARER_TOKEN_BEDROCK": "abc123"})
      resolved = settings.get("bedrock_anthropic")
      assert resolved is not None
      assert resolved.kind == "anthropic"
      assert resolved.model == "us.anthropic.claude-sonnet-5"
      assert resolved.base_url == "https://bedrock-runtime.us-east-1.amazonaws.com/anthropic"


  def test_bedrock_anthropic_base_url_and_model_are_operator_overridable() -> None:
      settings = load_settings(
          {
              "AWS_BEARER_TOKEN_BEDROCK": "abc123",
              "LALO_BEDROCK_BASE_URL": "https://bedrock-runtime.eu-west-1.amazonaws.com/anthropic",
              "LALO_BEDROCK_MODEL": "eu.anthropic.claude-opus-5",
          }
      )
      resolved = settings.get("bedrock_anthropic")
      assert resolved is not None
      assert resolved.base_url == "https://bedrock-runtime.eu-west-1.amazonaws.com/anthropic"
      assert resolved.model == "eu.anthropic.claude-opus-5"
  ```

  In `tests/lalo/test_providers.py`, add `from lalo.core import providers as providers_module` to the imports at the top of the file, then append:
  ```python
  def test_build_adapter_forwards_a_curated_base_url_for_the_anthropic_kind(
      monkeypatch: pytest.MonkeyPatch,
  ) -> None:
      """Regression test for the bug this task fixes: _build_adapter used to
      hardcode AnthropicProvider(api_key, model=model) for every "anthropic"-kind
      provider, silently discarding any curated base_url -- which would have sent
      every Bedrock-routed request to api.anthropic.com instead, with no error."""
      seen_urls: list[str] = []

      def fake_post_with_retry(client, url, *, json, headers, sleep=None):
          seen_urls.append(url)
          return httpx.Response(
              200, json={"stop_reason": "end_turn", "content": [{"type": "text", "text": "hi"}]}
          )

      monkeypatch.setattr(providers_module, "_post_with_retry", fake_post_with_retry)

      settings = load_settings({"AWS_BEARER_TOKEN_BEDROCK": "tok"})
      resolved = settings.get("bedrock_anthropic")
      assert resolved is not None
      adapter = providers_module._build_adapter(resolved)
      assert isinstance(adapter, AnthropicProvider)

      adapter.complete(CompletionRequest(prompt="x"))
      assert seen_urls == ["https://bedrock-runtime.us-east-1.amazonaws.com/anthropic/v1/messages"]
  ```

- [ ] **Step 2: Run test to verify it fails**
  ```
  uv run pytest \
    tests/lalo/test_config.py::test_bedrock_anthropic_curated_entry_resolves_via_the_aws_bearer_token_env \
    tests/lalo/test_config.py::test_bedrock_anthropic_base_url_and_model_are_operator_overridable \
    tests/lalo/test_providers.py::test_build_adapter_forwards_a_curated_base_url_for_the_anthropic_kind \
    -v
  ```
  Expected: `3 failed`. All three fail at `assert resolved is not None` with `AssertionError: assert None is not None`, because `"bedrock_anthropic"` isn't in `CURATED_PROVIDERS` yet, so `settings.get("bedrock_anthropic")` returns `None`.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/core/config.py`, change the field comment on line 47 from:
  ```python
      default_base_url: str | None = None  # openai_compatible only
  ```
  to:
  ```python
      default_base_url: str | None = None  # openai_compatible + Bedrock-style anthropic routes
  ```

  Then insert into `CURATED_PROVIDERS`, right after the native `"anthropic"` entry (after line 92's closing `),`) and before the `"openai"` entry:
  ```python
      ProviderSpec(
          id="bedrock_anthropic",
          # Anthropic's Messages API wire shape, reachable via Bedrock's
          # `/anthropic/v1/messages` compatibility route using a plain bearer
          # token (AWS_BEARER_TOKEN_BEDROCK) -- no AWS SigV4 request signing
          # needed, so the existing AnthropicProvider adapter (already
          # `x-api-key` + `anthropic-version` + a configurable base_url) works
          # against it completely unmodified. Deliberately scoped to Anthropic
          # models only: Bedrock's other model families (Titan, Llama, Mistral,
          # ...) expose ONLY the SigV4-signed InvokeModel/Converse API, which
          # needs a real request-signing implementation (canonical request +
          # credential scope + HMAC-SHA256 derived-key chain) that neither
          # stdlib nor any dependency already in this project provides --
          # deferred, not guessed at. A real follow-up would add `botocore`
          # (or a hand-rolled SigV4 signer) as its own separate adapter kind.
          kind="anthropic",
          candidate_key_envs=("AWS_BEARER_TOKEN_BEDROCK",),
          credential_hint=(
              "AWS_BEARER_TOKEN_BEDROCK (an Amazon Bedrock API key / bearer "
              "token from the Bedrock console -- not an IAM secret key)"
          ),
          default_model="us.anthropic.claude-sonnet-5",
          default_base_url="https://bedrock-runtime.us-east-1.amazonaws.com/anthropic",
          base_url_env="LALO_BEDROCK_BASE_URL",
          model_env="LALO_BEDROCK_MODEL",
      ),
  ```

  In `src/lalo/core/providers.py`, change `_build_adapter`'s `"anthropic"` branch (lines 304-306) from:
  ```python
  def _build_adapter(resolved: ResolvedProvider) -> Provider:
      if resolved.kind == "anthropic":
          return AnthropicProvider(resolved.api_key, model=resolved.model)
  ```
  to:
  ```python
  def _build_adapter(resolved: ResolvedProvider) -> Provider:
      if resolved.kind == "anthropic":
          # A curated "anthropic"-kind entry may point somewhere other than
          # api.anthropic.com while speaking the identical wire shape -- e.g.
          # Bedrock's bearer-token Anthropic-compatible route (see config.py's
          # "bedrock_anthropic" entry). Only fall back to the real default when
          # no curated base_url was set, so the native Anthropic entry (which
          # never sets one) keeps hitting api.anthropic.com exactly as before.
          return AnthropicProvider(
              resolved.api_key,
              model=resolved.model,
              base_url=resolved.base_url or "https://api.anthropic.com",
          )
  ```
  (the rest of the function — the `openai_responses`/`openai_compatible` branches below — is untouched).

- [ ] **Step 4: Run test to verify it passes**
  ```
  uv run pytest \
    tests/lalo/test_config.py::test_bedrock_anthropic_curated_entry_resolves_via_the_aws_bearer_token_env \
    tests/lalo/test_config.py::test_bedrock_anthropic_base_url_and_model_are_operator_overridable \
    tests/lalo/test_providers.py::test_build_adapter_forwards_a_curated_base_url_for_the_anthropic_kind \
    -v
  ```
  Expected: `3 passed`. Then run the full existing files once to confirm no regression: `uv run pytest tests/lalo/test_config.py tests/lalo/test_providers.py -v` — expected: all previously-passing tests (e.g. `test_resolves_only_configured_providers_in_preference_order`, `test_build_router_wires_configured_providers_and_registers_secrets`) still pass, since the new curated entry requires its own unset-by-default env var and the `_build_adapter` fallback preserves the native Anthropic entry's existing default.

- [ ] **Step 5: Commit**
  ```
  git add src/lalo/core/config.py src/lalo/core/providers.py tests/lalo/test_config.py tests/lalo/test_providers.py
  git commit -m "$(cat <<'EOF'
  feat(L4L0): add Bedrock's bearer-token Anthropic-compatible route as a curated provider

  Investigated Bedrock's general InvokeModel/Converse API and confirmed it needs
  real AWS SigV4 request signing with no lightweight path -- deliberately not
  built. Bedrock's Anthropic-specific /anthropic/v1/messages route, though, is
  wire-identical to the native Anthropic Messages API and works with a plain
  bearer token, so it reuses the existing anthropic ProviderKind unmodified.
  Also fixes _build_adapter, which was silently discarding any curated
  base_url override for every anthropic-kind provider.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

**Deferred / explicitly out of scope:** general Bedrock model access (Titan, Llama, Mistral, and any Claude access via the plain `InvokeModel`/`Converse` endpoints rather than the `/anthropic/v1/messages` route) requires real AWS SigV4 signing, which needs either the `botocore`/`boto3` dependency or a hand-rolled canonical-request/HMAC-SHA256 signer — a real, separate implementation task (its own `ProviderKind`, its own adapter class, a new dependency decision) that this task does not attempt or fake.


## Final Check

- [ ] Run the full non-live/non-integration suite: `uv run pytest -q -m "not integration and not live"` — expect all tests passing (no regressions across the 16 tasks above).
- [ ] Run lint across the whole tree: `uv run ruff check src/lalo tests/lalo` — expect zero errors.
- [ ] Run format check: `uv run ruff format --check src/lalo tests/lalo` — expect no reformatting needed (or run `uv run ruff format src/lalo tests/lalo` and commit any reformatting as its own small commit).
- [ ] Run the type checker: `uv run mypy` — expect no errors.
- [ ] Grep every file touched by this plan for any accidentally-leaked reference-project name (this project's own standing discipline — a prior sweep this same day found and fixed ~20 pre-existing leaks elsewhere in the codebase, so treat this as a real check, not a formality): `git diff --name-only <base-commit>..HEAD | xargs grep -niE "shannon|pentestgpt|\bstrix\b|\bpentagi\b|\bcai\b" || echo "clean"` — expect "clean" (the pre-existing `_shannon_entropy` function in `core/redaction.py` is the standard information-theory term and is not touched by this plan, so it will not appear in this plan's own diff).
- [ ] Confirm every new opt-in field introduced by this plan (`RuntimeConfig.forward_etc_hosts`, `RuntimeConfig.keep_on_failure`, `ScanConfig.cost_limit_usd`) defaults to the non-restrictive value (forwarding/reachability on by default, cost/keep-on-failure off by default) and that no new code path blocks, delays, or requires operator confirmation for anything the agent does — matching this plan's Global Constraints section.
