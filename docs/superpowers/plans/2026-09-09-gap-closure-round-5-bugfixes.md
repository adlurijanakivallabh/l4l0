# Gap Closure Round 5 — Bugfixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline execution, no subagent dispatch — operator's standing instruction this session). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix four independently-verified correctness bugs found during a function-level
gap analysis: an unlocked usage-ledger race, a per-finding review loop that can
crash-loop a scan forever, a dedup-merge that silently discards severity data, and a
SARIF automation id that breaks cross-run alert correlation.

**Architecture:** Each bug is small and independent — no shared new abstraction, no
new files. Every fix is 5-20 lines in an existing function, each verified with a
hermetic regression test proving the specific failure mode is closed.

**Tech Stack:** Python 3.13, pytest, `threading.Lock` (stdlib only — no new dependency).

**Spec:** `docs/superpowers/specs/2026-09-09-gap-closure-round-5-design.md`, Part A.

## Global Constraints

- No CLI/TUI, no confirmation/permission gates, no new restriction of any kind — every
  fix here is either a lock (prevents a race, doesn't change what's allowed), a
  try/except (prevents a crash, doesn't change what's allowed), a merge-policy change
  (keeps the more accurate of two computed values, doesn't reject anything), or an id
  derivation change (doesn't affect what's reported, only how re-scans of the same
  target correlate in a SARIF consumer).
- No reference-project names in code/comments/docs/commit messages — describe patterns
  generically ("a studied reference agent's own X"), per CLAUDE.md's clean-room policy.
  Re-verified via a full non-diff-scoped repo grep this same session (commit `5e00aea`)
  — hold this strictly, including in every new docstring/comment this plan adds.
- Full non-live suite + `ruff check`/`ruff format --check` + `mypy` + reference-name-leak
  grep + `git fsck --full` after every task, matching this session's standing discipline.
- Every file path/line number below was read live from the current source this same
  session, immediately before this plan was written — trust the described current
  content, but if it's drifted by the time you implement, re-read the live file rather
  than trusting a stale line number.

---

### Task 1: Lock `record_usage()`'s file-backed read-modify-write

**Files:**
- Modify: `src/lalo/core/usage.py:1-30` (module docstring — add one clarifying paragraph),
  `:157-238` (`record_usage`, add a module-level lock)
- Test: `tests/lalo/test_usage.py` (append)

**Interfaces:**
- Consumes: none from other tasks in this plan.
- Produces: no signature change — `record_usage`'s existing callers (`agent/loop.py`,
  `gui/app.py`) need zero changes. A new module-level `_lock: threading.Lock` in
  `core/usage.py`, private to the module.

**Important scoping note, verified by reading the module docstring in full:** this
module already has an explicit, documented decision to NOT add `fcntl`-based
inter-process file locking (two separate OS processes touching the same usage file is
judged low-probability, not worth the complexity). **This task does not touch or
reverse that decision.** The race this task closes is a different, narrower, and
definitely-not-low-probability one: multiple **threads within the same process** —
`scan.py` passes the identical `self.config.usage_path` to the root `AgentLoop` and to
every child `AgentLoop` a `spawn_agents` fan-out creates on real
`ThreadPoolExecutor` threads (confirmed by reading `scan.py`'s spawn-tool wiring and
`agent/spawn.py`'s `spawn_agents`) — every one of those calls `record_usage()` with the
same `path`. A `threading.Lock()` (in-process only, no `fcntl`, no cross-process
coordination) closes this without touching the already-decided inter-process question
at all. The module docstring gets one clarifying sentence added so a future reader
doesn't conflate the two.

- [ ] **Step 1: Write the failing test**

  Add to `tests/lalo/test_usage.py` (uses the file's own existing `_response`/`_PRICING`
  helpers and `load_usage`/`record_usage` imports, already present):

  ```python
  def test_record_usage_survives_concurrent_calls_with_no_lost_update(tmp_path: Path) -> None:
      """Two threads calling record_usage() with the same path must never lose an
      update to a race - the real hazard this closes: spawn_agents runs several
      children as real OS threads, all sharing ScanConfig.usage_path."""
      import threading

      path = tmp_path / "usage.json"
      call_count = 50

      def _hit() -> None:
          for _ in range(call_count):
              record_usage(_response(input_tokens=1, output_tokens=1), path=path)

      threads = [threading.Thread(target=_hit) for _ in range(4)]
      for t in threads:
          t.start()
      for t in threads:
          t.join()

      stats = load_usage(path)
      assert stats.total_requests == 4 * call_count
      assert stats.total_input_tokens == 4 * call_count
      assert stats.total_output_tokens == 4 * call_count
  ```

  (`UsageStats.total_requests`/`total_input_tokens`/`total_output_tokens` are existing
  properties — confirmed present via the file's own already-passing tests, e.g.
  `test_record_usage_accumulates_across_calls`.)

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_usage.py::test_record_usage_survives_concurrent_calls_with_no_lost_update -v
  ```

  Expected: fails intermittently (a real race — may occasionally pass by luck on a fast
  machine with few cores; run it a few times, or add `-x --count=5` via `pytest-repeat`
  if installed, to make the flake visible). If it happens to pass once, that does not
  mean the race is closed — proceed to the fix regardless, since the race is provably
  real from reading `record_usage`'s own unlocked read-modify-write.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/core/usage.py`, add one clarifying sentence to the existing "Deliberately
  NOT ported" paragraph in the module docstring:

  ```python
  Deliberately NOT ported: ``fcntl`` inter-process locking. A read-modify-write
  race here needs two callers touching the same usage file at once, and this
  project's own established convention (this file's persistence pattern
  mirrors :func:`~lalo.eval.scoring.append_composite_history`'s already-
  accepted decision) is that this is a real but low-probability edge case,
  not worth the complexity of process-level file locking for. Every scan the
  GUI launches (:mod:`lalo.gui.app`) passes its own ``run_dir / "usage.json"``
  ```

  becomes (only the new sentence is added, right after "process-level file locking
  for."):

  ```python
  Deliberately NOT ported: ``fcntl`` inter-process locking. A read-modify-write
  race here needs two callers touching the same usage file at once, and this
  project's own established convention (this file's persistence pattern
  mirrors :func:`~lalo.eval.scoring.append_composite_history`'s already-
  accepted decision) is that this is a real but low-probability edge case,
  not worth the complexity of process-level file locking for. A DIFFERENT,
  genuinely common race is guarded separately below with a plain
  ``threading.Lock`` -- multiple threads in the SAME process (a
  ``spawn_agents`` fan-out's concurrently-running children) sharing one
  ``ScanConfig.usage_path`` is the normal case for any scan that spawns more
  than one child, not an edge case, and needs no cross-process coordination
  to fix. Every scan the GUI launches (:mod:`lalo.gui.app`) passes its own
  ``run_dir / "usage.json"``
  ```

  Add the import and lock near the top of the file (find the existing `import` block —
  confirmed the file currently imports `json`, `dataclasses`, `pathlib.Path` among
  others; add `import threading` alphabetically), and a module-level lock right after
  `DEFAULT_USAGE_PATH`:

  ```python
  import threading
  ```

  ```python
  DEFAULT_USAGE_PATH = Path.home() / ".lalo" / "usage.json"

  # Guards record_usage()'s own load-mutate-write sequence below - see the
  # module docstring's own note on why this is a plain in-process
  # threading.Lock, not the inter-process fcntl locking this module already
  # decided against.
  _lock = threading.Lock()
  ```

  Wrap `record_usage`'s body in the lock, from the existing `stats = load_usage(path)`
  line through the existing `atomic_write_verified(...)` call (everything up to, but NOT
  including, the `cost_limit_usd` check + `raise CostLimitExceededError` + `return stats`
  at the very end — that check reads the now-durably-written `stats.total_cost_usd`,
  which doesn't need to stay inside the critical section, and `CostLimitExceededError`
  should not itself be raised from inside a locked block for hygiene, even though
  nothing here would actually deadlock if it were):

  ```python
  def record_usage(
      response: CompletionResponse,
      *,
      path: Path = DEFAULT_USAGE_PATH,
      pricing_table: PricingTable | None = None,
      cost_limit_usd: float | None = None,
      agent_id: str | None = None,
      step_key: str | None = None,
  ) -> UsageStats:
      """..."""  # docstring unchanged
      with _lock:
          stats = load_usage(path)
          input_tokens = response.input_tokens or 0
          output_tokens = response.output_tokens or 0
          cost = estimate_cost_usd(response, pricing_table) if pricing_table else None

          if step_key is not None and step_key in stats.by_step:
              prior = stats.by_step[step_key]
              _apply_delta(
                  stats,
                  provider=str(prior["provider"]),
                  agent_id=prior["agent_id"],  # type: ignore[arg-type]
                  input_tokens=int(prior["input_tokens"]),  # type: ignore[call-overload]
                  output_tokens=int(prior["output_tokens"]),  # type: ignore[call-overload]
                  cost=prior["cost_usd"],  # type: ignore[arg-type]
                  sign=-1,
              )

          _apply_delta(
              stats,
              provider=response.provider,
              agent_id=agent_id,
              input_tokens=input_tokens,
              output_tokens=output_tokens,
              cost=cost,
              sign=1,
          )

          if step_key is not None:
              stats.by_step[step_key] = {
                  "provider": response.provider,
                  "agent_id": agent_id,
                  "input_tokens": input_tokens,
                  "output_tokens": output_tokens,
                  "cost_usd": cost,
              }

          atomic_write_verified(
              path, json.dumps(stats.to_dict(), indent=2, sort_keys=True).encode("utf-8")
          )

      if cost_limit_usd is not None and stats.total_cost_usd > cost_limit_usd:
          raise CostLimitExceededError(
              f"lifetime cost ${stats.total_cost_usd:.4f} exceeds the ${cost_limit_usd:.4f} limit",
              total_cost_usd=stats.total_cost_usd,
              limit_usd=cost_limit_usd,
          )
      return stats
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_usage.py -v
  ```

  Expected: all tests pass, including the new concurrent one, deterministically (run it
  3-4 times in a row to build confidence the race is actually closed, not just less
  likely).

  ```
  uv run ruff check src/lalo/core/usage.py tests/lalo/test_usage.py
  uv run ruff format src/lalo/core/usage.py tests/lalo/test_usage.py
  uv run mypy src/lalo/core/usage.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/core/usage.py tests/lalo/test_usage.py
  git commit -m "$(cat <<'EOF'
  fix(core): lock record_usage's file-backed read-modify-write

  Multiple threads in the same process (spawn_agents' concurrently-running
  children, all sharing ScanConfig.usage_path) could race record_usage's
  unlocked load-mutate-write sequence, silently losing one side's update.
  A plain threading.Lock closes this - distinct from, and doesn't reverse,
  this module's own already-documented decision against fcntl inter-process
  locking, which guards a different (and genuinely rarer) hazard.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 2: Make the per-finding review loop crash-proof and resumable

**Files:**
- Modify: `src/lalo/scan.py:1044-1050` (`_run_inside` signature — confirm `journal`/
  `engagement` already in scope, no signature change needed), `:1331-1355` (the
  `for finding_id in graph.nodes_of_kind(NodeKind.FINDING):` loop)
- Test: `tests/lalo/test_scan.py` (append)

**Interfaces:**
- Consumes: `journal.run_once(key: str, fn: Callable[[], Any]) -> Any` (existing,
  `orchestrator/journal.py:130-138`) — already used elsewhere in `scan.py`/`agent/loop.py`
  with the `f"{agent_key}:{step}"` key convention; this task uses a parallel
  `f"review:{finding_id}"` convention instead, since a finding review isn't tied to any
  one agent's step sequence.
- Produces: no new public function — the loop body changes in place. No other task in
  this plan or the capability plan depends on this loop's internals directly (B1's new
  `record_safe` tool adds a *different* node kind entirely, never touched by this loop).

- [ ] **Step 1: Write the failing test**

  Verified pattern: this file already has a `_CrashingProvider` test double (used by
  `test_resume_after_a_crash_does_not_redispatch_the_completed_step` and others) whose
  `complete()` raises `RuntimeError("simulated crash")` when its scripted responder
  returns the literal string `"CRASH"`. Reuse it here, scripted to let the mission
  agent-loop phase succeed normally (so a real finding actually lands on the graph) and
  only fail during the *review* phase — confirmed by reading `findings/review.py`'s
  `run_adversarial_review`: it calls `router.complete()` under the `role="review"`
  route, so a router whose `"review"` route is wired to a crashing provider reproduces
  exactly the failure this task guards against, without needing to fake a malformed
  JSON response.

  Append to `tests/lalo/test_scan.py`:

  ```python
  def test_a_deterministically_failing_review_does_not_crash_loop_a_resume(
      tmp_path: Path, monkeypatch: pytest.MonkeyPatch
  ) -> None:
      """Real gap this closes: a finding whose review call always raises used to
      crash the whole run every single time - including on every subsequent
      resume, since the review loop was never journaled. This proves both
      halves of the fix: the run reaches a real terminal status instead of
      crashing, and a second resume does not re-spend an LLM call reviewing
      the same finding twice."""
      monkeypatch.setattr(scan_module, "docker_available", lambda: True)
      monkeypatch.setattr(scan_module, "RuntimeContainer", _FakeContainer)

      review_call_count = 0

      def _respond(_call_index: int, prompt: str) -> str:
          nonlocal review_call_count
          if "FINDING TO REVIEW" in prompt:
              review_call_count += 1
              return "CRASH"
          return _record_finding_call() if "HISTORY" not in prompt else _finish_call()

      router = ModelRouter(
          providers={"fake": _CrashingProvider(_respond)},
          routes={"reasoning": ("fake",), "review": ("fake",)},
          default_route=("fake",),
      )
      monkeypatch.setattr(scan_module, "build_router", lambda _settings: router)

      run_dir = tmp_path / "run"
      config = ScanConfig(mission="find a bug", target_specs=["example.com"], run_dir=run_dir)
      outcome = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()

      # The run reaches a real terminal outcome - it does NOT propagate the
      # review crash as an unhandled exception out of run().
      assert outcome.status is RunStatus.COMPLETED
      graph = ReachabilityGraph.load(run_dir / "graph.json")
      (finding_id,) = graph.nodes_of_kind(NodeKind.FINDING)
      assert graph.node(finding_id)["review_verdict"] == "open_proof_gap"
      first_run_review_calls = review_call_count

      # Resuming must not re-spend a review call for the same, already-
      # (degraded-)reviewed finding.
      outcome2 = ScanRunner(config, env={"ANTHROPIC_API_KEY": "sk-test"}).run()
      assert outcome2.status is RunStatus.COMPLETED
      assert review_call_count == first_run_review_calls
  ```

  (`_record_finding_call`/`_finish_call`/`_FakeContainer`/`_CrashingProvider` are this
  file's own existing helpers, already used by neighboring tests — no new imports
  needed beyond what the file already has.)

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_scan.py::test_a_deterministically_failing_review_does_not_crash_loop_a_resume -v
  ```

  Expected: fails with the `RuntimeError("simulated crash")` propagating uncaught out of
  `ScanRunner(...).run()` on the very first call — the test never even reaches its own
  `assert outcome.status is RunStatus.COMPLETED` line.

- [ ] **Step 3: Write minimal implementation**

  **Verified exact current behavior of `run_adversarial_review` first** (read in full):
  it already NEVER raises for a handled failure — a total provider-chain failure
  (`AllProvidersFailedError`) or an unparseable response both internally degrade via its
  own private `_fallback(reasoning, confidence.score)` helper, which returns
  `ReviewResult(verdict=ReviewVerdict.OPEN_PROOF_GAP, proof_level="L1", reasoning=...,
  adjusted_score=confidence.score)` — and on every return path (including that
  fallback), `run_adversarial_review` itself durably writes
  `{"review_verdict": ..., "review_proof_level": ..., "review_reasoning": ...}` onto the
  finding's graph node via `graph.add_node(finding_id, NodeKind.FINDING, **attrs)`
  *before* returning. So the only failure mode this task's `try`/`except` needs to guard
  against is `run_adversarial_review` itself raising an exception its own internals
  don't already catch (an unexpected error type, a bug, anything violating its own
  stated "never raises" contract) — in that case NOTHING gets written to the graph node
  from review.py's side at all, so the `except` branch below must write it itself, using
  the exact same three-field shape and the same `"L1"`/no-real-proof sentinel
  `_fallback` already uses, for parity with every other degraded-review path.

  Also note: `ReviewResult` has four fields (`verdict`, `proof_level: str`, `reasoning`,
  `adjusted_score: int`) — `proof_level` is a plain `str`, never `None` (matching
  `_fallback`'s own `"L1"` convention for "no real proof level achieved").

  In `src/lalo/scan.py`, replace the loop body (the `else:` branch's `for finding_id in
  graph.nodes_of_kind(NodeKind.FINDING):` block):

  ```python
          else:
              for finding_id in graph.nodes_of_kind(NodeKind.FINDING):
                  def _review_once(_finding_id: str = finding_id) -> dict[str, object]:
                      confidence = compute_confidence(graph, _finding_id)
                      try:
                          review = run_adversarial_review(
                              graph,
                              _finding_id,
                              confidence,
                              router,
                              second_opinion=self.config.enable_second_opinion_review,
                          )
                      except Exception as exc:  # noqa: BLE001 - one finding's review
                          # must never crash the whole run, on a fresh run or any
                          # future resume: run_adversarial_review already degrades a
                          # total provider failure or an unparseable response to
                          # open_proof_gap internally (and durably writes that verdict
                          # onto the graph node itself before returning) - this widens
                          # the exact same degrade-don't-crash contract to cover the
                          # one path run_adversarial_review's own internals don't
                          # already catch: itself raising, violating its own stated
                          # "never raises" contract. Mirrors review.py's own private
                          # _fallback() shape exactly (proof_level="L1", same
                          # no-real-proof sentinel), since nothing here has a real
                          # proof level or adjusted score to report either.
                          _log.warning(
                              "review crashed for finding %s (%s: %s) - "
                              "degrading to open_proof_gap",
                              _finding_id,
                              type(exc).__name__,
                              exc,
                          )
                          reasoning = f"review crashed: {type(exc).__name__}: {exc}"
                          graph.add_node(
                              _finding_id,
                              NodeKind.FINDING,
                              review_verdict=ReviewVerdict.OPEN_PROOF_GAP.value,
                              review_proof_level="L1",
                              review_reasoning=reasoning,
                          )
                          review = ReviewResult(
                              verdict=ReviewVerdict.OPEN_PROOF_GAP,
                              proof_level="L1",
                              reasoning=reasoning,
                              adjusted_score=confidence.score,
                          )
                      return {"confidence_score": confidence.score, "verdict": review.verdict.value}

                  # Journaled per finding, not per agent step - a finding's
                  # review is a fact about that finding, independent of which
                  # agent/step recorded it, so it gets its own namespace rather
                  # than reusing the f"{agent_key}:{step}" convention every
                  # OTHER journal.run_once call in this codebase uses.
                  result = journal.run_once(f"review:{finding_id}", _review_once)
                  node = graph.node(finding_id)
                  self._emit(
                      "finding",
                      {
                          "finding_id": finding_id,
                          "title": node.get("title", finding_id),
                          "severity": node.get("cvss_severity", "info"),
                          "confidence": result["confidence_score"],
                          "verdict": result["verdict"],
                      },
                  )
  ```

  (`graph.add_node`'s real merge semantics — confirmed elsewhere in this same file's
  existing `record_finding` merge branch — merge fields onto an existing node rather
  than replacing it wholesale, so this call only needs to carry the three
  review-specific fields, not every existing field on the node.)

  Add the two new imports this needs at the top of `scan.py`, alongside the existing
  `from .findings.review import run_adversarial_review` line — both are already
  re-exported from `lalo.findings.review` (confirmed: `ReviewResult`/`ReviewVerdict` are
  both also re-exported from `lalo.findings`'s own `__init__.py`, but importing directly
  from `.findings.review` here matches the existing import's own module path):

  ```python
  from .findings.review import ReviewResult, ReviewVerdict, run_adversarial_review
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_scan.py::test_a_deterministically_failing_review_does_not_crash_loop_a_resume -v
  uv run pytest tests/lalo/test_scan.py -q
  ```

  Expected: the new test passes; the full file's existing suite (including every other
  resume/review test) stays green — this change only adds a try/except and journaling
  around behavior that succeeds identically to before in the non-crashing case.

  ```
  uv run ruff check src/lalo/scan.py tests/lalo/test_scan.py
  uv run ruff format src/lalo/scan.py tests/lalo/test_scan.py
  uv run mypy src/lalo/scan.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/scan.py tests/lalo/test_scan.py
  git commit -m "$(cat <<'EOF'
  fix(L4L0): a single failing review can no longer permanently crash-loop a scan

  The post-loop per-finding confidence/review pass had no exception handling
  and was never journaled - a deterministically-failing review for one
  finding crashed the whole run, and since resume replays the identical
  already-completed agent-loop steps then re-enters this exact same
  unprotected loop, the crash repeated forever with no recovery path. Now
  each finding's review is journaled independently (journal.run_once) and a
  raised exception degrades that one finding to open_proof_gap instead of
  aborting the run, matching run_adversarial_review's own existing
  degrade-don't-crash contract for a provider failure.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 3: Dedup-merge keeps the stronger CVSS assessment, not the first one

**Files:**
- Modify: `src/lalo/findings/tool.py:103-190` (`_record_finding`'s merge branch)
- Test: `tests/lalo/test_report_sarif.py` or `tests/lalo/test_findings_tool.py`
  (whichever already covers dedup-merge behavior — confirm by grepping for
  `merged into existing finding` before choosing; append there)

**Interfaces:**
- Consumes: none from other tasks in this plan.
- Produces: no signature change to `build_record_finding_tool`/`_record_finding` — the
  merge branch's internal logic changes only.

- [ ] **Step 1: Write the failing test**

  First, confirm the exact current test file and helper shape by grepping
  `tests/lalo/` for `find_duplicate` and `merged into existing finding` to find where
  merge-branch behavior is already tested, and reuse that file's existing `_file`/graph
  helper (the same pattern `test_report_sarif.py` uses: `ToolRegistry([build_record_finding_tool(graph)]).dispatch("record_finding", args)`).

  Append (adjust the helper names to match whichever file actually already tests merge
  behavior):

  ```python
  def test_dedup_merge_keeps_the_stronger_cvss_assessment_not_the_first_one() -> None:
      """Real bug this closes: the merge branch used to update only evidence/
      identities/reproduced/evidence_grounded, silently discarding the newly
      computed cvss_score/severity/vector on every duplicate filing after the
      first - the graph kept whichever assessment happened to arrive first,
      forever, even when a later filing is materially more (or less) severe."""
      graph = ReachabilityGraph()
      weak_cvss = {**_VALID_CVSS, "confidentiality": "N", "integrity": "N", "availability": "N"}
      strong_cvss = {**_VALID_CVSS, "confidentiality": "H", "integrity": "H", "availability": "H"}

      _file(graph, cvss_breakdown=weak_cvss)  # first filing: weak
      _file(graph, cvss_breakdown=strong_cvss)  # second filing, same dedup_key: strong

      (finding_id,) = [
          n for n in graph.nodes_of_kind(NodeKind.FINDING)
      ]
      node = graph.node(finding_id)
      # the STRONGER of the two computed scores must win, not the first-filed one
      assert node["cvss_severity"] in ("high", "critical")
      assert node["cvss_score"] > 0.0
  ```

  (`_file`/`_VALID_CVSS`/`NodeKind` — reuse whichever test file's own existing helpers
  already build a minimal valid `record_finding` call; `_VALID_CVSS` matches the shape
  already used in `test_report_sarif.py`.)

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_findings_tool.py::test_dedup_merge_keeps_the_stronger_cvss_assessment_not_the_first_one -v
  ```

  Expected: fails — the node's `cvss_severity` stays whatever the *first* (weak) call
  computed, not the second (strong) one.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/findings/tool.py`, the merge branch currently (confirmed by reading the
  live file):

  ```python
          existing_id = find_duplicate(graph, key)
          if existing_id is not None:
              existing = graph.node(existing_id)
              merged_evidence = [*existing.get("evidence", []), *[redact(e) for e in evidence]]
              merged_identities = sorted(
                  set(existing.get("identities_confirmed", [])) | set(identities)
              )
              graph.add_node(
                  existing_id,
                  NodeKind.FINDING,
                  evidence=merged_evidence,
                  identities_confirmed=merged_identities,
                  reproduced=existing.get("reproduced", False) or reproduced,
                  evidence_grounded=existing.get("evidence_grounded", False) or grounded,
              )
  ```

  Change to (this task's diff is additive to the existing merge fields, nothing above is
  removed). Verified exact current shape: `cvss = compute_cvss(cvss_breakdown)` is
  already computed earlier in this same function (a `CvssResult(score, severity,
  vector)`, `findings/cvss.py`), well before the `existing_id is not None` branch — it's
  in scope here unchanged, no new computation needed:

  ```python
          existing_id = find_duplicate(graph, key)
          if existing_id is not None:
              existing = graph.node(existing_id)
              merged_evidence = [*existing.get("evidence", []), *[redact(e) for e in evidence]]
              merged_identities = sorted(
                  set(existing.get("identities_confirmed", [])) | set(identities)
              )
              # Strongest-signal-wins, not first-writer-wins: a later filing of
              # the SAME dedup_key can be materially more (or less) severe than
              # the first one L4L0 happened to see - keeping whichever score is
              # higher means a weaker duplicate never waters down an already-
              # established stronger signal, and a stronger duplicate correctly
              # upgrades an initially-underestimated one, mirroring the
              # strongest-signal-across-merged-observations principle a studied
              # reference agent's own reconciliation logic applies for the
              # analogous cross-producer case.
              existing_score = float(existing.get("cvss_score", 0.0))
              merge_fields: dict[str, object] = {
                  "evidence": merged_evidence,
                  "identities_confirmed": merged_identities,
                  "reproduced": existing.get("reproduced", False) or reproduced,
                  "evidence_grounded": existing.get("evidence_grounded", False) or grounded,
              }
              if cvss.score > existing_score:
                  merge_fields["cvss_score"] = cvss.score
                  merge_fields["cvss_severity"] = cvss.severity
                  merge_fields["cvss_vector"] = cvss.vector
              graph.add_node(existing_id, NodeKind.FINDING, **merge_fields)
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_findings_tool.py -v
  uv run pytest tests/lalo/test_report_sarif.py -v
  ```

  Expected: the new test passes; every existing dedup/merge test in both files stays
  green (the change is additive — a merge where the new call's score is NOT higher than
  the existing one behaves identically to before, since `merge_fields` only gains the
  three CVSS keys when `cvss_score > existing_score`).

  ```
  uv run ruff check src/lalo/findings/tool.py tests/lalo/test_findings_tool.py
  uv run ruff format src/lalo/findings/tool.py tests/lalo/test_findings_tool.py
  uv run mypy src/lalo/findings/tool.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/findings/tool.py tests/lalo/test_findings_tool.py
  git commit -m "$(cat <<'EOF'
  fix(findings): dedup-merge keeps the stronger CVSS assessment, not the first one

  Merging a duplicate finding (same dedup_key) only ever updated evidence/
  identities/reproduced/evidence_grounded - the newly computed cvss_score/
  severity/vector was silently discarded on every filing after the first,
  so the graph kept whichever assessment happened to arrive first, forever.
  Now a merge keeps whichever of the two computed scores is higher, the same
  strongest-signal-wins policy a studied reference agent's own reconciliation
  logic applies to the analogous cross-producer case.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 4: SARIF `automationDetails.id` keys off the target, not the run directory

**Files:**
- Modify: `src/lalo/report/writer.py:167` (the `automation_id=run_dir.name` call site)
- Test: `tests/lalo/test_report_writer.py` (append)

**Interfaces:**
- Consumes: `Engagement.describe() -> str` (existing, `execution/target.py:181-189`) —
  already computed and passed into `write_report` for `ReportMetadata.engagement_scope`
  (confirmed: `scan.py`'s `_run_inside` already calls `engagement.describe()` at least
  twice for this exact purpose).
- Produces: no signature change to `write_report`/`render_sarif` — only the *value*
  `write_report` passes as `automation_id` changes, from `run_dir.name` to a stable hash
  of the engagement scope.

- [ ] **Step 1: Write the failing test**

  First, confirm `write_report`'s real signature by reading `report/writer.py` in full
  (it's referenced elsewhere in this plan as accepting a `metadata: ReportMetadata`
  parameter carrying `engagement_scope`/`model_provider` — confirm this is still
  accurate before writing the test, since this file has been modified multiple times
  this session).

  Append to `tests/lalo/test_report_writer.py`:

  ```python
  def test_sarif_automation_id_is_stable_across_two_different_run_dirs_same_target(
      tmp_path: Path,
  ) -> None:
      """Real gap this closes: automation_id used to be run_dir.name, so every
      scan of the SAME target got a different id, breaking a CI consumer's
      ability to correlate alerts across re-scans. Two scans of the same
      target (different run directories, exactly as two real re-scans would
      be) must now produce the SAME automation_id."""
      run_dir_1 = tmp_path / "run-abc123"
      run_dir_2 = tmp_path / "run-def456"
      run_dir_1.mkdir()
      run_dir_2.mkdir()
      metadata = ReportMetadata(engagement_scope="- example.com (any port, any scheme)", model_provider="anthropic:claude-sonnet-5")

      paths_1 = write_report([], _coverage(), run_dir_1, metadata=metadata)
      paths_2 = write_report([], _coverage(), run_dir_2, metadata=metadata)

      sarif_1 = json.loads(paths_1["sarif"].read_text(encoding="utf-8"))
      sarif_2 = json.loads(paths_2["sarif"].read_text(encoding="utf-8"))
      id_1 = sarif_1["runs"][0]["automationDetails"]["id"]
      id_2 = sarif_2["runs"][0]["automationDetails"]["id"]
      assert id_1 == id_2
      # And it must NOT just be a constant/empty string - still derived from
      # the real engagement, so two DIFFERENT targets get different ids.
      other_metadata = ReportMetadata(engagement_scope="- other.example.com (any port, any scheme)", model_provider="anthropic:claude-sonnet-5")
      run_dir_3 = tmp_path / "run-ghi789"
      run_dir_3.mkdir()
      paths_3 = write_report([], _coverage(), run_dir_3, metadata=other_metadata)
      sarif_3 = json.loads(paths_3["sarif"].read_text(encoding="utf-8"))
      assert sarif_3["runs"][0]["automationDetails"]["id"] != id_1
  ```

  (`_coverage()` — reuse whichever zero-argument helper this test file already has for
  building a minimal `CoverageSummary`; `ReportMetadata`/`write_report`/`json` — reuse
  the file's own existing imports, adding `ReportMetadata` from `.collect` and `json`
  from stdlib if not already imported. Adjust `write_report`'s exact call signature/
  parameter order to match what's actually in the live file if it differs from this
  sketch — the point of Step 1 here is proving the *id-stability behavior*, not
  matching an assumed call shape exactly; read the file first.)

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_report_writer.py::test_sarif_automation_id_is_stable_across_two_different_run_dirs_same_target -v
  ```

  Expected: fails at `assert id_1 == id_2` — today's `automation_id=run_dir.name` makes
  every run directory's own SARIF get a different id regardless of target.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/report/writer.py`, change the current call site:

  ```python
          automation_id=run_dir.name,
  ```

  to a stable derivation from the engagement scope already available at this call site
  (via the `metadata` parameter — confirm the exact parameter name/shape by reading the
  live function signature first):

  ```python
          # A stable identifier for the ENGAGEMENT (target/scope), not the
          # ephemeral run directory - every fresh scan of the same target gets
          # a new run_dir, so keying off that broke cross-run SARIF alert
          # correlation in any CI consumer that relies on automationDetails.id
          # to track which alerts persisted vs. got fixed across re-scans.
          automation_id=(
              hashlib.sha256(metadata.engagement_scope.encode("utf-8")).hexdigest()[:16]
              if metadata is not None
              else run_dir.name
          ),
  ```

  Add `import hashlib` to the top of `report/writer.py` (alongside its existing stdlib
  imports) if not already present.

  (The `if metadata is not None else run_dir.name` fallback preserves today's exact
  behavior for the one caller path — if any — that doesn't pass `metadata`; confirm by
  grepping `write_report(` call sites whether `metadata` is always provided in practice
  before deciding whether the fallback branch is even reachable, but keep it regardless
  for defensive completeness matching this codebase's own established style.)

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_report_writer.py -v
  ```

  Expected: the new test passes; every existing `write_report`/SARIF test in the file
  stays green (`automation_id`'s value changes, but nothing else about `render_sarif`'s
  document shape does).

  ```
  uv run ruff check src/lalo/report/writer.py tests/lalo/test_report_writer.py
  uv run ruff format src/lalo/report/writer.py tests/lalo/test_report_writer.py
  uv run mypy src/lalo/report/writer.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/report/writer.py tests/lalo/test_report_writer.py
  git commit -m "$(cat <<'EOF'
  fix(report): SARIF automation_id keys off the target, not the run directory

  Every scan gets a fresh run_dir, so automationDetails.id (run_dir.name)
  was different on every re-scan of the same target - a CI consumer relying
  on it to correlate alerts across scans (which persisted, which got fixed)
  saw every re-scan as an unrelated result set. Now derived from a stable
  hash of the engagement scope instead, so re-scanning the same target
  produces the same id while different targets still get different ids.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

## Final Check

- [ ] `uv run pytest -q -m "not integration and not live"` — full suite green.
- [ ] `uv run ruff check src/lalo tests/lalo` — zero errors.
- [ ] `uv run ruff format --check src/lalo tests/lalo` — no reformatting needed.
- [ ] `uv run mypy` — no errors.
- [ ] `git diff --name-only <base-commit>..HEAD | xargs grep -niE "shannon|pentestgpt|\bstrix\b|\bpentagi\b|\bcai\b" || echo clean` — expect clean.
- [ ] `git fsck --full` — zero errors.
- [ ] Confirm no new restriction was introduced anywhere: every fix in this plan is a
  lock, a try/except, a merge-policy change favoring more information, or an id
  derivation change — none of them change what the agent is permitted to do or report.
