# Usage Accounting Survives Replay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A step whose usage was recorded but whose journal entry never
landed before a crash no longer double-counts when that step is redone
on resume — every existing `UsageStats` field keeps its exact shape.

**Architecture:** `UsageStats` gains one new field, `by_step`, keyed by
the exact `f"{agent_key}:{step}"` string the journal already uses for
that step. `record_usage(..., step_key=...)` subtracts a step's prior
recorded delta back out before adding its new one, so only the latest
attempt at any given step ever counts. `agent/loop.py` threads that same
key through its own step loop — no new state, no new coordination
mechanism between the journal and the usage ledger.

**Tech Stack:** Python 3.13, `uv`.

**Spec:** `docs/superpowers/specs/2026-09-08-usage-accounting-survives-replay-design.md`

## Global Constraints

- `total_requests`, `total_input_tokens`, `total_output_tokens`,
  `total_cost_usd`, `by_provider`, `by_agent` keep their EXACT current
  shape and meaning — no downstream reader (`report/collect.py`,
  `report/markdown.py`, `report/html.py`, `scan.py`'s usage-delta diffing)
  needs any change.
- `step_key=None` (the default on `record_usage`) preserves today's exact
  plain-accumulate behavior — every existing caller and every existing
  test that doesn't pass `step_key` must see zero behavior change.
- `_compact_history`'s own `_complete(...)` call is NOT given a step_key —
  compaction isn't tied to a journaled mission step.

---

## Task 1: `UsageStats.by_step` + recompute-from-attempts in `record_usage`

**Files:**
- Modify: `src/lalo/core/usage.py`
- Test: `tests/lalo/test_usage.py`

**Interfaces:**
- Produces: `UsageStats.by_step: dict[str, dict[str, object]]` (new field,
  default `{}`); `record_usage(response, *, path=DEFAULT_USAGE_PATH,
  pricing_table=None, cost_limit_usd=None, agent_id=None,
  step_key: str | None = None) -> UsageStats`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/lalo/test_usage.py` (after the existing per-agent-breakdown
test, using the file's own `_response()`/`_PRICING` fixtures):

```python
def test_record_usage_with_a_step_key_replaces_not_adds_a_second_attempt(
    tmp_path: Path,
) -> None:
    path = tmp_path / "usage.json"
    record_usage(
        _response(input_tokens=1000, output_tokens=500),
        path=path,
        pricing_table=_PRICING,
        agent_id="root",
        step_key="root:0",
    )
    # The crash-timing race this closes: the SAME step is redone (a
    # genuinely new completion, different token counts here to prove it's
    # not coincidentally identical) after a crash that landed between the
    # first attempt's usage recording and its own journal write.
    stats = record_usage(
        _response(input_tokens=200, output_tokens=100),
        path=path,
        pricing_table=_PRICING,
        agent_id="root",
        step_key="root:0",
    )
    assert stats.total_requests == 1  # not 2
    assert stats.total_input_tokens == 200  # the SECOND attempt's numbers only
    assert stats.total_output_tokens == 100
    assert stats.by_provider["anthropic"]["requests"] == 1
    assert stats.by_agent["root"]["requests"] == 1
    assert stats.by_agent["root"]["input_tokens"] == 200


def test_record_usage_with_different_step_keys_both_count(tmp_path: Path) -> None:
    path = tmp_path / "usage.json"
    record_usage(_response(input_tokens=100), path=path, step_key="root:0")
    stats = record_usage(_response(input_tokens=200), path=path, step_key="root:1")
    assert stats.total_requests == 2
    assert stats.total_input_tokens == 300


def test_record_usage_without_a_step_key_still_accumulates_normally(tmp_path: Path) -> None:
    path = tmp_path / "usage.json"
    record_usage(_response(input_tokens=100), path=path)
    stats = record_usage(_response(input_tokens=200), path=path)
    assert stats.total_requests == 2  # no step_key -> no dedup, exactly today's behavior
    assert stats.total_input_tokens == 300


def test_usage_stats_round_trips_by_step(tmp_path: Path) -> None:
    path = tmp_path / "usage.json"
    record_usage(_response(input_tokens=100), path=path, step_key="root:0")
    stats = load_usage(path)
    assert stats.by_step["root:0"]["input_tokens"] == 100
```

(`load_usage` is already imported at the top of `test_usage.py`.)

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/lalo/test_usage.py -k "step_key or round_trips_by_step" -v`
Expected: FAIL — `record_usage() got an unexpected keyword argument 'step_key'`.

- [ ] **Step 3: Implement**

In `src/lalo/core/usage.py`, add the new field to `UsageStats` (after
`by_agent`):

```python
    # Keyed by the exact same "{agent_key}:{step}" string the durable
    # journal itself uses for that step's own tool-dispatch entry (see
    # agent/loop.py's own journal.run_once call). A crash between this
    # step's own LLM completion recording its usage and that same step's
    # journal write landing means the WHOLE step re-runs live on resume -
    # a genuinely new completion, a genuinely new record_usage() call for
    # what is really the same logical step. Rather than trusting an
    # ever-incrementing running total that can't un-double-count once a
    # step's usage lands twice, record_usage's own step_key argument
    # recomputes the affected totals from the CURRENT set of per-step
    # attempts: an already-seen step_key's prior contribution is
    # subtracted back out before the new attempt's is added, so only the
    # LATEST attempt at any given step ever counts.
    by_step: dict[str, dict[str, object]] = field(default_factory=dict)
```

Update `to_dict`/`from_dict`:

```python
    def to_dict(self) -> dict[str, object]:
        return {
            "total_requests": self.total_requests,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cost_usd": self.total_cost_usd,
            "by_provider": self.by_provider,
            "by_agent": self.by_agent,
            "by_step": self.by_step,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> UsageStats:
        by_provider_raw = data.get("by_provider")
        by_provider = dict(by_provider_raw) if isinstance(by_provider_raw, dict) else {}
        by_agent_raw = data.get("by_agent")
        by_agent = dict(by_agent_raw) if isinstance(by_agent_raw, dict) else {}
        by_step_raw = data.get("by_step")
        by_step = dict(by_step_raw) if isinstance(by_step_raw, dict) else {}
        return cls(
            total_requests=int(data.get("total_requests", 0)),  # type: ignore[call-overload]
            total_input_tokens=int(data.get("total_input_tokens", 0)),  # type: ignore[call-overload]
            total_output_tokens=int(data.get("total_output_tokens", 0)),  # type: ignore[call-overload]
            total_cost_usd=float(data.get("total_cost_usd", 0.0)),  # type: ignore[arg-type]
            by_provider=by_provider,
            by_agent=by_agent,
            by_step=by_step,
        )
```

Extract the increment logic into a signed helper (module-level function,
above `record_usage`), then rewrite `record_usage` to use it twice
(subtract the prior attempt, add the new one):

```python
def _apply_delta(
    stats: UsageStats,
    *,
    provider: str,
    agent_id: str | None,
    input_tokens: int,
    output_tokens: int,
    cost: float | None,
    sign: int,
) -> None:
    stats.total_requests += sign
    stats.total_input_tokens += sign * input_tokens
    stats.total_output_tokens += sign * output_tokens
    if cost is not None:
        stats.total_cost_usd += sign * cost

    provider_stats = stats.by_provider.setdefault(
        provider, {"requests": 0.0, "input_tokens": 0.0, "output_tokens": 0.0, "cost_usd": 0.0}
    )
    provider_stats["requests"] += sign
    provider_stats["input_tokens"] += sign * input_tokens
    provider_stats["output_tokens"] += sign * output_tokens
    if cost is not None:
        provider_stats["cost_usd"] += sign * cost

    if agent_id:
        agent_stats = stats.by_agent.setdefault(
            agent_id, {"requests": 0.0, "input_tokens": 0.0, "output_tokens": 0.0, "cost_usd": 0.0}
        )
        agent_stats["requests"] += sign
        agent_stats["input_tokens"] += sign * input_tokens
        agent_stats["output_tokens"] += sign * output_tokens
        if cost is not None:
            agent_stats["cost_usd"] += sign * cost


def record_usage(
    response: CompletionResponse,
    *,
    path: Path = DEFAULT_USAGE_PATH,
    pricing_table: PricingTable | None = None,
    cost_limit_usd: float | None = None,
    agent_id: str | None = None,
    step_key: str | None = None,
) -> UsageStats:
    """Add ``response``'s usage to the persisted lifetime total and return it.

    The update is always persisted first, even if ``cost_limit_usd`` is then
    exceeded — the API call already happened and already cost real money, so
    the ledger reflects that regardless of whether the caller stops the run
    afterward (see :class:`~lalo.core.errors.CostLimitExceededError`'s own
    docstring for why this is the opposite order from the reference this
    module is informed by).

    ``agent_id`` (root or a spawned child's own id) attributes this response
    to ``by_agent`` the same way ``response.provider`` already attributes it
    to ``by_provider`` - omitted (the default) when the caller has no agent
    identity to report, in which case only the lifetime/by_provider totals
    are updated, exactly as before this parameter existed.

    ``step_key`` (the exact ``f"{agent_key}:{step}"`` string the durable
    journal itself uses for that step) closes a real crash-timing race: a
    resumed step whose LLM completion already recorded usage here, but
    whose own journal entry never landed before a crash, re-runs in full on
    resume - a genuinely new completion. Passing the SAME step_key a second
    time subtracts that step's prior recorded delta back out before adding
    the new one, so only the latest attempt at any given step is ever
    reflected in the totals. ``None`` (the default) preserves the exact
    plain-accumulate behavior every existing caller already relies on.
    """
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
            input_tokens=int(prior["input_tokens"]),  # type: ignore[arg-type]
            output_tokens=int(prior["output_tokens"]),  # type: ignore[arg-type]
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

(This removes the old inline increment block entirely, replacing it with
the two `_apply_delta` calls above — every existing behavior for a caller
that never passes `step_key` is unchanged: the `if step_key is not None
and step_key in stats.by_step:` subtract branch never fires, and the one
`_apply_delta(..., sign=1)` call does exactly what the old inline code did.)

- [ ] **Step 4: Run to verify they pass, then the full existing usage suite**

Run: `uv run pytest tests/lalo/test_usage.py -v`
Expected: PASS, every test (including every pre-existing one — this
confirms the refactor changed no existing behavior).

- [ ] **Step 5: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/core/usage.py tests/lalo/test_usage.py
git commit -m "feat(L4L0): UsageStats.by_step + recompute-from-attempts dedup in record_usage"
```

---

## Task 2: Thread `step_key` through `agent/loop.py`'s step loop

**Files:**
- Modify: `src/lalo/agent/loop.py` (`_complete`,
  `_retry_through_provider_outage`, `run()`'s call site)
- Test: `tests/lalo/test_agent_loop.py`

**Interfaces:**
- Consumes: `record_usage(..., step_key=...)` (Task 1).
- Produces: `_complete(self, prompt, *, system=None, step_key=None)`;
  `_retry_through_provider_outage(self, prompt, *, step_key=None)`.

- [ ] **Step 1: Write the failing test**

Add to `tests/lalo/test_agent_loop.py`, right after
`test_a_crash_after_journaling_but_mid_step_still_resumes_correctly`
(reusing that same test's established `should_stop`-free, real-crash
style, but here the crash must land AFTER the step's completion succeeds
and usage is recorded, and BEFORE that step's own journal write lands —
achieved by subclassing `DurableJournal` to fail its `record()` call
exactly once):

```python
class _CrashOnFirstJournalWrite(DurableJournal):
    """Lets the step's own tool dispatch genuinely run (a real side
    effect, exactly like a real crash landing after the LLM call already
    succeeded) but fails durably recording it - the precise window this
    task closes a usage-double-count in, matching this project's own
    established practice of testing an exact crash-timing window directly
    rather than approximating it.
    """

    def __init__(self, path) -> None:
        super().__init__(path)
        self._raised = False

    def record(self, key: str, result: object) -> None:
        if not self._raised:
            self._raised = True
            raise RuntimeError("simulated crash mid tool-dispatch-journal-write")
        super().record(key, result)


def test_a_step_redone_after_a_crash_before_its_journal_write_is_not_double_billed(
    tmp_path,
) -> None:
    tool, calls = _counting_tool("probe")
    registry = ToolRegistry([tool])
    usage_path = tmp_path / "usage.json"
    journal = _CrashOnFirstJournalWrite(tmp_path / "j.jsonl")
    router1 = _scripted(['{"tool": "probe", "args": {}}'])
    loop1 = AgentLoop(router1, registry, system_prompt="", usage_path=usage_path)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="simulated crash"):
        loop1.run("mission", journal=journal, agent_key="root")
    # The real side effect happened (the tool actually ran) and usage was
    # actually recorded, but the step's own journal entry never landed.
    assert calls["n"] == 1
    assert load_usage(usage_path).total_requests == 1
    assert not journal.has("root:0")

    # Resume: the un-journaled step redoes in full - a genuinely new
    # completion, a genuinely new usage record for the SAME step_key.
    router2 = _scripted(
        ['{"tool": "probe", "args": {}}', '{"tool": "finish", "args": {"summary": "done"}}']
    )
    loop2 = AgentLoop(router2, registry, system_prompt="", usage_path=usage_path)  # type: ignore[arg-type]
    result = loop2.run("mission", journal=journal, agent_key="root")

    assert result.stop_reason == "finished"
    assert calls["n"] == 2  # the tool really did run twice (a real re-dispatch)
    # But the usage ledger counts it once, not twice - recompute-from-attempts.
    assert load_usage(usage_path).total_requests == 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/lalo/test_agent_loop.py -k not_double_billed -v`
Expected: FAIL — `assert load_usage(usage_path).total_requests == 1` fails
with `2 == 1` (today's code has no `step_key` dedup at all, so the second
attempt's usage simply adds on top of the first).

- [ ] **Step 3: Implement**

In `src/lalo/agent/loop.py`, `_complete` (currently):

```python
    def _complete(self, prompt: str, *, system: str | None = None) -> CompletionResponse | None:
        ...
        effective_system = system if system is not None else self.system_prompt
        try:
            response = self.router.complete(
                self.config.role, CompletionRequest(prompt=prompt, system=effective_system)
            )
        except AllProvidersFailedError:
            return None
        if self.usage_path is not None:
            try:
                record_usage(
                    response,
                    path=self.usage_path,
                    agent_id=self.agent_id,
                    pricing_table=self.pricing_table,
                )
            except Exception:
                _log.exception("usage recording failed; continuing without it")
        return response
```

becomes (one new parameter, threaded straight into the existing
`record_usage` call):

```python
    def _complete(
        self, prompt: str, *, system: str | None = None, step_key: str | None = None
    ) -> CompletionResponse | None:
        ...
        effective_system = system if system is not None else self.system_prompt
        try:
            response = self.router.complete(
                self.config.role, CompletionRequest(prompt=prompt, system=effective_system)
            )
        except AllProvidersFailedError:
            return None
        if self.usage_path is not None:
            try:
                record_usage(
                    response,
                    path=self.usage_path,
                    agent_id=self.agent_id,
                    pricing_table=self.pricing_table,
                    step_key=step_key,
                )
            except Exception:
                _log.exception("usage recording failed; continuing without it")
        return response
```

`_retry_through_provider_outage` (currently):

```python
    def _retry_through_provider_outage(self, prompt: str) -> CompletionResponse | None:
        ...
        for attempt in range(self.config.provider_outage_max_retries):
            delay = self.config.provider_outage_base_delay_s * (2**attempt)
            self._emit("provider_outage_retry", {"attempt": attempt + 1, "delay_s": delay})
            if not self._interruptible_sleep(delay):
                return None
            response = self._complete(prompt)
            if response is not None:
                self._emit("provider_outage_recovered", {"attempt": attempt + 1})
                return response
        return None
```

becomes:

```python
    def _retry_through_provider_outage(
        self, prompt: str, *, step_key: str | None = None
    ) -> CompletionResponse | None:
        ...
        for attempt in range(self.config.provider_outage_max_retries):
            delay = self.config.provider_outage_base_delay_s * (2**attempt)
            self._emit("provider_outage_retry", {"attempt": attempt + 1, "delay_s": delay})
            if not self._interruptible_sleep(delay):
                return None
            response = self._complete(prompt, step_key=step_key)
            if response is not None:
                self._emit("provider_outage_recovered", {"attempt": attempt + 1})
                return response
        return None
```

`run()`'s own call site (currently):

```python
                directive = self._budget_directive()
                prompt = self._render_prompt(mission, transcript, directive)
                with self.tracer.span("llm_completion", step=step, agent_id=self.agent_id):
                    response = self._complete(prompt)
                if response is None:
                    response = self._retry_through_provider_outage(prompt)
```

becomes:

```python
                directive = self._budget_directive()
                prompt = self._render_prompt(mission, transcript, directive)
                step_key = f"{agent_key}:{step}"
                with self.tracer.span("llm_completion", step=step, agent_id=self.agent_id):
                    response = self._complete(prompt, step_key=step_key)
                if response is None:
                    response = self._retry_through_provider_outage(prompt, step_key=step_key)
```

(`agent_key` is already the `run()` parameter in scope at this exact call
site — no new state needed. `_compact_history`'s own `_complete(prompt,
system=_COMPACTION_SYSTEM_PROMPT)` call is untouched — it has no step_key
to offer and none of this task's tests expect it to.)

- [ ] **Step 4: Run to verify it passes, then the full existing loop suite**

Run: `uv run pytest tests/lalo/test_agent_loop.py -v`
Expected: PASS, every test — in particular
`test_usage_is_recorded_when_a_usage_path_is_provided` (asserts
`total_requests == 2` for two DIFFERENT steps in one fresh run) must
still pass unchanged: different steps get different `step_key`s, so no
dedup fires between them.

- [ ] **Step 5: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/agent/loop.py tests/lalo/test_agent_loop.py
git commit -m "feat(L4L0): thread step_key through the loop so redone steps aren't double-billed"
```

---

## Final Check (after both tasks)

1. Full check: `uv run ruff check src/lalo tests/lalo && uv run ruff format --check src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"` — must be fully green.
2. Whole-branch review: confirm `report/collect.py`, `report/markdown.py`,
   `report/html.py`, and `scan.py`'s own usage-delta diffing are
   byte-identical in behavior (none of them read `by_step`, and every
   field they DO read keeps its exact prior meaning for a caller that
   never passes `step_key` — `scan.py`'s own root/child `AgentLoop`
   construction sites need NO changes at all, since `step_key` is
   computed entirely inside `run()`'s own loop, not passed in from
   outside).
3. No live Playwright check needed — backend-only, no GUI-visible change
   (a usage ledger's exact per-step accounting is not surfaced anywhere
   in the UI beyond the totals it already showed before this plan).
