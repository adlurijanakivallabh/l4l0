# Gap-Closure Round 5 — Design

## Context

A 13-way parallel exhaustive research pass read the entire real source of a studied
reference agent's codebase (~227 files across its core engine, prompt library, CLI,
report templates, and self-documentation — every file, not sampled) and cross-checked
every distinct function/feature/technique found against the live current state of L4L0
(`/home/kali/Downloads/reachagent`, package `lalo`, branch `project-lalo`). This is the
third such comparison pass this session; the first two closed their own gap lists (see
`docs/superpowers/plans/2026-09-07-shannon-gap-closure.md` and
`docs/superpowers/plans/2026-09-08-gap-closure-round-4.md`). This pass went one level
deeper — function/feature granularity, not architectural-comparison-doc granularity —
per the operator's explicit request, and reused the operator's own prior directive: no
CLI, no restrictions, L4L0 must end up a strict superset of the reference's real
capability.

Four of the research findings turned out, on direct verification against live source, to
be genuine correctness bugs rather than missing capabilities. The rest are real,
verified capability/quality gaps, organized below by theme. Everything the research
flagged as an intentional non-goal (a permission/confirmation gate, Temporal adoption, a
fixed multi-stage SAST pipeline, a CLI/TUI, host-credential-file mounting, a second TOML
config layer) is excluded — porting any of those would be a regression against this
project's own already-decided design center, not a gap in it.

**Operator's own scoping instructions, verbatim and binding:** "fix each and every gap
and each and every bug properly and completely... our project must be convenient and
fully freedom and all types of attacks can be detected no restrictions must be there in
our project." Nothing in this spec is deferred or cut on the operator's own instruction —
three items the drafting pass had proposed deprioritizing (packaged CI/CD integration,
per-agent log-file splitting, LLM-call cancellation) are included in full below.

## Global Constraints

- **No CLI/TUI.** `pyproject.toml`'s own design center; GUI is the only operator
  interface (`setup.py`'s credential wizard is the one already-accepted, narrow
  exception). Nothing in this spec adds a terminal command.
- **No restrictions.** Every new mechanism below is additive capability, an optional
  agent-callable tool, or a correctness fix — never a confirmation gate, permission
  check, or default-on limitation. Where a candidate idea from the research was
  gate-shaped (a studied reference agent's own permission-system/path-confinement
  mechanism, its fixed vuln-class pipeline, its pre-planning "task formation" stage), it
  is excluded here as an intentional non-goal, not silently softened into a weaker gate.
- **Agent-driven methodology, not fixed detector code.** Every methodology-shaped
  addition (severity-calibration refinements, new attack-surface techniques, the
  cross-agent-dedup discipline) lands as skill-file/prompt guidance the agent may apply,
  never as a mandatory Python gate on what counts as a finding.
- **No reference-project names** anywhere in code, comments, docs, module names, or
  commit messages (this project's standing clean-room policy) — every citation below
  describes a pattern generically for planning purposes; the actual code/docs written
  from this spec use the established "a studied reference agent's own X" phrasing.
- **Honest coverage stays honest.** Every new positive-assertion mechanism (the
  `record_safe` tool, the coverage sub-taxonomy) must make the report *more* accurate
  about what was and wasn't tested, never let a surface get marked clean without real
  evidence.

## Part A — Bug fixes (4 items, independently verified against live source)

These are defects, not capability gaps — worth fixing regardless of anything else in
this spec, and small enough to land first.

### A1. `record_usage()`'s file-backed ledger has no lock

**File:** `src/lalo/core/usage.py:157-229` (`record_usage`)

**Current behavior (verified):** `load_usage(path)` → mutate the in-memory `UsageStats`
→ `atomic_write_verified(path, ...)`. No lock guards this read-modify-write sequence.
`src/lalo/scan.py` passes the *same* `self.config.usage_path` to the root `AgentLoop`
and to every child `AgentLoop` a `spawn_agents` fan-out creates on real `ThreadPoolExecutor`
threads — a textbook lost-update race: two children's concurrent `record_usage` calls
both read the same starting state, and whichever writes second silently discards the
first's delta (including, worst case, an already-spent cost that a `cost_limit_usd`
check should have seen).

**Fix:** A module-level `threading.Lock()` (matching the exact pattern already used by
`Budget._lock`, `Tracer._lock`, `ScanRunner._graph_lock`, `HttpFirer._breaker_lock`, and
`DurableJournal`'s own lock — this project's established idiom for state
`spawn_agents`' concurrent children share) held around the load→mutate→write sequence in
`record_usage`. `load_usage` itself (a pure read, called elsewhere for display) stays
unlocked — only the read-modify-write in `record_usage` needs it.

### A2. The post-loop confidence/review pass can crash-loop a scan forever

**File:** `src/lalo/scan.py:1332-1350` (the `for finding_id in graph.nodes_of_kind(NodeKind.FINDING):`
loop inside `_run_inside`, in the `else` branch of the idempotent-resume check)

**Current behavior (verified):** No `try`/`except` around `compute_confidence()` or
`run_adversarial_review()`. Nothing in this loop is journaled (`journal.run_once` is used
only inside `agent/loop.py`'s own step loop). If review raises for any one finding — a
provider returning something `extract_json_object` can't parse, a total provider-chain
failure — the whole `ScanRunner.run()` call crashes uncaught. Because nothing here is
journaled, a resumed run replays the identical already-completed agent-loop steps (a fast
no-op) and then re-enters this exact same unprotected loop from finding zero, hitting the
identical deterministic failure again. There is no recovery path today short of manually
editing the run directory.

**Fix:** Two changes, both required for this to actually close:
1. Wrap each finding's `compute_confidence`/`run_adversarial_review` call in its own
   `try`/`except Exception`, degrading that one finding to `open_proof_gap` at its
   unadjusted confidence score (mirroring `run_adversarial_review`'s own existing
   degrade-on-provider-failure behavior, just widened to cover an exception path that
   currently isn't caught at all) rather than aborting the whole run.
2. Journal each finding's review outcome — `journal.run_once(f"review:{finding_id}", ...)`
   — so a resume that reaches this loop again adopts already-reviewed findings from the
   journal instead of re-running review (and re-spending an LLM call) for every finding
   on every resume, and only ever retries a finding that never completed.

### A3. Dedup-merging a finding silently discards its CVSS/severity on every later filing

**File:** `src/lalo/findings/tool.py:141-167` (`_record_finding`'s `if existing_id is not None:` branch)

**Current behavior (verified):** The merge branch updates `evidence` (concatenate),
`identities_confirmed` (union), `reproduced` (OR), and `evidence_grounded` (OR) on the
existing node. It never touches `cvss_score`/`cvss_severity`/`cvss_vector`/`title`/
`description`/`counterevidence`/`remediation` — all computed fresh from the new call's
`args` just above this branch, then silently dropped. The graph node keeps whichever
severity assessment the *first* call to file this `dedup_key` happened to report, forever,
even when a later, better-evidenced filing computes a materially different (higher *or*
lower) CVSS score.

**Fix:** On a merge, keep the *stronger* signal, not the first one — compare the newly
computed `cvss_score` against `existing.get("cvss_score")` and update
`cvss_score`/`cvss_severity`/`cvss_vector` (and, if changed, `title`/`description` — the
fields a stronger, more specific filing is more likely to have gotten right) to whichever
call scored higher. Mirrors the same "strongest signal wins across merged observations"
principle the research verified in the reference's own reconciliation logic, applied here
to L4L0's single-producer dedup-merge instead of a cross-producer reconciliation stage.

### A4. SARIF's `automationDetails.id` breaks cross-run alert correlation

**Files:** `src/lalo/report/writer.py:167` (`automation_id=run_dir.name`),
`src/lalo/report/sarif.py:221-226` (`render_sarif`)

**Current behavior (verified):** Every scan gets a fresh `run_dir` (a fresh `run_id`), so
`automation_id` is different on every scan of the *same* target — a CI consumer (GitHub
code-scanning, etc.) that keys alert persistence/dedup off `automationDetails.id` sees
every re-scan as an entirely new, unrelated result set, defeating the point of tracking
which alerts persisted vs. got fixed across scans.

**Fix:** Derive `automation_id` from a stable identifier of the *engagement* (the
target/scope), not the ephemeral run directory — e.g. a stable hash or normalized form
of `Engagement.describe()`/the sorted `target_specs` list, threaded from `scan.py` into
`write_report`'s existing `automation_id` parameter. `render_sarif`'s own signature needs
no change; only the value `writer.py` passes changes.

## Part B — Capability superset additions

### B1. Honest coverage: positive "tested and confirmed clean" assertions

The single highest-confidence gap in the whole analysis — it surfaced independently
across four separate research chunks (report-content, collectors, services, docs), and
`report/coverage.py`'s own current code has no way to represent it: `CoverageSummary` is
a binary `assessed`/`not_assessed` list computed purely from "did any filed finding
mention this vuln_class" (`src/lalo/report/coverage.py:59-76`). It cannot distinguish
"tested this thoroughly, genuinely clean" from "nobody ever looked" — CLAUDE.md's own
"Honest coverage" principle states the intent but the mechanism to back it doesn't exist.

**New agent tool: `record_safe`** (new function in `src/lalo/findings/tool.py`, alongside
`build_record_finding_tool`), symmetric to `record_finding`: takes `vuln_class`,
`target`, `param` (optional), and a required `defense_mechanism` (why this is
believed safe — e.g. "parameterized query confirmed via source read," "CSP `script-src
'self'` blocks injected script, verified via response header"). Lands as a new
`NodeKind.VERIFIED_SAFE` graph node (new enum member, `src/lalo/graph/model.py`), never
a `FINDING` — it's evidence of absence-of-vulnerability, not itself a vulnerability
record, so it must never be confused with or merged into the finding dedup/confidence/
review pipeline. Never a gate: calling it or not calling it never blocks, limits, or
alters what the agent may otherwise do.

**`build_coverage_summary` extended** to accept these nodes: a vuln_class with a
`VERIFIED_SAFE` node but no `FINDING` renders as a third state — "assessed, clean" —
distinct from `not_assessed`. `report/markdown.py`/`report/html.py` render this state
with the `defense_mechanism` reasoning inline (matching the reference's own narrative
"tested X, here's why it's clean" framing the research found in finished sample
reports), closing the report-richness gap (B2 below) for this specific case at the same
time.

**Coverage sub-taxonomy for the genuinely-unassessed case:** extend `CoverageSummary`
with a reason per not-assessed class where one is knowable — "no agent ever attempted
this class" (the default, unchanged case) vs. "an agent attempted this and the attempt
itself failed/crashed" (derivable from `AgentCoordinator`'s own already-tracked
per-child success/failure state, `agent/spawn.py`). Never blocks anything; purely a
richer, more honest coverage report.

### B2. Report content richness

All of the following are **agent-authored data captured at `record_finding` time,
rendered deterministically** — consistent with `report/collect.py`'s own explicit
"report rendering is never an LLM decision point" principle (confirmed, already adopted
from the reference's own renderer discipline). None of these invent content at render
time; each is a schema field the agent already implicitly knows the answer to when it
calls `record_finding`, plus a render-path addition.

- **`Finding.prerequisites: str`** (optional, default `""`) — what access/credentials an
  attacker needs before this finding is reachable (e.g. "none — publicly accessible" vs.
  "requires a valid low-privilege session"). Rendered as its own labeled field per
  finding, alongside the existing severity/CVSS/confidence lines.
- **`Finding.impact: str`** (optional, default `""`) — a short, distinct-from-`description`
  statement of what an attacker can *do* with this, business-consequence framed. Kept
  separate from `description` (what the bug is) rather than folded in, matching the
  reference's own Overview/Impact split every sample finding used.
- **Structured exploitation steps**: `Finding.evidence` stays exactly as-is (a flat
  `list[str]`, never touched — evidence-grounding/`is_grounded()` continues to operate
  on it unchanged); add `Finding.exploitation_steps: list[str]` (optional, default `[]`)
  as agent-authored ordered, titled reproduction narration ("1. Authenticate as low-priv
  user... 2. Request `/api/admin/users/1` directly..."), rendered as a numbered list
  above the raw evidence blobs rather than replacing them.
- **Executive-summary rollups** (`report/collect.py`'s `ExecutiveSummary`, pure
  aggregation over already-collected `FindingRecord`s, zero new agent-facing surface):
  a `by_confidence` band count (High ≥ 80 / Medium ≥ 50 / Low < 50, matching
  `findings/confidence.py`'s own existing 0-100 scale) and a `critical_findings: list[str]`
  (titles of every `effective_severity == "critical"` finding), both rendered near the
  top of the Executive Summary section every format already has.
- **A dedicated Findings-Overview table**: one row per finding (id/title/vuln_class/
  severity/confidence), rendered once near the top of `markdown.py`/`html.py`'s output,
  before the verdict-grouped detail sections — a scannable index the reference's finished
  reports all have and L4L0's current anchor-link list under-serves.
- **A dedicated attack-surface/recon section**: a new report section (not tied to any
  specific finding) surfacing what `recon/facts.py`'s `merge_facts()` gate already
  captured (open services, endpoints, fingerprinted technologies) — reads directly from
  existing `ReachabilityGraph` node kinds (`ENDPOINT`/`SERVICE`/`FINGERPRINT`), no new
  agent-facing tool or data capture needed, purely a new render pass over data L4L0
  already has and currently never surfaces in the delivered report.
- **Render branching on `reproduced`**: `FindingRecord.reproduced: bool` already exists
  and is already captured; `render_finding_md`/`render_finding_html` currently render
  every finding identically regardless of it. Branch the section labeling/ordering (e.g.
  "Exploitation Steps" + evidence when `reproduced`, "Analysis" + evidence when not) —
  pure render-logic, the underlying data already exists.

### B3. Browser-driven auth parity with HTTP auth

L4L0's HTTP/JSON login already gets one preflight-and-reuse-across-agents treatment
(`identity/login.py`'s `login()` + `SessionRegistry`, called once during
`ScanRunner`'s preflight via `_preflight_logins`). A UI-driven SSO/SPA login — anything
`identity/login.py`'s mechanical form/JSON model can't express — has no equivalent:
`browser/session.py`'s `BrowserSession` is a fresh in-process Playwright page per scan
with no storage-state export/import, so nothing about a browser-driven login survives
across the one shared `BrowserSession` object's own lifetime in a structured, verifiable
way, and no preflight step ever attempts one.

- **`BrowserSession.export_storage_state()` / `.import_storage_state(state)`** — thin
  wrappers over Playwright's own `context.storage_state()`/`browser.new_context(storage_state=...)`,
  letting a captured authenticated session (cookies + localStorage) be saved once and
  reused, the same reuse-across-agents shape `SessionRegistry` already gives HTTP logins.
- **A browser-driven login preflight step** (new, in `scan.py`'s existing preflight
  chain, alongside `_preflight_logins`): for a `LoginScheme` whose type marks it
  browser-driven (new, opt-in — nothing about existing HTTP/JSON schemes changes), drive
  `BrowserSession` through the configured flow once during preflight, verify success via
  a real, checkable condition (a URL substring or a specific element becoming
  present/absent — never "the agent said so"), and only then export the storage state
  into the shared session for reuse. Mirrors `_preflight_logins`' own existing
  "validate before burning mission budget on broken auth" motivation, extended to the
  one auth shape it currently can't reach at all.

### B4. Runtime correctness/isolation (non-restrictive)

- **Schema-check structured LLM output.** `findings/review.py`'s `run_adversarial_review`
  (`extract_json_object(text)`, `src/lalo/core/json_response.py`) only confirms the
  response is *valid JSON*, never that it has the right shape (`verdict` is one of the
  three real enum values, `proof_level` is a string, etc.) — a malformed-but-parseable
  response is currently accepted as a real verdict at face value. Add a small, local
  shape check (no new dependency — a handful of `isinstance`/membership checks) right
  after `extract_json_object` returns, degrading to `open_proof_gap` on a shape mismatch
  the same way a total parse failure already does. Keeps L4L0's existing free-text-JSON
  provider-portable tool-calling convention completely intact — this is a shape check on
  an already-parsed dict, not a switch to native function-calling.
- **Confined-child tool-allowlist self-check.** `scan.py`'s `role="source_reviewer"`
  path (`_ROLE_TOOL_NAMES`, `_build_registry(child_graph, child_id, tool_names=...)`)
  builds a restricted `ToolRegistry` for a confined child but never re-verifies the
  registry it actually handed the child matches the intended set — a one-line assertion
  (`assert set(registry.names()) == expected_names`) before dispatch catches a future
  wiring bug (an accidental extra tool, or a missing one) rather than silently running
  with the wrong toolset. A correctness self-check on L4L0's *own* already-decided
  confinement, not a new authorization boundary.
- **Per-child scratch-directory namespace.** `spawn_agents`' `ThreadPoolExecutor` runs
  several children as real concurrent OS threads inside the *same* disposable container;
  any child using `run_command` to write scratch files, clone a repo for source review,
  or stage payloads currently has no per-agent working-directory namespace, risking
  scratch-filename collisions between concurrent siblings. A cheap fix: have
  `_build_registry`/the child-dispatch path set (or document/prepend to the child's own
  task prompt) a per-child scratch subdirectory name derived from the already-unique,
  system-generated `agent_id` (never the agent-chosen `name`/`task` free text) — the
  filesystem analogue of `isolate_for_child`'s existing graph-snapshot isolation.
- **Non-retryable provider-failure classification.** `agent/loop.py`'s
  `_retry_through_provider_outage` retries any total provider-chain failure
  unconditionally through a multi-minute exponential backoff, with no distinction
  between a transient outage and a permanently-invalid credential (a `401`) or a
  context-length-exceeded failure — neither of which any amount of retrying, or even
  failing over to a different provider, can fix. `core/errors.py` already has the
  building blocks (`ProviderRefusalError`/`ProviderUnavailableError`); thread that
  existing classification into the outer retry loop to skip the wait-and-retry cycle
  entirely on a known-permanent failure class, surfacing the real error immediately
  instead of burning the full backoff schedule first.
- **Bounded retry on transient journal/atomic-write I/O.** `orchestrator/journal.py`'s
  `record()` and `core/atomic_io.py`'s `atomic_write_verified`/`append_owner_only_line`
  each perform a single write attempt; a transient `OSError` (a momentarily-full disk, a
  brief NFS hiccup) aborts the whole run today. A small bounded retry (2-3 attempts,
  short fixed delay) on `OSError` specifically — cheap, deterministic I/O is safe to
  retry, matching the reasoning the research verified in the reference's own
  deterministic-vs-model retry-profile split.
- **`usage_accounting_complete` signal.** `core/usage.py`'s `UsageStats` has no way to
  say "this total might be an undercount" — add a boolean (and, if ever needed, a
  reasons list) that flips `False` whenever a `record_usage` call itself fails after
  its own retries (see above) or hits an unexpected shape, surfaced in the GUI/report
  usage summary rather than silently presenting a possibly-partial number as final.
  Matches CLAUDE.md's own "coverage is machine-observed, not asserted" principle,
  applied to cost/usage reporting specifically.

### B5. Cheap, doc-only / small-mechanism wins

- **Centralized run-artifact filenames.** `"events.jsonl"`, `"resume_manifest.json"`,
  `"narrative.log"`, and `"usage.json"` are each duplicated as literal strings across
  2-4 separate files (`scan.py`, `orchestrator/narrative.py`, `gui/app.py`,
  `core/usage.py` — confirmed by grep). A small `src/lalo/paths.py` (or equivalent)
  centralizing these as named constants, imported everywhere they're currently
  hardcoded, closes a real, already-present rename/drift risk cheaply.
- **Browser fingerprint hardening.** `browser/session.py`'s existing stealth init
  script (already overrides `navigator.webdriver`/`plugins`/`chrome.runtime`) has a
  shallow plugin spoof (`[1,2,3,4,5]`, bare numbers) and no UA/viewport/locale
  overrides. Strengthen the plugin array to realistic named plugin objects and add a
  fixed desktop UA string + 1920x1080 viewport + `en-US` locale/Accept-Language to
  `_ensure_started`.
- **Severity-calibration refinements** (4 specific, narrow rules added to
  `skills/content/methodology/severity-calibration.md`, each a short paragraph, no code):
  a trusted-controller-mediated-interface pattern (an exploit that only lets an
  already-authoritative component do what it could legitimately do anyway caps low,
  *unless* it bypasses a specific documented safety/security control that component was
  designed to respect — stays high then); a multi-tenant resource-reuse exception to the
  existing self-contained-blast-radius cap (state/credentials surviving into a different
  principal's later reuse of the same execution slot, e.g. a warm serverless
  container, is NOT self-contained); a non-repudiation carve-out (an effect confined to
  the attacker's own data still caps low *unless* it also breaks non-repudiation —
  enables fraud/blame-shifting); and a "classify attacker position by trust barrier
  crossed, not by wire protocol" heuristic (a component bound to loopback/service-mesh-only
  is LOCAL exposure even if it happens to speak HTTP).
- **Cross-agent report-deduplication discipline** (new short section in `review.txt` or
  `agent.txt`): when independent specialist children each confirm the same underlying
  defect via different symptoms/routes, the guidance for recognizing and consolidating
  duplicate write-ups — clean every candidate title down to defect+location (never
  consequence/hedges/process-framing) before comparing, and explicitly bias toward
  under-merging (a visible duplicate is recoverable) over over-merging (which can hide a
  genuinely distinct finding) — mirrors CLAUDE.md's own existing "a multi-agent parent
  merges only a child's authoritative finding-ids, never its prose summary" principle,
  extended to the report-assembly step specifically.
- **DOM Clobbering** — one bullet added to `skills/content/vulnerabilities/xss.md`'s
  existing client-side-sinks/techniques section (injecting elements whose `id`/`name`
  shadow global JS variables to corrupt app logic or bypass a sanitizer without executing
  `<script>` at all).
- **Adversarial-sweep planning discipline** — a short addition to `agent.txt`'s
  existing THOROUGHNESS/MULTI-AGENT-WORK guidance: periodically spawn a child
  specifically tasked with re-examining a surface already judged low-value/`ruled_out`,
  with no prior context, as a deliberate check against confirmation bias/tunnel vision
  from over-trusting upstream recon.
- **Exhaustive same-contract call-site sweep** — a short addition to
  `skills/content/methodology/source-aware-review.md`'s Step Two: when a shared
  function/helper carries an implicit safety contract (a buffer-size assumption, a
  sanitization precondition), grep every call site of that helper across the whole
  repo and check each individually, rather than assuming one safe example proves every
  caller is safe (the offensive complement to `closure-discipline.md`'s existing
  defensive "safe sibling" trap).

### B6. Packaged CI/CD integration

L4L0 already has everything a CI wrapper needs (`report/sarif.py`, OWASP-tagged
findings, `report/manifest.py`'s per-format digest) but no packaged way to slot into a
consumer's pipeline. A thin CLI-*script* here is not a violation of the no-CLI/no-TUI
design center (that principle is about L4L0's own *product* interface — the GUI stays
the only way to operate L4L0 interactively; a CI wrapper is automation glue a *different*
tool's pipeline invokes non-interactively, the same category as `setup.py`'s already-
accepted narrow exception): a small script (`scripts/ci-scan.py` or similar, outside
`src/lalo/` proper) that launches a scan against a given target via the existing GUI
HTTP API (`POST /scan`, poll `/runs/{id}`), waits for completion, copies the SARIF
output to a caller-specified path, and exits non-zero only when the worst
**`review_verdict == "confirmed"`** finding meets or exceeds a caller-supplied
`--fail-on-severity` threshold (never gated on an unconfirmed/open-proof-gap finding).
Paired with a documented GitHub Actions workflow YAML example and a GitLab CI
component example in `docs/`, both driving that same script — no new Python package
surface inside `src/lalo/`, no new operator-facing interactive mode.

### B7. Per-agent narrative log splitting

`orchestrator/narrative.py`'s `write_narrative_log` currently renders one whole-run
`narrative.log` with every agent's lines interleaved by emission order. Add
`write_per_agent_narrative_logs(run_dir) -> dict[str, Path]` (new function, same module):
groups the already-parsed `(category, payload)` events by their real `agent_id`
(`"system"`/`"operator"` for the categories `render_narrative_line` already treats that
way) and writes one `narrative-<agent_id>.log` per agent alongside the existing combined
file — the combined file is not replaced, this is additive. Filenames are built only from
the already-safe, system-generated `agent_id` (`agent-N`), never the agent-chosen `name`/
`task` free text, per the same discipline this project already applies to journal keys.
Wire a per-agent download alongside the existing `/runs/{run_id}/report/narrative` GUI
link once more than one agent participated in a run (a single-agent run's per-agent file
is identical to the combined one — skip generating it to avoid a pointless duplicate,
purely a size/clutter optimization with no behavior implication).

### B8. Cancellation for an in-flight LLM call

`CompletionRequest`/`Provider.complete()` (`core/model_router.py`, `core/providers.py`)
carry no cancellation mechanism today — an in-flight `httpx` POST runs to completion or
timeout regardless of an operator-triggered stop. Thread `httpx`'s own request-level
cancellation through: `AgentLoop`'s existing `should_stop` callback (already polled
between steps) gets one additional check point — pass a `threading.Event` (already the
natural primitive for `AgentLoop`'s synchronous, thread-per-agent execution model, no new
async infrastructure needed) down into `_post_with_retry`, checked in the same
interruptible-sleep-chunk pattern `agent/loop.py` already uses for its own backoff waits,
and have `Provider.complete()` accept an optional `cancel_event` it can pass to `httpx`
as a `timeout`-adjacent mechanism (httpx supports closing the underlying connection from
another thread to abort an in-flight request). A manual operator stop or a wall-clock/
cost-ceiling kill then interrupts an in-flight LLM call within about one polling
interval instead of waiting for it to finish or hit its own 120s timeout.

## Verification approach

- **Part A (bugs):** each gets its own hermetic regression test proving the specific
  failure mode is closed — a concurrent-`record_usage` race test (two threads, same
  path, assert no lost update), a review-loop crash-then-resume test (mirroring this
  project's existing `_CrashingProvider` pattern), a dedup-merge severity-upgrade test,
  and a SARIF automation-id-stability-across-two-run-dirs test.
- **Part B:** each new field/tool/mechanism gets unit coverage matching this project's
  established TDD-per-task discipline; anything GUI-visible (per-agent log links, a
  browser-login-preflight step's effect on scan launch) gets a live Playwright check
  before being called done, per this project's own standing frontend-change convention.
- **Full non-live suite, ruff, mypy, reference-name-leak grep, `git fsck`** after every
  task, exactly as every prior round this session.
- **One live-eval run** (an on-demand lab target, e.g. VAmPI or a target with a real SSO
  login) exercising at minimum: the `record_safe` tool actually getting called by the
  agent for at least one clean surface, the new report sections rendering with real
  data, and (if a suitable SSO-shaped lab target is available) the browser-login
  preflight path.

## Sequencing

Two implementation plans, matching this session's own established per-round pattern:

1. **Bugfix plan** (Part A, 4 small tasks) — ships first, independent of everything else.
2. **Capability-superset plan** (Parts B1-B8) — a larger round, grouped in the order
   above (B1's honest-coverage mechanism is referenced by B2's report rendering, so B1
   precedes B2; everything else is independent and orderable for convenience).

Both executed **inline** (no subagent dispatch), per the operator's own standing
instruction earlier this session ("next task onwards use inline execution") — self-
reviewed against real test/lint/mypy/fsck evidence at each commit, matching every task
in the round-4 plan.
