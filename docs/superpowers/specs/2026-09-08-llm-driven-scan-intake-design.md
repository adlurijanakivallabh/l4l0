# LLM-Driven Scan Intake — Design Spec

**Status:** approved for planning (brainstormed interactively; operator picked
"pure LLM parsing, every launch" over a hybrid deterministic-fast-path
alternative after seeing both).

## Why

Real, reproducible bug: the GUI composer's target extraction is a client-side
regex (`TARGET_PATTERN` in `app.js`, `/\bhttps?:\/\/\S+|\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g`)
that only matches a full `http(s)://` URL or a bare IPv4 address. A prompt
like `"test this website localhost:5000"` — a completely reasonable way to
name a target — extracts zero targets and the composer refuses to launch at
all ("I need a target to scope this to"). The operator's own framing: if the
system already runs an LLM capable of finding vulnerabilities, gatekeeping
whether a mission even *reaches* that LLM behind a dumb regex defeats the
point of a natural-language interface.

A second, related gap this closes for free: `ScanConfig.rules_of_engagement`
already exists and already gets its own dedicated, "always in force,
independent of anything the mission text does or doesn't repeat" block in
the system prompt (`prompts/content/agent.txt`) — but the GUI has no field
for it at all. An operator typing "don't test DDoS/DoS, focus on API" today
gets that constraint buried in free-form mission text with no code path
lifting it into the block specifically designed to hold it.

## Scope

One feature: move target/constraint understanding server-side into the same
LLM completion pipeline the rest of the system already uses (the pattern
`findings/review.py`'s adversarial review already established — system
prompt, JSON-only reply, 2-attempt retry, graceful non-crashing fallback),
and make the GUI's `/scan` launch always route through it rather than a
client-side regex gate.

**Explicitly out of scope for this pass** (three related reference-comparison
items the operator wants next, each queued as its own future brainstorm →
spec → plan cycle, not folded into this one): a real confined source-review
agent role, per-child mid-flight journaling for crash resume, and
recompute-from-attempts usage accounting under replay.

**Explicitly rejected, not silently dropped:** converting `recall()` (skill
retrieval), confidence scoring, or report/severity rendering to LLM
judgment. All three are deterministic by design in CLAUDE.md (auditable,
reproducible, compute-don't-trust) — an LLM call there would be a
regression, not an improvement, and `recall()` runs many times per scan
(not once at launch), so the cost/benefit is inverted relative to a
one-time intake parse.

## Architecture

`gui/app.py`'s `/scan` endpoint currently rejects a launch with an empty
`targets` list outright (a body-logic check, not a schema requirement —
`ScanRequest.targets` is already `list[str] = []`). This changes to: when
`targets` comes up empty, the backend derives it (plus `exclude_targets`
and `rules_of_engagement`) from the mission text via one new LLM
completion, using the exact retry/fallback shape `findings/review.py`
already established for exactly this kind of "ask the model for one JSON
object, never crash the pipeline on a bad answer" call.

### New components

- **`src/lalo/intake.py`** (new, top-level — not GUI-specific, so any future
  caller besides the GUI gets the same behavior for free):
  ```python
  @dataclass(frozen=True)
  class ParsedIntent:
      targets: list[str]
      exclude_targets: list[str]
      rules_of_engagement: str

  def parse_scan_intent(
      mission_text: str,
      router: ModelRouter,
      *,
      prompt_overrides_dir: Path | None = None,
  ) -> ParsedIntent:
      ...
  ```
  Calls `router.complete("intake", CompletionRequest(system=..., prompt=mission_text))`.
  No changes needed to `core/providers.py`'s `build_router` — an unregistered
  role already falls through to `default_route` (confirmed: `"review"`
  already relies on exactly this, it is not in `build_router`'s `routes`
  dict either).

- **`prompts/content/intake.txt`** (new role, registered in
  `prompts/loader.py`'s `REQUIRED_PLACEHOLDERS` as `frozenset()` — no
  placeholders, matching `review`/`review_second_opinion`'s own pattern
  where the actual payload goes in the *user* prompt, not templated into the
  system prompt). Content, mirroring `review.txt`'s exact style:
  ```
  You are parsing a security-testing operator's free-form request into a
  structured scan launch. The operator's text may name a URL, a bare
  hostname, an IP, a host:port pair, or something more casual ("my local
  api on port 5000") - understand it the way a human security engineer
  reading the same sentence would.

  Reply with a single JSON object and nothing else:
  {"targets": ["..."],
   "exclude_targets": ["..."],
   "rules_of_engagement": "..."}

  - "targets": every host/URL/IP the operator wants tested. Pass a bare
    hostname/IP/host:port through EXACTLY as named, with no scheme added -
    only include a scheme (http:// or https://) when the operator's own
    text actually specifies or clearly implies one.
  - "exclude_targets": anything the operator explicitly said NOT to test
    (a sub-path, a host, a service) - empty list if none.
  - "rules_of_engagement": one or two sentences capturing any explicit
    constraint on HOW to test (attack types to avoid, areas to focus on,
    intensity limits) stated anywhere in the text - empty string if the
    text states no such constraint. Do not invent one.
  - If the text names no target at all, "targets" must be an empty list -
    never guess a placeholder host.
  ```
  **Why no scheme-injection**: `Engagement._parse_target_specs` (verified in
  the real current source) already handles a bare `host` or `host:port`
  spec correctly — no scheme means `TargetRule.schemes=None` ("any scheme
  allowed"). If the model instead synthesized `http://localhost:5000` for
  a bare `"localhost:5000"`, the resulting rule would restrict to
  `schemes={"http"}` and the agent could never legitimately test `https://`
  on that same host even if that's what it actually serves — a real
  regression the prompt above exists specifically to avoid.

- **Shared JSON-extraction helper.** `findings/review.py` already has a
  private `_extract_json_object(text) -> dict[str, object] | None` (finds
  the first `{`...last `}`, `json.loads`s it, confirms it's an object).
  Promoted to `src/lalo/core/json_response.py` as `extract_json_object`,
  imported by both `review.py` (replacing its private copy, no behavior
  change) and the new `intake.py` — avoids duplicating a small, general
  utility, per this project's own reuse-over-duplication convention.

### Data flow

1. `app.js`'s `launchFromPrompt` deletes its `extractTargets`/
   `TARGET_PATTERN` client-side gate entirely. `POST /scan` with
   `{mission: text}` — `targets` omitted, always, for every GUI launch.
2. `gui/app.py`'s `ScanRequest.targets` needs **no schema change at all** —
   it's already `list[str] = []` (verified in the real current model: it
   was never a *required* Pydantic field; the 400 comes from `start_scan`'s
   own body logic, not the schema). The actual change is inside
   `start_scan`'s fresh-launch `else` branch (not the `resume_run_id`
   branch, which already reads every locked field from the run's own
   manifest and never touches this path). Today:
   ```python
   mission = request.mission.strip()
   targets = [t.strip() for t in request.targets if t.strip()]
   exclude_targets = [t.strip() for t in request.exclude_targets if t.strip()]
   if not mission or not targets:
       return JSONResponse({"error": "'mission' and 'targets' are required"}, status_code=400)
   ```
   becomes: keep the blank-`mission` check as an immediate 400 (nothing to
   parse from empty text). If `targets` (after stripping/filtering, as
   today) is empty, call `parse_scan_intent(mission, router)` — using a
   router built the same way the existing `/settings/providers` verify
   endpoint already builds one (`build_router(load_settings(os.environ))`)
   — and use its `targets`/`exclude_targets`; for `rules_of_engagement`,
   `request.rules_of_engagement.strip() or parsed.rules_of_engagement`
   (an operator who set the field explicitly even while leaving targets to
   be inferred still wins). If `targets` is *not* empty, skip the parse
   entirely and use `request.targets`/`request.exclude_targets`/
   `request.rules_of_engagement` exactly as today — a caller handing over
   already-structured data is never second-guessed.
3. `ScanConfig.target_specs`/`exclude_target_specs`/`rules_of_engagement`
   are then built from whichever of the two branches above ran, exactly as
   `start_scan` already builds them today (no change to `ScanConfig`
   itself).
4. If the resulting `targets` is still empty after the parse attempt (the
   model genuinely found nothing target-shaped), return the *same* existing
   400 `{"error": "'mission' and 'targets' are required"}` — no new error
   path invented for "the AI couldn't understand this."
5. Both branches (resume and fresh) already converge on one shared
   `return JSONResponse({"ok": True, "run_dir": ..., "run_id": ...})` at
   the end of `start_scan`, after `config` (a `ScanConfig`) is fully built
   either way. That return gains `resolved_targets`/
   `resolved_exclude_targets`/`resolved_rules_of_engagement`, read
   straight off the final `config` object (`config.target_specs`, etc.) —
   one shared computation, no branch-specific tracking of "was this
   parsed" needed. The frontend only *renders* the "Understood: ..." line
   (reusing the existing message-rendering helper, no new UI component)
   from `launchFromPrompt`'s own success handler — not from
   `resumeRun`/`continueViewedRun`, where the operator already knows what
   they're resuming and the line would just be noise. Never a blocking
   confirm step either way; the whole point is removing friction, not
   adding a click.

### Error handling

- Malformed/unparseable model output: one retry (mirrors `review.py`'s
  `_MAX_ATTEMPTS = 2` exactly), then an empty `ParsedIntent` — falls into
  the same "please clarify" 400 as a genuine no-target case. No new
  user-facing error message.
- Every configured provider failing: `AllProvidersFailedError` propagates
  naturally out of `parse_scan_intent` (not caught/hidden there) — `start_scan`
  already has a structured handler for this exact exception elsewhere in
  the same file (`role`/`failures` surfaced to the frontend); this reuses
  it rather than adding a second one.
- **Deliberately not built:** any heuristic to detect a hallucinated
  target (e.g. "does the returned host appear as a substring of the
  original text"). That is exactly the kind of bespoke guessing code this
  feature exists to move away from, and it would false-flag legitimate
  paraphrases ("my local api" -> `127.0.0.1`). The safety net for a
  misunderstood target is the same one that already exists today for any
  other reason a scan might go sideways: the operator watches it launch,
  sees the rendered "Understood: ..." line, and can `stop`/relaunch with
  clearer wording — this is the accepted tradeoff of choosing full LLM
  parsing over a hybrid fallback-only design.

## Testing

- `tests/lalo/test_intake.py` (new): scripted-provider tests for
  `parse_scan_intent` — happy path with a bare `host:port` passed through
  unscoped (never given a synthesized scheme), a scheme-qualified URL
  passed through as-is, constraint text correctly landing in
  `rules_of_engagement`, malformed-JSON-then-empty-after-retries,
  `AllProvidersFailedError` propagation, empty-text-in-empty-targets-out.
  Same fixture conventions as `tests/lalo/test_findings_review.py`.
- `tests/lalo/test_gui_app.py`: targets-omitted launch derives and uses the
  parse (via a monkeypatched `parse_scan_intent`, matching this file's own
  `_FakeScanRunner` monkeypatch convention); explicit-targets launch never
  calls the parser at all; an empty parse result still 400s with the
  existing message; the success response carries the three `resolved_*`
  fields.
- `tests/lalo/test_findings_review.py`: full existing suite green,
  unchanged, after `_extract_json_object` becomes an import from
  `core/json_response.py` — proves the extraction was a pure refactor.
- `tests/lalo/test_json_response.py` (new, small): direct unit tests for
  the promoted `extract_json_object` helper (valid object, no braces,
  malformed JSON, a non-object JSON value like a bare list or string).
- One live Playwright check (per this project's own GUI-change
  convention): type `"test this website localhost:5000 and dont test ddos
  and dos attacks focus on api"` into the composer against a real running
  `lalo-gui`, confirm it launches (no "I need a target" rejection) and the
  rendered "Understood" line shows a sane target and a rules-of-engagement
  line naming the no-DDoS/API-focus constraint.

## Related work (not in this spec)

Three more items from the reference comparison are queued next, each getting
its own brainstorm → spec → plan cycle after this one ships: a real
confined source-review agent role, per-child mid-flight journaling for
crash resume, and recompute-from-attempts usage accounting under replay.
