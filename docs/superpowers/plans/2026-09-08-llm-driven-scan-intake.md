# LLM-Driven Scan Intake Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the GUI's client-side regex target extraction with a
backend LLM parse, so a natural-language mission like "test this website
localhost:5000 and dont test ddos and dos attacks focus on api" launches
correctly instead of being rejected, and constraints stated in free text get
lifted into the engagement's real, always-in-force `rules_of_engagement`
field.

**Architecture:** One new completion role (`"intake"`), mirroring
`findings/review.py`'s own adversarial-review call shape (system prompt,
JSON-only reply, 2-attempt retry, no silent fallback on total provider
failure). `gui/app.py`'s `/scan` handler calls it when the caller supplies
no targets; the frontend stops gatekeeping locally and always defers to the
backend.

**Tech Stack:** Python 3.13, FastAPI/Pydantic (existing `gui/app.py`), the
existing `ModelRouter`/`Provider` abstraction (`core/model_router.py`,
`core/providers.py`), the existing prompt-template loader
(`prompts/loader.py`), vanilla JS (`gui/static/app.js`).

**Spec:** `docs/superpowers/specs/2026-09-08-llm-driven-scan-intake-design.md`

## Global Constraints

- No new dependencies — reuse the existing `ModelRouter`/`Provider`
  abstraction exactly as `findings/review.py` already does.
- The new `"intake"` role needs no entry in `core/providers.py`'s
  `build_router` `routes` dict — an unregistered role already falls
  through to `default_route` (`ModelRouter.chain_for`), matching how
  `"review"` already works today without being registered there either.
- Never synthesize a `http://`/`https://` scheme onto a bare
  hostname/IP/host:port the operator didn't scheme-qualify themselves —
  `Engagement._parse_target_specs` already treats a bare host as
  scheme-unrestricted (`TargetRule.schemes=None`); injecting a scheme
  would incorrectly restrict testing to just that scheme.
- `AllProvidersFailedError` propagates OUT of `parse_scan_intent` (never
  caught/hidden there) — `start_scan` is an HTTP request handler with a
  real place to surface it as a structured error response, unlike
  `findings/review.py`'s `_compute_review` (deep in report generation,
  degrades to `open_proof_gap` because it has no HTTP caller to answer).
- A malformed/unparseable model reply (after retries) is NOT an error —
  it degrades to an empty `ParsedIntent`, which falls into the exact same
  "mission and targets are required" 400 a genuine no-target case already
  produces. No new user-facing error message.
- `ScanRequest.targets`/`exclude_targets`/`rules_of_engagement` need NO
  Pydantic schema change — all three are already optional
  (`list[str] = []` / `str = ""`) in the current model. Only
  `start_scan`'s body logic changes.
- Resume launches (`resume_run_id` set) are completely untouched by this
  plan — that branch already reads every locked field from the run's own
  manifest and never calls the intake parser.

---

## Task 1: Promote the shared JSON-extraction helper

**Files:**
- Create: `src/lalo/core/json_response.py`
- Modify: `src/lalo/findings/review.py:130-141` (removes the private
  `_extract_json_object`, imports the promoted one instead)
- Test: `tests/lalo/test_json_response.py`
- Test (unchanged, must still pass): `tests/lalo/test_findings_review.py`

**Interfaces:**
- Produces: `extract_json_object(text: str) -> dict[str, object] | None` —
  identical behavior to `findings/review.py`'s current private
  `_extract_json_object` (find the first `{`...last `}` substring,
  `json.loads` it, return `None` if no braces found, invalid JSON, or the
  parsed value isn't a `dict`).

- [ ] **Step 1: Write the failing tests for the promoted helper**

```python
# tests/lalo/test_json_response.py
"""Tests for the shared JSON-object extraction helper."""

from __future__ import annotations

from lalo.core.json_response import extract_json_object


def test_extracts_a_clean_json_object() -> None:
    assert extract_json_object('{"a": 1}') == {"a": 1}


def test_extracts_a_json_object_surrounded_by_prose() -> None:
    text = 'Here is the answer:\n{"a": 1, "b": "two"}\nHope that helps!'
    assert extract_json_object(text) == {"a": 1, "b": "two"}


def test_returns_none_when_no_braces_are_present() -> None:
    assert extract_json_object("no json here at all") is None


def test_returns_none_for_malformed_json_inside_braces() -> None:
    assert extract_json_object('{"a": }') is None


def test_returns_none_when_the_parsed_value_is_not_an_object() -> None:
    # A bare JSON array or string is valid JSON but not the dict this
    # helper's every caller actually needs.
    assert extract_json_object("[1, 2, 3]") is None
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/lalo/test_json_response.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'lalo.core.json_response'`

- [ ] **Step 3: Create the promoted helper**

```python
# src/lalo/core/json_response.py
"""Pull one JSON object out of an LLM completion's free-form reply text.

Promoted from findings/review.py's own private _extract_json_object -
every LLM call site that asks for "reply with a single JSON object and
nothing else" still has to tolerate a model wrapping that object in a
sentence or two of prose, so this is shared rather than reimplemented per
call site.
"""

from __future__ import annotations

import json


def extract_json_object(text: str) -> dict[str, object] | None:
    stripped = text.strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        parsed = json.loads(stripped[start : end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None
```

- [ ] **Step 4: Run to verify the new tests pass**

Run: `uv run pytest tests/lalo/test_json_response.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Point `findings/review.py` at the promoted helper**

In `src/lalo/findings/review.py`, delete the private `_extract_json_object`
function (currently right after `_build_user_prompt`, before `_fallback`):

```python
def _extract_json_object(text: str) -> dict[str, object] | None:
    stripped = text.strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        parsed = json.loads(stripped[start : end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None
```

Add the import near the top of the file (alongside the other `..core`
imports):

```python
from ..core.json_response import extract_json_object
```

Update `_parse_review_response`'s one call site from `_extract_json_object(text)`
to `extract_json_object(text)`. The now-unused `import json` at the top of
`review.py` can stay if `json.dumps` is still used elsewhere in the file
(it is, in `_build_user_prompt`) — verify with `uv run ruff check
src/lalo/findings/review.py` that nothing is flagged as an unused import.

- [ ] **Step 6: Run the full existing review suite to confirm zero regression**

Run: `uv run pytest tests/lalo/test_findings_review.py -v`
Expected: PASS, every test, unchanged — this proves the extraction was a
pure refactor with no behavior change.

- [ ] **Step 7: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/core/json_response.py src/lalo/findings/review.py tests/lalo/test_json_response.py
git commit -m "refactor(L4L0): promote review.py's JSON-object extraction into a shared helper"
```

---

## Task 2: Add the `intake` prompt role

**Files:**
- Create: `src/lalo/prompts/content/intake.txt`
- Modify: `src/lalo/prompts/loader.py:26-30` (adds `"intake"` to
  `REQUIRED_PLACEHOLDERS`)
- Modify: `tests/lalo/test_prompts.py:13-15` (the existing
  `test_every_built_in_role_loads_and_validates` iterates a hardcoded
  tuple `("agent", "review", "review_second_opinion")` — add `"intake"`)
- Test: `tests/lalo/test_prompts.py` (new test appended, same file — this
  is where `render_prompt`/`load_prompt_template` are already tested for
  every other role, confirmed by reading the file in full this session)

**Interfaces:**
- Produces: a loadable prompt role `"intake"` with
  `REQUIRED_PLACEHOLDERS["intake"] = frozenset()` (no placeholders — the
  actual mission text is the *user* prompt at call time, exactly matching
  how `"review"`'s finding data is the user prompt, never templated into
  the system prompt itself).

- [ ] **Step 1: Update the existing "every built-in role" test and add a new one**

In `tests/lalo/test_prompts.py`, change the existing (verified real,
current) test:

```python
def test_every_built_in_role_loads_and_validates() -> None:
    for role in ("agent", "review", "review_second_opinion"):
        assert load_prompt_template(role).strip()
```

to:

```python
def test_every_built_in_role_loads_and_validates() -> None:
    for role in ("agent", "review", "review_second_opinion", "intake"):
        assert load_prompt_template(role).strip()
```

Append a new test to the same file:

```python
def test_render_prompt_for_intake_needs_no_variables() -> None:
    rendered = render_prompt("intake")
    assert "targets" in rendered
    assert "rules_of_engagement" in rendered
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/lalo/test_prompts.py -k "every_built_in or for_intake" -v`
Expected: FAIL — `PromptLoadError: no built-in prompt for role 'intake'`

- [ ] **Step 3: Register the role and write the prompt content**

In `src/lalo/prompts/loader.py`, add `"intake": frozenset()` to
`REQUIRED_PLACEHOLDERS` (alongside the existing `"review"` and
`"review_second_opinion"` entries — both already `frozenset()`, same
shape):

```python
REQUIRED_PLACEHOLDERS: dict[str, frozenset[str]] = {
    "agent": frozenset({"engagement_scope", "rules_of_engagement"}),
    "review": frozenset(),
    "review_second_opinion": frozenset(),
    "intake": frozenset(),
}
```

Create `src/lalo/prompts/content/intake.txt`:

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
  text actually specifies or clearly implies one. Do NOT invent a scheme
  for a bare host: an unscoped target is allowed to be tested over
  either http or https, and adding one yourself would incorrectly
  restrict it to only that one.
- "exclude_targets": anything the operator explicitly said NOT to test
  (a sub-path, a host, a service) - empty list if none.
- "rules_of_engagement": one or two sentences capturing any explicit
  constraint on HOW to test (attack types to avoid, areas to focus on,
  intensity limits) stated anywhere in the text - empty string if the
  text states no such constraint. Do not invent one.
- If the text names no target at all, "targets" must be an empty list -
  never guess a placeholder host.
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/lalo/test_prompts.py -v`
Expected: PASS, full file (proves the new role loads and every existing
role's test is still unaffected)

- [ ] **Step 5: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/prompts/loader.py src/lalo/prompts/content/intake.txt tests/lalo/test_prompts.py
git commit -m "feat(L4L0): register the intake prompt role"
```

---

## Task 3: `parse_scan_intent` — the core intake parser

**Files:**
- Create: `src/lalo/intake.py`
- Test: `tests/lalo/test_intake.py`

**Interfaces:**
- Consumes: `render_prompt("intake", overrides_dir=...)` (Task 2),
  `extract_json_object` (Task 1), `ModelRouter.complete(role, CompletionRequest)`
  (existing, `core/model_router.py:107`), `AllProvidersFailedError`
  (existing, `core/errors.py:57`).
- Produces: `ParsedIntent` (`targets: list[str]`, `exclude_targets:
  list[str]`, `rules_of_engagement: str`) and
  `parse_scan_intent(mission_text: str, router: ModelRouter, *,
  prompt_overrides_dir: Path | None = None) -> ParsedIntent`, consumed by
  Task 4's `gui/app.py` changes.

- [ ] **Step 1: Write the failing tests**

```python
# tests/lalo/test_intake.py
"""Tests for the LLM-driven scan-intake parser."""

from __future__ import annotations

import pytest

from lalo.core.errors import AllProvidersFailedError
from lalo.core.model_router import CompletionRequest, CompletionResponse, ModelRouter
from lalo.intake import ParsedIntent, parse_scan_intent


class _FakeProvider:
    def __init__(
        self,
        *,
        text: str = "",
        texts: list[str] | None = None,
        raises: Exception | None = None,
    ) -> None:
        self.name = "fake"
        self._text = text
        self._texts = texts
        self._raises = raises
        self.seen_prompts: list[CompletionRequest] = []

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.seen_prompts.append(request)
        if self._raises is not None:
            raise self._raises
        if self._texts is not None:
            index = min(len(self.seen_prompts) - 1, len(self._texts) - 1)
            text = self._texts[index]
        else:
            text = self._text
        return CompletionResponse(text=text, provider=self.name, model="fake-model")


def _router(provider: _FakeProvider) -> ModelRouter:
    return ModelRouter(providers={"fake": provider}, routes={"intake": ("fake",)})


def test_happy_path_extracts_targets_and_rules_of_engagement() -> None:
    provider = _FakeProvider(
        text='{"targets": ["localhost:5000"], "exclude_targets": [], '
        '"rules_of_engagement": "No DDoS/DoS testing. Focus on API endpoints."}'
    )
    result = parse_scan_intent("test this website localhost:5000, focus on api", _router(provider))
    assert result == ParsedIntent(
        targets=["localhost:5000"],
        exclude_targets=[],
        rules_of_engagement="No DDoS/DoS testing. Focus on API endpoints.",
    )


def test_bare_host_port_is_never_given_a_synthesized_scheme() -> None:
    # The model is instructed not to do this; this test locks in that the
    # parser itself doesn't second-guess or "fix up" what the model returned.
    provider = _FakeProvider(text='{"targets": ["localhost:5000"], "exclude_targets": [], "rules_of_engagement": ""}')
    result = parse_scan_intent("test localhost:5000", _router(provider))
    assert result.targets == ["localhost:5000"]


def test_a_scheme_qualified_url_passes_through_unchanged() -> None:
    provider = _FakeProvider(
        text='{"targets": ["https://api.example.com"], "exclude_targets": [], "rules_of_engagement": ""}'
    )
    result = parse_scan_intent("test https://api.example.com", _router(provider))
    assert result.targets == ["https://api.example.com"]


def test_no_target_named_in_the_text_produces_an_empty_target_list() -> None:
    provider = _FakeProvider(
        text='{"targets": [], "exclude_targets": [], "rules_of_engagement": ""}'
    )
    result = parse_scan_intent("what can you do?", _router(provider))
    assert result.targets == []


def test_malformed_json_retries_once_then_returns_empty_after_max_attempts() -> None:
    provider = _FakeProvider(texts=["not json at all", "still not json"])
    result = parse_scan_intent("test example.com", _router(provider))
    assert result == ParsedIntent(targets=[], exclude_targets=[], rules_of_engagement="")
    assert len(provider.seen_prompts) == 2


def test_a_malformed_reply_followed_by_a_valid_one_succeeds_on_retry() -> None:
    provider = _FakeProvider(
        texts=[
            "not json at all",
            '{"targets": ["example.com"], "exclude_targets": [], "rules_of_engagement": ""}',
        ]
    )
    result = parse_scan_intent("test example.com", _router(provider))
    assert result.targets == ["example.com"]
    assert len(provider.seen_prompts) == 2


def test_all_providers_failed_propagates_rather_than_being_swallowed() -> None:
    provider = _FakeProvider(raises=AllProvidersFailedError(role="intake", failures=[("fake", "timeout")]))
    with pytest.raises(AllProvidersFailedError):
        parse_scan_intent("test example.com", _router(provider))


def test_all_providers_failed_is_never_retried() -> None:
    # An uncaught exception exits the retry loop on its first raise - the
    # chain has already exhausted itself once, so a second attempt could
    # only repeat the identical failure.
    provider = _FakeProvider(raises=AllProvidersFailedError(role="intake", failures=[]))
    with pytest.raises(AllProvidersFailedError):
        parse_scan_intent("test example.com", _router(provider))
    assert len(provider.seen_prompts) == 1


def test_missing_fields_in_the_reply_default_to_empty() -> None:
    provider = _FakeProvider(text='{"targets": ["example.com"]}')
    result = parse_scan_intent("test example.com", _router(provider))
    assert result == ParsedIntent(targets=["example.com"], exclude_targets=[], rules_of_engagement="")


def test_non_string_list_items_are_coerced_to_strings() -> None:
    # Defensive: a model returning a non-string element (e.g. a bare
    # number) must not crash the parser.
    provider = _FakeProvider(text='{"targets": [8080], "exclude_targets": [], "rules_of_engagement": ""}')
    result = parse_scan_intent("test port 8080", _router(provider))
    assert result.targets == ["8080"]
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/lalo/test_intake.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'lalo.intake'`

- [ ] **Step 3: Implement `src/lalo/intake.py`**

```python
"""Turn a free-form operator request into a structured scan launch.

Mirrors findings/review.py's own _compute_review retry/fallback shape
exactly: a system prompt, a JSON-only reply, a bounded retry on a
malformed response, and a graceful (never-crashing) degrade to "found
nothing" rather than raising on a bad-but-non-fatal model reply. The one
deliberate divergence from review.py: AllProvidersFailedError propagates
here instead of degrading to a fallback value, because this runs inside
an HTTP request handler (gui/app.py's start_scan) that has a real,
structured way to surface it as an error response - review.py's own
_compute_review has no such caller and must degrade internally instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .core.json_response import extract_json_object
from .core.model_router import CompletionRequest, ModelRouter
from .prompts import render_prompt

_MAX_ATTEMPTS = 2


@dataclass(frozen=True)
class ParsedIntent:
    targets: list[str]
    exclude_targets: list[str]
    rules_of_engagement: str


_EMPTY_INTENT = ParsedIntent(targets=[], exclude_targets=[], rules_of_engagement="")


def _coerce_str_list(raw: object) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(item).strip() for item in raw if str(item).strip()]


def _parse_response(text: str) -> ParsedIntent | None:
    parsed = extract_json_object(text)
    if parsed is None:
        return None
    return ParsedIntent(
        targets=_coerce_str_list(parsed.get("targets")),
        exclude_targets=_coerce_str_list(parsed.get("exclude_targets")),
        rules_of_engagement=str(parsed.get("rules_of_engagement", "")).strip(),
    )


def parse_scan_intent(
    mission_text: str,
    router: ModelRouter,
    *,
    prompt_overrides_dir: Path | None = None,
) -> ParsedIntent:
    """Derive targets/exclusions/rules-of-engagement from ``mission_text``
    via one LLM completion. Never raises for a malformed or empty model
    reply (returns an empty :class:`ParsedIntent` instead, indistinguishable
    from "the operator named no target"); ``AllProvidersFailedError``
    propagates uncaught - see the module docstring for why.
    """
    system_prompt = render_prompt("intake", overrides_dir=prompt_overrides_dir)
    for _attempt in range(_MAX_ATTEMPTS):
        response = router.complete(
            "intake", CompletionRequest(system=system_prompt, prompt=mission_text)
        )
        parsed = _parse_response(response.text)
        if parsed is not None:
            return parsed
    return _EMPTY_INTENT
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/lalo/test_intake.py -v`
Expected: PASS (10 tests)

- [ ] **Step 5: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/intake.py tests/lalo/test_intake.py
git commit -m "feat(L4L0): parse_scan_intent - LLM-driven target/rules-of-engagement extraction"
```

---

## Task 4: Wire the intake parser into `/scan`

**Files:**
- Modify: `src/lalo/gui/app.py` (imports; `start_scan`'s fresh-launch
  branch, currently around the `mission`/`targets`/`exclude_targets`
  block and the 400 check; the shared final `JSONResponse` return)
- Test: `tests/lalo/test_gui_app.py`

**Interfaces:**
- Consumes: `parse_scan_intent`, `ParsedIntent` (Task 3).
- Produces: `/scan`'s success response gains `resolved_targets: list[str]`,
  `resolved_exclude_targets: list[str]`, `resolved_rules_of_engagement: str`
  (read from the final `ScanConfig`, present for both the resume and
  fresh-launch branches). A provider-failure-during-parse response:
  `{"error": str, "role": str, "failures": [{"provider": str, "reason": str}]}`,
  status 503.

- [ ] **Step 1: Write the failing tests**

Add to `tests/lalo/test_gui_app.py` (uses the file's existing `_client`/
`_FakeScanRunner` fixtures, already imported):

```python
def test_scan_derives_targets_from_mission_when_none_are_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)

    def fake_parse_scan_intent(mission, router):
        from lalo.intake import ParsedIntent

        assert mission == "test this website localhost:5000, focus on api"
        return ParsedIntent(
            targets=["localhost:5000"],
            exclude_targets=[],
            rules_of_engagement="Focus on API endpoints.",
        )

    monkeypatch.setattr(app_module, "parse_scan_intent", fake_parse_scan_intent)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post(
        "/scan", json={"mission": "test this website localhost:5000, focus on api"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["resolved_targets"] == ["localhost:5000"]
    assert body["resolved_rules_of_engagement"] == "Focus on API endpoints."
    assert current_config().target_specs == ["localhost:5000"]
    assert current_config().rules_of_engagement == "Focus on API endpoints."


def test_scan_skips_the_parser_entirely_when_targets_are_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    called = False

    def fake_parse_scan_intent(mission, router):
        nonlocal called
        called = True
        raise AssertionError("must not be called when targets are already explicit")

    monkeypatch.setattr(app_module, "parse_scan_intent", fake_parse_scan_intent)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post(
        "/scan", json={"mission": "find a bug", "targets": ["example.com"]}
    )
    assert response.status_code == 200
    assert called is False
    assert response.json()["resolved_targets"] == ["example.com"]


def test_scan_still_400s_when_the_parser_finds_no_target_either(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)

    def fake_parse_scan_intent(mission, router):
        from lalo.intake import ParsedIntent

        return ParsedIntent(targets=[], exclude_targets=[], rules_of_engagement="")

    monkeypatch.setattr(app_module, "parse_scan_intent", fake_parse_scan_intent)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post("/scan", json={"mission": "what can you do?"})
    assert response.status_code == 400
    assert "required" in response.json()["error"]


def test_scan_surfaces_a_structured_503_when_every_provider_fails_during_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)

    def fake_parse_scan_intent(mission, router):
        raise AllProvidersFailedError(role="intake", failures=[("anthropic", "401 unauthorized")])

    monkeypatch.setattr(app_module, "parse_scan_intent", fake_parse_scan_intent)
    client, _ = _client(runs_dir=tmp_path)
    response = client.post("/scan", json={"mission": "test localhost:5000"})
    assert response.status_code == 503
    body = response.json()
    assert body["role"] == "intake"
    assert body["failures"] == [{"provider": "anthropic", "reason": "401 unauthorized"}]


def test_scan_resume_response_also_carries_resolved_fields(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module, "ScanRunner", _FakeScanRunner)
    run_dir = tmp_path / "abc123"
    run_dir.mkdir()
    (run_dir / "resume_manifest.json").write_text(
        '{"mission": "m", "target_specs": ["example.com"], "egress_lock": false}',
        encoding="utf-8",
    )
    client, _ = _client(runs_dir=tmp_path)
    response = client.post("/scan", json={"resume_run_id": "abc123"})
    assert response.status_code == 200
    assert response.json()["resolved_targets"] == ["example.com"]
```

(These new tests add `AllProvidersFailedError` usage to the existing
imports if not already present in the file — it already is, imported at
the top for the pre-existing failed-scan tests.)

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/lalo/test_gui_app.py -k "derives_targets or skips_the_parser or finds_no_target_either or structured_503 or resume_response_also" -v`
Expected: FAIL — `AttributeError: module 'lalo.gui.app' has no attribute 'parse_scan_intent'` (and `resolved_targets`/etc. absent from responses)

- [ ] **Step 3: Wire `parse_scan_intent` into `start_scan`**

Add the import near the top of `src/lalo/gui/app.py` (alongside the other
same-package imports, e.g. near `from ..scan import ...`):

```python
from ..intake import parse_scan_intent
```

In `start_scan`'s fresh-launch `else` branch, replace:

```python
        else:
            mission = request.mission.strip()
            targets = [t.strip() for t in request.targets if t.strip()]
            exclude_targets = [t.strip() for t in request.exclude_targets if t.strip()]
            if not mission or not targets:
                return JSONResponse(
                    {"error": "'mission' and 'targets' are required"}, status_code=400
                )
```

with:

```python
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
```

Update the `ScanConfig(...)` construction a few lines below (still in the
same `else` branch) to use the new `rules_of_engagement` local instead of
re-reading `request.rules_of_engagement.strip()`:

```python
            config = ScanConfig(
                mission=mission,
                target_specs=targets,
                exclude_target_specs=exclude_targets,
                rules_of_engagement=rules_of_engagement,
                run_dir=run_dir,
                usage_path=run_dir / "usage.json",
                max_steps=request.max_steps if request.max_steps is not None else 25,
                budget_ceiling=request.budget_ceiling
                if request.budget_ceiling is not None
                else 300,
                redact_findings=request.redact_findings,
                egress_lock=request.egress_lock,
            )
```

Finally, update the shared final return (used by both the resume and
fresh-launch branches) from:

```python
        threading.Thread(target=_run_and_clear, daemon=True).start()
        return JSONResponse({"ok": True, "run_dir": str(run_dir), "run_id": run_id})
```

to:

```python
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
```

`build_router`/`load_settings`/`os` are already imported in this file
(verify with `grep -n "^import os\|build_router\|load_settings" src/lalo/gui/app.py`
before assuming — they were confirmed present as of this plan's writing).

- [ ] **Step 4: Run to verify they pass, then the full existing GUI suite**

Run: `uv run pytest tests/lalo/test_gui_app.py -v`
Expected: PASS, every test (the 5 new ones plus the full existing suite —
this confirms explicit-`targets` launches are completely unaffected).

- [ ] **Step 5: Full check and commit**

```bash
uv run ruff check src/lalo tests/lalo --fix && uv run ruff format src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"
git add src/lalo/gui/app.py tests/lalo/test_gui_app.py
git commit -m "feat(L4L0): /scan derives targets/rules-of-engagement via LLM when none are given"
```

---

## Task 5: Frontend — remove the regex gate, render what was understood

**Files:**
- Modify: `src/lalo/gui/static/app.js` (`launchFromPrompt`; deletes
  `TARGET_PATTERN`/`extractTargets`; updates the bulk-import comment)

**Interfaces:**
- Consumes: `/scan`'s response `resolved_targets`/`resolved_exclude_targets`/
  `resolved_rules_of_engagement` (Task 4).
- No new interfaces produced — this is the last task in the plan.

- [ ] **Step 1: Read the current `launchFromPrompt` and its call site in full**

Already known from this plan's own research, reproduced here for the
exact anchor to edit:

```javascript
  const TARGET_PATTERN = /\bhttps?:\/\/\S+|\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g;

  function extractTargets(text) {
    const matches = text.match(TARGET_PATTERN) || [];
    return [...new Set(matches.map((t) => t.replace(/[.,;:)]+$/, "")))];
  }

  async function launchFromPrompt(text) {
    const targets = extractTargets(text);
    if (!targets.length) {
      appendUserMessage(text, { error: true });
      appendAgentText('I need a target to scope this to — include a URL or IP, e.g. "https://example.com".');
      return;
    }
    composerSendBtn.disabled = true;
    composerInput.disabled = true;
    try {
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
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(body.error || `request failed (${response.status})`);
      }
      // A fresh launch always becomes the thread's new focus, live - the
      // very first scan of the process happens to be the backend's
      // "primary" (see gui/app.py's own primary_run_id), but every launch
      // after that must be explicitly watched or its progress would only
      // ever surface by clicking into Past Runs.
      _resetThreadForNewView();
      liveWatchRunId = body.run_id;
      lastCursor = null;
      appendUserMessage(text);
      composerInput.value = "";
      socket.close(); // reconnects scoped to body.run_id
      onScanStarted();
    } catch (err) {
      appendUserMessage(`[scan not started: ${err.message}] ${text}`, { error: true });
    } finally {
      composerSendBtn.disabled = false;
      composerInput.disabled = false;
      composerInput.focus();
    }
  }
```

- [ ] **Step 2: Write a manual verification checklist (frontend has no unit-test harness in this project — verified live in the Final Check below)**

No automated JS test exists for this file in this project (confirmed: no
test framework wired for `app.js`); this task is verified via the plan's
own Final Check live Playwright walkthrough instead, matching how every
other frontend-only change in this project's history was verified.

- [ ] **Step 3: Delete the regex gate, always defer to the backend**

Delete `TARGET_PATTERN` and `extractTargets` entirely. Replace
`launchFromPrompt`'s body:

```javascript
  async function launchFromPrompt(text) {
    composerSendBtn.disabled = true;
    composerInput.disabled = true;
    try {
      const maxSteps = document.getElementById("opt-max-steps").value;
      const budgetCeiling = document.getElementById("opt-budget-ceiling").value;
      const egressLock = document.getElementById("opt-egress-lock").checked;
      const redactFindings = document.getElementById("opt-redact-findings").checked;
      const response = await fetch("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          mission: text,
          ...(maxSteps ? { max_steps: Number(maxSteps) } : {}),
          ...(budgetCeiling ? { budget_ceiling: Number(budgetCeiling) } : {}),
          egress_lock: egressLock,
          redact_findings: redactFindings,
        }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(body.error || `request failed (${response.status})`);
      }
      _resetThreadForNewView();
      liveWatchRunId = body.run_id;
      lastCursor = null;
      appendUserMessage(text);
      const parts = [`Understood — target(s): ${body.resolved_targets.join(", ")}`];
      if (body.resolved_exclude_targets && body.resolved_exclude_targets.length) {
        parts.push(`excluding: ${body.resolved_exclude_targets.join(", ")}`);
      }
      if (body.resolved_rules_of_engagement) {
        parts.push(`rules of engagement: ${body.resolved_rules_of_engagement}`);
      }
      appendAgentText(parts.join(" · "));
      composerInput.value = "";
      socket.close(); // reconnects scoped to body.run_id
      onScanStarted();
    } catch (err) {
      appendUserMessage(`[scan not started: ${err.message}] ${text}`, { error: true });
    } finally {
      composerSendBtn.disabled = false;
      composerInput.disabled = false;
      composerInput.focus();
    }
  }
```

Note `targets` is no longer sent in the request body at all — omitting the
key is equivalent to the existing Pydantic default (`targets: list[str] = []`).

- [ ] **Step 4: Update the bulk-import comment that referenced `extractTargets`**

Find (near the `bulkImportAddBtn` click handler):

```javascript
  // Bulk target import: pasted lines just become more text in the same
  // composer box a normal scan launch already parses via extractTargets, so
  // no backend/endpoint change is needed here either.
```

Replace with:

```javascript
  // Bulk target import: pasted lines just become more text in the same
  // composer box a normal scan launch already understands via the
  // backend's LLM intake parse, so no backend/endpoint change is needed
  // here either.
```

- [ ] **Step 5: Commit**

```bash
git add src/lalo/gui/static/app.js
git commit -m "feat(L4L0): GUI launch always defers target/rules understanding to the backend LLM parse"
```

---

## Final Check (after all 5 tasks)

1. Full check: `uv run ruff check src/lalo tests/lalo && uv run ruff format --check src/lalo tests/lalo && uv run mypy && uv run pytest -q -m "not integration and not live"` — must be fully green.
2. A final whole-branch review of every file this plan touched (not just
   per-task diffs) — confirm the `intake` role is genuinely unreachable
   from any place that shouldn't call it, confirm no dead code remains
   from the deleted `TARGET_PATTERN`/`extractTargets`, confirm
   `findings/review.py`'s refactor introduced no behavior drift.
3. Live Playwright verification (per this project's own established
   convention for GUI-visible changes): start `lalo-gui`, type exactly
   `"test this website localhost:5000 and dont test ddos and dos attacks
   focus on api"` into the composer, confirm:
   - The launch succeeds (no "I need a target" rejection).
   - The rendered "Understood — target(s): ..." line names a sane target
     derived from `localhost:5000` with no synthesized scheme.
   - The line also surfaces a rules-of-engagement mention of the
     no-DDoS/API-focus constraint.
   - If no live LLM provider credential is configured in the environment,
     document this plainly (per this project's own "honest coverage"
     convention) rather than skipping the check silently — verify the
     503 path renders a sane error in the composer instead.
4. Commit any final cleanup found during the review as its own small
   commit, same as every other plan in this project's history.
