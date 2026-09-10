# Strix Gap Closure — New Capabilities Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build every genuine new capability identified in the design spec on top of
L4L0's own existing architecture — new optional `Finding` fields, SARIF/coverage
report enrichment, a coverage ledger tool, multi-agent lifecycle extensions, a
passive HTTP history/replay tool, a shared baseline artifact, two new methodology
skills, ~19 new vulnerability/methodology skill playbooks, and one small runtime
capability — so that everything strix can do has a real L4L0-shaped equivalent.

**Architecture:** Every item slots into an existing L4L0 mechanism rather than adding
a parallel structure: new `Finding` fields extend the existing dataclass and flow
through the existing `record_finding` tool and `report/collect.py`; the coverage
ledger and baseline artifact are new node kinds on the existing `ReachabilityGraph`
(the same pattern `VERIFIED_SAFE` and `NOTE` already use), not a separate persistence
layer; multi-agent lifecycle extensions build on `AgentCoordinator`'s existing
lock/dict/thread-pool shape; the HTTP history tool wraps `HttpFirer.fire()` at its
one existing choke point; every new skill file matches the existing frontmatter +
Attack Surface/Recon/Techniques/Proof Ladder/Validation/Impact/Summary shape.

**Tech Stack:** Python 3.13, pytest, `networkx` (already a dependency, backs
`ReachabilityGraph`), stdlib only otherwise.

**Spec:** `docs/superpowers/specs/2026-09-10-strix-gap-closure-design.md`, §3
(capability gaps 3.1–3.9).

## Global Constraints

- No CLI/TUI — every capability here is an agent tool, a skill file, or report/
  schema enrichment, never an interactive command.
- No restrictions/gates of any kind. Every task below is additive capability or
  report/schema enrichment — nothing here ever blocks a finding, blocks a tool call,
  or requires confirmation. The coverage ledger and baseline artifact are informational
  and self-reported, never a precondition for anything else.
- No reference-project names in code/comments/docs/commit messages inside `src/lalo`,
  `tests/lalo`, or any commit message — describe patterns generically per
  `THIRD_PARTY_NOTICES.md`'s clean-room policy. Skill file bodies never name a
  reference project either, matching every existing skill file's own convention.
- Agent-driven methodology stays primary: every new tool is something an agent
  chooses to call, every new skill is something an agent chooses to `recall` — never
  a fixed Python detector, never a mandatory pipeline stage.
- Every file path/line number/signature below was read live from current source
  during this planning session — re-verify against the live file at implementation
  time if it has drifted, rather than trusting a stale line number.
- Full non-live test suite + `uv run ruff check src/lalo tests/lalo` +
  `uv run ruff format --check src/lalo tests/lalo` + `uv run mypy` + a reference-name
  grep (`grep -rniE "strix" src/lalo tests/lalo` must return nothing) +
  `git fsck --full` after every task.
- Commit message convention: end every commit with the attribution line the harness
  supplies at commit time (it can change between sessions — use whatever the current
  system prompt specifies, not fixed text copied from this plan).
- Every new `category: vulnerability` skill file must contain a `## Proof Ladder`
  heading and cite `[[closure-discipline]]` somewhere in its body — two existing
  structural tests (`tests/lalo/test_skills_loader.py::test_every_vulnerability_skill_states_a_proof_ladder`
  and `::test_every_vulnerability_skill_cites_closure_discipline`) enforce this
  automatically the moment a new file is dropped into `skills/content/`, with no
  test-file change required.

## Scope corrections made during this planning pass

Two items from the spec/approved design were reframed after reading the live current
source, per this project's own "verify before writing a task" discipline:

- **§3.4's coverage ledger** was originally framed as wiring directly into
  `agent/loop.py`'s finish-handling code. Read live: `agent/loop.py`'s finish path
  (`_final_turn`, the mid-loop `"finish"` branch) is generic tool-call handling with
  no report-specific knowledge, and hard-coding a coverage read there would be exactly
  the "mandatory pipeline stage" this project's own constraints forbid. The ledger is
  built as an ordinary tool instead (Task 5), with a one-line prompt-text addition
  (not a code branch) reminding the agent to check it before finishing — informational
  only, changes no control flow.
- **§3.3's protocol-specific skills** named `protocols/graphql.md` as a new file.
  `src/lalo/skills/content/vulnerabilities/graphql.md` already exists and already
  covers schema acquisition, resolver-level authorization, batching/aliasing abuse,
  subscriptions, and persisted-query/federation gaps in full — a real, comprehensive
  skill, not a stub. Task 14 below covers only OAuth/OIDC, the one protocol actually
  missing; GraphQL is recorded as already covered, no task needed.

---

### Task 1: `Finding` schema extensions — fix-verification and dependency/SCA fields

**Files:**
- Modify: `src/lalo/findings/model.py:57-104` (`Finding` dataclass,
  `validate_finding_fields`)
- Modify: `src/lalo/findings/tool.py:37-46,103-251` (`build_record_finding_tool`)
- Modify: `src/lalo/report/collect.py:46-132` (`FindingRecord`, `collect_findings`)
- Test: `tests/lalo/test_findings_model.py`, `tests/lalo/test_findings_tool.py`,
  `tests/lalo/test_report_collect.py` (append to each)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `Finding` gains `fix_verified: bool = False`,
  `fix_verification_notes: str = ""`, `code_locations: list[dict[str, str]] =
  field(default_factory=list)` (each entry: `{"location": str, "fix_before": str,
  "fix_after": str}`), `package_name: str = ""`, `installed_version: str = ""`,
  `ecosystem: str = ""`, `manifest_path: str = ""`, `reachability: str = "unknown"`,
  `reachability_evidence: str = ""`, `contextual_cvss: float | None = None`. A new
  function `validate_dependency_fields(fields: dict[str, object]) -> list[str]` in
  `findings/model.py`. `FindingRecord` gains the identical field set (same names/
  types) — Task 2 and Task 3 read these directly off `FindingRecord`.

- [ ] **Step 1: Write the failing tests**

  Add to `tests/lalo/test_findings_model.py` (the file already has a
  `_valid_fields()`-style helper building a complete, passing `fields` dict for
  `validate_finding_fields` — reuse and extend that pattern for the new validator):

  ```python
  from lalo.findings.model import validate_dependency_fields


  def test_validate_dependency_fields_passes_when_reachability_absent() -> None:
      assert validate_dependency_fields({}) == []

  def test_validate_dependency_fields_passes_for_unknown_reachability() -> None:
      assert validate_dependency_fields({"reachability": "unknown"}) == []

  def test_validate_dependency_fields_rejects_invalid_reachability_value() -> None:
      errors = validate_dependency_fields({"reachability": "definitely"})
      assert any("reachability must be one of" in e for e in errors)

  def test_validate_dependency_fields_requires_evidence_for_non_unknown_reachability() -> None:
      errors = validate_dependency_fields({"reachability": "confirmed"})
      assert any("reachability_evidence cannot be empty" in e for e in errors)

  def test_validate_dependency_fields_passes_confirmed_with_evidence() -> None:
      errors = validate_dependency_fields(
          {"reachability": "confirmed", "reachability_evidence": "traced call path in app.py:42"}
      )
      assert errors == []
  ```

  Add to `tests/lalo/test_findings_tool.py` (the file already builds a
  `ReachabilityGraph()` and calls `build_record_finding_tool(graph).run(args)` with a
  complete valid `args` dict via an existing helper — extend that helper's dict
  rather than duplicating it):

  ```python
  def test_record_finding_accepts_dependency_fields(graph: ReachabilityGraph) -> None:
      tool = build_record_finding_tool(graph)
      args = _valid_finding_args()  # existing helper in this file
      args.update(
          package_name="lodash",
          installed_version="4.17.15",
          ecosystem="npm",
          manifest_path="package-lock.json",
          reachability="confirmed",
          reachability_evidence="traced import in src/utils.js:3, called at src/index.js:88",
          contextual_cvss=6.5,
      )
      result = tool.run(args)
      assert result.ok
      finding_id = result.observation.split()[1].rstrip(":")
      node = graph.node(finding_id)
      assert node["package_name"] == "lodash"
      assert node["reachability"] == "confirmed"
      assert node["contextual_cvss"] == 6.5

  def test_record_finding_rejects_reachability_claim_with_no_evidence(
      graph: ReachabilityGraph,
  ) -> None:
      tool = build_record_finding_tool(graph)
      args = _valid_finding_args()
      args["reachability"] = "likely"
      result = tool.run(args)
      assert not result.ok
      assert "reachability_evidence" in result.observation

  def test_record_finding_accepts_code_locations(graph: ReachabilityGraph) -> None:
      tool = build_record_finding_tool(graph)
      args = _valid_finding_args()
      args["code_locations"] = [
          {"location": "app.py:42", "fix_before": "eval(user_input)", "fix_after": "ast.literal_eval(user_input)"}
      ]
      result = tool.run(args)
      assert result.ok
      finding_id = result.observation.split()[1].rstrip(":")
      assert graph.node(finding_id)["code_locations"] == args["code_locations"]
  ```

  Add to `tests/lalo/test_report_collect.py` (reuse the file's own existing
  `graph.add_node(..., NodeKind.FINDING, ...)` construction pattern):

  ```python
  def test_collect_findings_surfaces_dependency_and_fix_verification_fields() -> None:
      graph = ReachabilityGraph()
      graph.add_node(
          "finding-1", NodeKind.FINDING,
          title="t", description="d", vuln_class="dependency-vulnerability", target="pkg",
          evidence=["e"], evidence_excerpt="e", evidence_grounded=True,
          counterevidence="c", severity_change_conditions="s", remediation="r",
          cvss_score=6.5, cvss_severity="medium", cvss_vector="v",
          reproduced=False, identities_confirmed=[], dedup_key="k",
          package_name="lodash", ecosystem="npm", reachability="confirmed",
          contextual_cvss=6.5, code_locations=[{"location": "a.py:1", "fix_before": "x", "fix_after": "y"}],
          fix_verified=True,
      )
      records = collect_findings(graph)
      assert records[0].package_name == "lodash"
      assert records[0].reachability == "confirmed"
      assert records[0].fix_verified is True
      assert records[0].code_locations == [{"location": "a.py:1", "fix_before": "x", "fix_after": "y"}]
  ```

  (Match `test_report_collect.py`'s own existing full keyword set for `add_node`
  exactly, as Plan 1 Task 9 already notes — the fields above are illustrative of what
  to ADD to that existing set, not a replacement for it.)

- [ ] **Step 2: Run tests to verify they fail**

  ```
  uv run pytest tests/lalo/test_findings_model.py -k dependency_fields tests/lalo/test_findings_tool.py -k "dependency_fields or code_locations or reachability_claim" tests/lalo/test_report_collect.py -k dependency_and_fix -v
  ```

  Expected: FAIL — `validate_dependency_fields` doesn't exist (`ImportError`); the new
  args are silently accepted but never stored (`KeyError` on `node["package_name"]`).

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/findings/model.py`, add after `REQUIRED_TEXT_FIELDS` (around line 54):

  ```python
  _VALID_REACHABILITY = frozenset({"confirmed", "likely", "unlikely", "unknown"})


  def validate_dependency_fields(fields: dict[str, object]) -> list[str]:
      """Extra checks for a dependency/SCA-shaped finding - a no-op for every
      ordinary finding, since the default ``reachability`` is ``"unknown"``
      and an absent key reads the same way. A closed enum, and every
      non-"unknown" value must carry a stated reason: a reachability CLAIM
      with no evidence behind it is the same unfalsifiable-claim problem
      REQUIRED_TEXT_FIELDS already polices for counterevidence and
      severity_change_conditions above - a scanner-reported CVE against an
      installed version proves nothing about whether the vulnerable code
      path is ever actually reached.
      """
      reachability = str(fields.get("reachability") or "unknown").strip().lower()
      errors: list[str] = []
      if reachability not in _VALID_REACHABILITY:
          errors.append(
              f"reachability must be one of {sorted(_VALID_REACHABILITY)}, got {reachability!r}"
          )
      elif reachability != "unknown" and not str(fields.get("reachability_evidence") or "").strip():
          errors.append(
              "reachability_evidence cannot be empty when reachability is not 'unknown' - "
              "state what you traced (a real call path, or a confirmed-absent import) "
              "to reach that verdict"
          )
      return errors
  ```

  Add the new fields to `Finding` (append after `exploitation_steps`, line 87):

  ```python
      # Set when an agent re-tests a PREVIOUSLY reported finding against a
      # claimed fix and confirms it actually holds - never required, never
      # blocking anything; a finding with fix_verified=False simply has no
      # verification opinion yet, the same "absence is not a claim" stance
      # every other optional field here already takes.
      fix_verified: bool = False
      fix_verification_notes: str = ""
      # Each entry: {"location": "path:line", "fix_before": str, "fix_after": str} -
      # what actually changed at a specific location, distinct from
      # source_location's single vulnerability-location/chain-hop role above.
      code_locations: list[dict[str, str]] = field(default_factory=list)
      # Dependency/SCA-shaped finding fields - all optional, all "" / "unknown"
      # by default so an ordinary (non-dependency) finding is entirely
      # unaffected. contextual_cvss is deliberately distinct from
      # cvss_breakdown/the computed cvss_score above: an advisory's own base
      # score describes the vulnerability in the abstract, this one reflects
      # THIS specific deployment's actual reachability and blast radius.
      package_name: str = ""
      installed_version: str = ""
      ecosystem: str = ""
      manifest_path: str = ""
      reachability: str = "unknown"
      reachability_evidence: str = ""
      contextual_cvss: float | None = None
  ```

  In `src/lalo/findings/tool.py`, add a dict-list coercion helper near
  `_as_str_dict` (around line 46):

  ```python
  def _as_dict_list(raw: object) -> list[dict[str, str]]:
      if not isinstance(raw, list):
          return []
      return [{str(k): str(v) for k, v in item.items()} for item in raw if isinstance(item, dict)]
  ```

  Modify `_record_finding`'s validation line (currently line 107-109):

  ```python
          errors = validate_finding_fields(fields) + validate_dependency_fields(fields)
          if errors:
              return ToolResult(observation="error: " + "; ".join(errors), ok=False)
  ```

  (Add `validate_dependency_fields` to the existing `from .model import Finding,
  validate_finding_fields` import line.)

  After the existing `exploitation_steps = [redact(s) for s in ...]` line (line 142),
  add:

  ```python
          code_locations = _as_dict_list(args.get("code_locations"))
          fix_verified = bool(args.get("fix_verified", False))
          fix_verification_notes = redact(str(args.get("fix_verification_notes", "")))
          package_name = str(args.get("package_name", "")).strip()
          installed_version = str(args.get("installed_version", "")).strip()
          ecosystem = str(args.get("ecosystem", "")).strip()
          manifest_path = redact(str(args.get("manifest_path", "")))
          reachability = str(args.get("reachability") or "unknown").strip().lower()
          reachability_evidence = redact(str(args.get("reachability_evidence", "")))
          contextual_cvss_raw = args.get("contextual_cvss")
          contextual_cvss = (
              float(contextual_cvss_raw)  # type: ignore[arg-type]
              if isinstance(contextual_cvss_raw, int | float)
              else None
          )
  ```

  Thread these into the `Finding(...)` construction (add as kwargs after
  `exploitation_steps=exploitation_steps,`, line 209):

  ```python
              code_locations=code_locations,
              fix_verified=fix_verified,
              fix_verification_notes=fix_verification_notes,
              package_name=package_name,
              installed_version=installed_version,
              ecosystem=ecosystem,
              manifest_path=manifest_path,
              reachability=reachability,
              reachability_evidence=reachability_evidence,
              contextual_cvss=contextual_cvss,
  ```

  And into the `attrs` dict built from `finding` (add after `"exploitation_steps":
  finding.exploitation_steps,`, line 234):

  ```python
              "code_locations": finding.code_locations,
              "fix_verified": finding.fix_verified,
              "fix_verification_notes": finding.fix_verification_notes,
              "package_name": finding.package_name,
              "installed_version": finding.installed_version,
              "ecosystem": finding.ecosystem,
              "manifest_path": finding.manifest_path,
              "reachability": finding.reachability,
              "reachability_evidence": finding.reachability_evidence,
              "contextual_cvss": finding.contextual_cvss,
  ```

  Append to `record_finding`'s tool description (end of the existing string, before
  the closing `)}`  at line 299), a new sentence covering the new optional args:

  ```python
              '"code_locations": list[{"location": str, "fix_before": str, "fix_after": '
              'str}] (optional - use when re-testing a PREVIOUSLY reported finding against '
              'a claimed fix), "fix_verified": bool (optional, default false - set true '
              "only once you've actually confirmed the fix holds), \"fix_verification_notes\": "
              'str (optional), "package_name": str, "installed_version": str, "ecosystem": '
              'str (e.g. "npm", "pypi", "cargo"), "manifest_path": str (optional - all four '
              "for a dependency/SCA finding), \"reachability\": "
              '"confirmed"|"likely"|"unlikely"|"unknown" (optional, default "unknown" - '
              "whether the vulnerable code path in this specific dependency is actually "
              'reachable from the target, not just present), "reachability_evidence": str '
              "(required if reachability is not \"unknown\" - what you traced to reach that "
              'verdict), "contextual_cvss": number (optional - this deployment\'s actual '
              "score, distinct from the advisory's own base cvss_breakdown above)}"
  ```

  In `src/lalo/report/collect.py`, add the identical field set to `FindingRecord`
  (append after `exploitation_steps`, line 86):

  ```python
      code_locations: list[dict[str, str]] = field(default_factory=list)
      fix_verified: bool = False
      fix_verification_notes: str = ""
      package_name: str = ""
      installed_version: str = ""
      ecosystem: str = ""
      manifest_path: str = ""
      reachability: str = "unknown"
      reachability_evidence: str = ""
      contextual_cvss: float | None = None
  ```

  And in `collect_findings`'s `FindingRecord(...)` construction (append after
  `exploitation_steps=list(node.get("exploitation_steps", [])),`, line 129):

  ```python
                  code_locations=list(node.get("code_locations", [])),
                  fix_verified=bool(node.get("fix_verified", False)),
                  fix_verification_notes=str(node.get("fix_verification_notes", "")),
                  package_name=str(node.get("package_name", "")),
                  installed_version=str(node.get("installed_version", "")),
                  ecosystem=str(node.get("ecosystem", "")),
                  manifest_path=str(node.get("manifest_path", "")),
                  reachability=str(node.get("reachability", "unknown")),
                  reachability_evidence=str(node.get("reachability_evidence", "")),
                  contextual_cvss=node.get("contextual_cvss"),
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```
  uv run pytest tests/lalo/test_findings_model.py tests/lalo/test_findings_tool.py tests/lalo/test_report_collect.py -v
  ```

  Expected: all PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/findings/model.py src/lalo/findings/tool.py src/lalo/report/collect.py tests/lalo/test_findings_model.py tests/lalo/test_findings_tool.py tests/lalo/test_report_collect.py
  git commit -m "feat(findings): add fix-verification and dependency/SCA fields to Finding

Additive optional fields on the existing Finding/record_finding/FindingRecord
path rather than a separate finding type - code_locations/fix_verified for
re-testing a claimed fix, and package_name/reachability/contextual_cvss for a
dependency finding whose reachability claim must carry evidence, the same
unfalsifiable-claim discipline the existing required text fields already
enforce."
  ```

---

### Task 2: SARIF `fixes[]` synthesis from `code_locations`

**Files:**
- Modify: `src/lalo/report/sarif.py:173-219` (`_build_result`)
- Test: `tests/lalo/test_report_sarif.py` (append)

**Interfaces:**
- Consumes: `FindingRecord.code_locations` (Task 1).
- Produces: a new function `_build_fixes(code_locations: list[dict[str, str]]) ->
  list[dict[str, Any]]` in `report/sarif.py`. No change to `render_sarif`'s public
  signature.

**Context:** SARIF 2.1.0's `result.fixes[]` array lets a viewer (GitHub code scanning
among them) show a suggested/verified code change alongside a result. L4L0 now
records exactly this data (`code_locations`, Task 1) when an agent re-tests a claimed
fix, but nothing renders it into the SARIF output yet.

- [ ] **Step 1: Write the failing test**

  Add to `tests/lalo/test_report_sarif.py` (the file already has a `_record(...)`
  helper building a minimal `FindingRecord` for `render_sarif` — extend its call with
  `code_locations`):

  ```python
  def test_render_sarif_includes_fixes_from_code_locations() -> None:
      record = _record(
          code_locations=[
              {"location": "app.py:42", "fix_before": "eval(x)", "fix_after": "ast.literal_eval(x)"}
          ]
      )
      doc = render_sarif([record])
      result = doc["runs"][0]["results"][0]
      assert "fixes" in result
      fix = result["fixes"][0]
      assert fix["artifactChanges"][0]["artifactLocation"]["uri"] == "app.py"
      assert fix["artifactChanges"][0]["replacements"][0]["insertedContent"]["text"] == (
          "ast.literal_eval(x)"
      )

  def test_render_sarif_omits_fixes_key_when_no_code_locations() -> None:
      record = _record()
      doc = render_sarif([record])
      assert "fixes" not in doc["runs"][0]["results"][0]

  def test_render_sarif_skips_an_unparseable_code_location() -> None:
      record = _record(code_locations=[{"location": "not-a-location", "fix_after": "x"}])
      doc = render_sarif([record])
      assert "fixes" not in doc["runs"][0]["results"][0]
  ```

  (If `_record`'s existing helper doesn't accept `**overrides` today, extend it
  minimally to pass extra `FindingRecord` kwargs through — check the live file first;
  every other test in this file already relies on that helper staying a thin
  pass-through.)

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_report_sarif.py -k fixes -v
  ```

  Expected: FAIL — `"fixes" not in result` for the first test (`KeyError`-shaped
  assertion failure), since nothing builds a `fixes` key today.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/report/sarif.py`, add near `_code_flow` (around line 171):

  ```python
  def _build_fixes(code_locations: list[dict[str, str]]) -> list[dict[str, Any]]:
      """One SARIF ``fix`` per code location that parses - an unparseable
      location is dropped, the same graceful-degrade every other location
      helper in this module already applies, never a reason to fail the
      whole result."""
      fixes: list[dict[str, Any]] = []
      for location in code_locations:
          physical = _physical_location(str(location.get("location", "")))
          if physical is None:
              continue
          fixes.append(
              {
                  "description": {"text": f"Verified fix at {location.get('location', '')}"},
                  "artifactChanges": [
                      {
                          "artifactLocation": physical["artifactLocation"],
                          "replacements": [
                              {
                                  "deletedRegion": physical["region"],
                                  "insertedContent": {"text": str(location.get("fix_after", ""))},
                              }
                          ],
                      }
                  ],
              }
          )
      return fixes
  ```

  In `_build_result` (currently ending around line 216-218 with `if code_flows:
  result["codeFlows"] = code_flows`), add immediately after:

  ```python
      if record.code_locations:
          fixes = _build_fixes(record.code_locations)
          if fixes:
              result["fixes"] = fixes
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_report_sarif.py -k fixes -v
  ```

  Expected: all three PASS.

- [ ] **Step 5: Run the full SARIF suite to confirm no regression**

  ```
  uv run pytest tests/lalo/test_report_sarif.py -v
  ```

  Expected: all PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/report/sarif.py tests/lalo/test_report_sarif.py
  git commit -m "feat(report): synthesize SARIF fixes[] from a finding's code_locations

A finding re-tested against a claimed fix now renders that verification as a
real SARIF result.fixes[] entry (GitHub code scanning and other SARIF
viewers render this natively) instead of the data sitting unused on the
graph node."
  ```

---

### Task 3: SARIF coverage-ledger integration

**Files:**
- Modify: `src/lalo/report/sarif.py:221-264` (`render_sarif`)
- Test: `tests/lalo/test_report_sarif.py` (append)

**Interfaces:**
- Consumes: `CoverageSummary` (`report/coverage.py`, already built — `assessed`/
  `not_assessed`/`verified_safe`/`safe_reasons`).
- Produces: `render_sarif` gains a new optional parameter `coverage:
  CoverageSummary | None = None` — omitted (the default), behavior is byte-for-byte
  identical to today.

**Context:** `render_sarif` today only ever emits a result for a vuln_class that
produced an actual `FindingRecord`. A class an agent specifically tested and
confirmed clean (`record_safe`, surfaced today only via `CoverageSummary.
verified_safe`) has no SARIF representation at all — a CI consumer reading the SARIF
file alone cannot tell "tested, clean" from "never looked at either," even though
L4L0 already has the data to say so.

- [ ] **Step 1: Write the failing test**

  ```python
  def test_render_sarif_with_coverage_emits_a_not_applicable_result_for_verified_safe() -> None:
      from lalo.report.coverage import CoverageSummary

      coverage = CoverageSummary(
          assessed=["xss"],
          not_assessed=["ssrf"],
          verified_safe=["sql-injection"],
          safe_reasons={"sql-injection": "parameterized queries confirmed via source read"},
      )
      doc = render_sarif([], coverage=coverage)
      results = doc["runs"][0]["results"]
      assert len(results) == 1
      assert results[0]["ruleId"] == "sql-injection"
      assert results[0]["kind"] == "notApplicable"
      assert "parameterized queries" in results[0]["message"]["text"]

  def test_render_sarif_with_coverage_never_emits_a_result_for_not_assessed() -> None:
      from lalo.report.coverage import CoverageSummary

      coverage = CoverageSummary(assessed=[], not_assessed=["ssrf"])
      doc = render_sarif([], coverage=coverage)
      assert doc["runs"][0]["results"] == []

  def test_render_sarif_without_coverage_arg_is_unchanged() -> None:
      doc = render_sarif([])
      assert doc["runs"][0]["results"] == []
      assert "coverage" not in doc["runs"][0]
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_report_sarif.py -k coverage -v
  ```

  Expected: FAIL — `render_sarif` accepts no `coverage` keyword today (`TypeError`).

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/report/sarif.py`, add the import:

  ```python
  from .coverage import CoverageSummary
  ```

  Add a builder function near `_owasp_taxonomy_component` (around line 115):

  ```python
  def _coverage_results(
      coverage: CoverageSummary, rule_index_by_id: dict[str, int], rules: list[dict[str, Any]]
  ) -> list[dict[str, Any]]:
      """One SARIF result per verified-safe class - a class actively tested
      and confirmed clean, rendered as ``kind: "notApplicable"`` so a CI
      consumer can tell it apart from a class nobody looked at (which gets
      no result at all here, matching CoverageSummary's own "not asserted"
      honesty principle - see report/coverage.py's module docstring)."""
      results: list[dict[str, Any]] = []
      for vuln_class in coverage.verified_safe:
          if vuln_class not in rule_index_by_id:
              rule_index_by_id[vuln_class] = len(rules)
              rules.append(
                  {
                      "id": vuln_class,
                      "name": vuln_class,
                      "shortDescription": {"text": vuln_class},
                      "defaultConfiguration": {"level": "none"},
                  }
              )
          results.append(
              {
                  "ruleId": vuln_class,
                  "ruleIndex": rule_index_by_id[vuln_class],
                  "kind": "notApplicable",
                  "level": "none",
                  "message": {"text": coverage.safe_reasons.get(vuln_class, "verified safe")},
              }
          )
      return results
  ```

  Modify `render_sarif`'s signature and body (currently lines 221-264):

  ```python
  def render_sarif(
      records: list[FindingRecord],
      *,
      execution_successful: bool = True,
      automation_id: str | None = None,
      coverage: CoverageSummary | None = None,
  ) -> dict[str, Any]:
  ```

  Give every real-finding result an explicit `"kind": "fail"` (SARIF's own default
  for an absent `kind`, made explicit now that this module emits other kinds too) by
  adding it inside `_build_result`'s `result` dict construction (alongside the
  existing `"ruleId"`/`"ruleIndex"`/`"level"` keys):

  ```python
      result: dict[str, Any] = {
          "ruleId": _rule_id(record),
          "ruleIndex": rule_index,
          "kind": "fail",
          "level": _sarif_level(record),
  ```

  And at the end of `render_sarif`, before building `run` (after the existing `for
  record in records:` loop):

  ```python
      if coverage is not None:
          results.extend(_coverage_results(coverage, rule_index_by_id, rules))
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_report_sarif.py -k coverage -v
  ```

  Expected: all three PASS.

- [ ] **Step 5: Run the full SARIF suite to confirm no regression**

  ```
  uv run pytest tests/lalo/test_report_sarif.py -v
  ```

  Expected: all PASS — every existing test calls `render_sarif` positionally/without
  `coverage`, which defaults to `None` and skips the new branch entirely; the new
  `"kind": "fail"` key on every real result is additive and no existing test asserts
  the full result dict shape (each existing test asserts specific keys, confirmed by
  reading the file's own existing assertions).

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/report/sarif.py tests/lalo/test_report_sarif.py
  git commit -m "feat(report): fold the coverage ledger into SARIF as notApplicable results

A vuln_class an agent specifically tested and confirmed clean now renders in
SARIF output too (kind=notApplicable), so a CI consumer reading the SARIF
file alone can tell 'tested, clean' apart from 'nobody looked' - reuses the
existing CoverageSummary.verified_safe data, no new source of truth."
  ```

---

### Task 4: Coverage synonym-phrasing widening

**Files:**
- Modify: `src/lalo/report/coverage.py:50-103` (`build_coverage_summary`)
- Test: `tests/lalo/test_report_coverage.py` (append)

**Interfaces:**
- Consumes: nothing.
- Produces: a new module-level constant `_PHRASING_ALIASES: dict[str, tuple[str,
  ...]]` and a new function `_matches_skill(vuln_class: str, skill_name: str) ->
  bool`. `build_coverage_summary`'s public signature is unchanged.

**Context:** `findings/tool.py`'s own `record_finding` description already states
the hyphenated-slug convention explicitly (a real fix already shipped, per this
module's own docstring). This task is the belt-and-suspenders half: a small phrasing
table so a finding filed as `"broken access control"` or `"sql injection"` (spaces,
not hyphens — a plausible small residual drift even with the improved tool
description) still matches the `access-control`/`sql-injection` skill, without
resurrecting the 76-phrase table this module's own docstring already explains was
deliberately not adopted wholesale.

- [ ] **Step 1: Write the failing test**

  Add to `tests/lalo/test_report_coverage.py` (the file already has a `_skill(name)`
  and `_record(vuln_class)` helper — reuse both):

  ```python
  def test_build_coverage_summary_matches_a_space_separated_phrasing() -> None:
      skills = [_skill("sql-injection")]
      records = [_record("sql injection")]
      summary = build_coverage_summary(skills, records)
      assert summary.assessed == ["sql-injection"]
      assert summary.not_assessed == []

  def test_build_coverage_summary_matches_underscore_separated_phrasing() -> None:
      skills = [_skill("access-control")]
      records = [_record("access_control")]
      summary = build_coverage_summary(skills, records)
      assert summary.assessed == ["access-control"]

  def test_build_coverage_summary_still_reports_not_assessed_for_a_real_miss() -> None:
      skills = [_skill("xss")]
      records = [_record("sql injection")]
      summary = build_coverage_summary(skills, records)
      assert summary.not_assessed == ["xss"]
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_report_coverage.py -k "space_separated or underscore_separated" -v
  ```

  Expected: FAIL — today's exact-match-only comparison leaves `"sql injection"` !=
  `"sql-injection"`, so `sql-injection` lands in `not_assessed` despite the matching
  finding.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/report/coverage.py`, add near the top (after imports, before
  `CoverageSummary`):

  ```python
  def _normalize_phrasing(text: str) -> str:
      """Collapse whitespace/underscores to hyphens and lowercase - closes the
      most common residual drift (a finding filed as "sql injection" or
      "access_control" instead of the skill's own hyphenated slug) without
      the full free-text synonym table this module's own docstring explains
      was deliberately not adopted."""
      return "-".join(text.strip().lower().replace("_", " ").split())


  def _matches_skill(vuln_class: str, skill_name: str) -> bool:
      return _normalize_phrasing(vuln_class) == skill_name.lower()
  ```

  Modify `build_coverage_summary`'s matching (currently lines 83-96):

  ```python
      known = sorted(
          {skill.name.lower() for skill in skills if skill.category == SkillCategory.VULNERABILITY}
      )
      seen_normalized = {_normalize_phrasing(record.vuln_class) for record in records}
      safe_classes: dict[str, str] = {}
      if graph is not None:
          for node_id in graph.nodes_of_kind(NodeKind.VERIFIED_SAFE):
              node = graph.node(node_id)
              vuln_class = _normalize_phrasing(str(node.get("vuln_class", "")))
              if vuln_class and vuln_class not in safe_classes:
                  safe_classes[vuln_class] = str(node.get("defense_mechanism", ""))
      assessed = [name for name in known if name in seen_normalized]
      verified_safe = [name for name in known if name not in seen_normalized and name in safe_classes]
      not_assessed = [
          name for name in known if name not in seen_normalized and name not in safe_classes
      ]
  ```

  (`_matches_skill` is exposed as a small, independently-testable unit even though
  `build_coverage_summary`'s own set-based matching above uses the equivalent
  `_normalize_phrasing(...) == name` comparison directly via set membership — both
  paths apply the identical normalization function, so there is exactly one place
  a future phrasing rule would ever need to change.)

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_report_coverage.py -k "space_separated or underscore_separated or real_miss" -v
  ```

  Expected: all three PASS.

- [ ] **Step 5: Run the full coverage suite to confirm no regression**

  ```
  uv run pytest tests/lalo/test_report_coverage.py -v
  ```

  Expected: all PASS — every existing test already uses exact hyphenated names,
  which `_normalize_phrasing` leaves unchanged (a no-op on an already-hyphenated,
  already-lowercase string).

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/report/coverage.py tests/lalo/test_report_coverage.py
  git commit -m "fix(report): widen coverage matching to space/underscore phrasing variants

record_finding's own tool description already states the hyphenated-slug
convention explicitly, but a small residual drift (a finding filed as 'sql
injection' instead of 'sql-injection') still silently read as a false
'not-tested' gap. Normalizes both sides through one shared function rather
than resurrecting a large synonym table."
  ```

---

### Task 5: Coverage ledger tool (`record_coverage`/`list_coverage`)

**Files:**
- Create: `src/lalo/graph/coverage_ledger.py`
- Modify: `src/lalo/graph/model.py:47-65` (`NodeKind`)
- Modify: `src/lalo/agent/loop.py:207-215` (`_PROTOCOL`)
- Modify: `src/lalo/scan.py:1350-1371` (tool wiring)
- Test: `tests/lalo/test_graph_coverage_ledger.py` (new), `tests/lalo/test_agent_loop.py`
  (append one prompt-content assertion)

**Interfaces:**
- Consumes: `ReachabilityGraph` (existing).
- Produces: `NodeKind.COVERAGE_LEDGER = "coverage_ledger"`; a new function
  `build_coverage_ledger_tool(graph: ReachabilityGraph) -> FunctionTool`. The tool is
  self-reported and purely informational — nothing reads it to gate anything.

**Context, corrected from the original framing (see "Scope corrections" above):**
this is an ordinary agent tool on the existing graph, matching `access_control_matrix`'s
own action-dispatch shape (`build`/`mark_tested`/`query_untested`) rather than a new
persistence layer. An outcome taxonomy of `tested-and-reported` / `tested-and-clean` /
`actively-ruled-out` / `not-applicable` / `needs-follow-up` lets an agent leave an
explicit self-attestation for a surface where none of the existing machine-observed
signals apply (`record_finding` for a real finding, `record_safe` for "I tested this
class and confirmed a working defense") — for example, "I checked whether this
service exposes a GraphQL endpoint at all and it doesn't" (not-applicable), or "I
found a suspicious pattern but couldn't get a definitive read before running out of
time" (needs-follow-up). This is explicitly a THIRD, self-attested signal alongside
the two machine-observed ones `report/coverage.py`'s own docstring already
distinguishes — never a replacement for either, and never blocking anything.

- [ ] **Step 1: Write the failing test**

  Create `tests/lalo/test_graph_coverage_ledger.py`:

  ```python
  from lalo.graph.coverage_ledger import build_coverage_ledger_tool
  from lalo.graph.model import NodeKind, ReachabilityGraph


  def test_record_coverage_requires_outcome_and_target() -> None:
      graph = ReachabilityGraph()
      tool = build_coverage_ledger_tool(graph)
      result = tool.run({"action": "record", "target": "https://x/api"})
      assert not result.ok

  def test_record_coverage_rejects_an_unknown_outcome() -> None:
      graph = ReachabilityGraph()
      tool = build_coverage_ledger_tool(graph)
      result = tool.run(
          {"action": "record", "target": "https://x/api", "vuln_class": "ssrf", "outcome": "maybe"}
      )
      assert not result.ok
      assert "outcome must be one of" in result.observation

  def test_record_and_list_coverage_round_trips() -> None:
      graph = ReachabilityGraph()
      tool = build_coverage_ledger_tool(graph)
      recorded = tool.run(
          {
              "action": "record",
              "target": "https://x/api",
              "vuln_class": "ssrf",
              "outcome": "not-applicable",
              "notes": "no outbound-URL-accepting parameter found",
          }
      )
      assert recorded.ok
      listed = tool.run({"action": "list"})
      assert listed.ok
      assert "ssrf" in listed.observation
      assert "not-applicable" in listed.observation
      assert len(graph.nodes_of_kind(NodeKind.COVERAGE_LEDGER)) == 1

  def test_list_coverage_filters_by_outcome() -> None:
      graph = ReachabilityGraph()
      tool = build_coverage_ledger_tool(graph)
      tool.run({"action": "record", "target": "a", "vuln_class": "ssrf", "outcome": "not-applicable"})
      tool.run({"action": "record", "target": "b", "vuln_class": "xss", "outcome": "needs-follow-up"})
      listed = tool.run({"action": "list", "outcome": "needs-follow-up"})
      assert "xss" in listed.observation
      assert "ssrf" not in listed.observation
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_graph_coverage_ledger.py -v
  ```

  Expected: FAIL — `lalo.graph.coverage_ledger` doesn't exist yet (`ImportError`).

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/graph/model.py`, add to `NodeKind` (after `NOTE`, line 64):

  ```python
      # A self-attested coverage entry - "I tested this and here's what
      # happened" for a surface/outcome shape none of the existing
      # machine-observed signals cover (record_finding for a real finding,
      # VERIFIED_SAFE for a confirmed working defense). Purely informational,
      # never a gate on anything - see graph/coverage_ledger.py.
      COVERAGE_LEDGER = "coverage_ledger"
  ```

  Create `src/lalo/graph/coverage_ledger.py`:

  ```python
  """The ``record_coverage``/``list_coverage`` self-attestation ledger.

  A third coverage signal alongside the two :mod:`~lalo.report.coverage`
  already distinguishes (machine-observed: a filed finding, or a
  ``record_safe`` confirmed-clean assertion) - for a surface where neither
  applies (the class genuinely doesn't exist on this target, or a check
  ran out of time before reaching a verdict), this is where an agent leaves
  an honest, explicit note instead of the surface silently reading as
  "never looked at all." Purely informational: nothing reads this to gate
  anything, matching CLAUDE.md's own no-restrictions posture exactly.
  """

  from __future__ import annotations

  import uuid

  from ..agent.tools import FunctionTool, ToolResult, str_arg
  from ..core.redaction import redact
  from .model import NodeKind, ReachabilityGraph

  _VALID_OUTCOMES = frozenset(
      {"tested-and-reported", "tested-and-clean", "actively-ruled-out", "not-applicable", "needs-follow-up"}
  )
  _MAX_ENTRIES_LISTED = 100


  def build_coverage_ledger_tool(graph: ReachabilityGraph) -> FunctionTool:
      def _run(args: dict[str, object]) -> ToolResult:
          action = str_arg(args, "action", "").strip()
          if action == "record":
              target = str_arg(args, "target", "").strip()
              vuln_class = str_arg(args, "vuln_class", "").strip()
              outcome = str_arg(args, "outcome", "").strip()
              if not target or not vuln_class or not outcome:
                  return ToolResult(
                      observation="error: 'target', 'vuln_class', and 'outcome' are all required",
                      ok=False,
                  )
              if outcome not in _VALID_OUTCOMES:
                  return ToolResult(
                      observation=f"error: outcome must be one of {sorted(_VALID_OUTCOMES)}",
                      ok=False,
                  )
              notes = redact(str(args.get("notes", "")))
              entry_id = f"coverage-{uuid.uuid4().hex[:12]}"
              graph.add_node(
                  entry_id,
                  NodeKind.COVERAGE_LEDGER,
                  target=redact(target),
                  vuln_class=vuln_class,
                  outcome=outcome,
                  notes=notes,
              )
              return ToolResult(observation=f"recorded {entry_id}: {vuln_class} on {target} - {outcome}")
          if action == "list":
              outcome_filter = str_arg(args, "outcome", "").strip()
              ids = graph.nodes_of_kind(NodeKind.COVERAGE_LEDGER)
              lines = []
              for entry_id in ids:
                  node = graph.node(entry_id)
                  if outcome_filter and node.get("outcome") != outcome_filter:
                      continue
                  lines.append(
                      f"- {node.get('vuln_class')} on {node.get('target')}: {node.get('outcome')}"
                      + (f" ({node.get('notes')})" if node.get("notes") else "")
                  )
              shown = lines[:_MAX_ENTRIES_LISTED]
              header = f"{len(lines)} coverage entr{'y' if len(lines) == 1 else 'ies'}:"
              return ToolResult(observation="\n".join([header, *shown]) if lines else "(no coverage entries)")
          return ToolResult(observation=f"error: unknown action {action!r} - use record|list", ok=False)

      return FunctionTool(
          name="coverage_ledger",
          description=(
              "Self-report what you tested and what happened, for a surface none of "
              "record_finding/record_safe already cover (the class doesn't apply here, or "
              "you ran out of time before reaching a verdict). Never a gate on anything - "
              'purely informational. args: {"action": "record"|"list", ...}. record: '
              '{"target": str, "vuln_class": str (same hyphenated-slug convention as '
              'record_finding), "outcome": "tested-and-reported"|"tested-and-clean"|'
              '"actively-ruled-out"|"not-applicable"|"needs-follow-up", "notes": str '
              '(optional)}. list: {"outcome": str (optional filter)}.'
          ),
          func=_run,
      )
  ```

  In `src/lalo/agent/loop.py`, widen `_PROTOCOL` (currently lines 207-215) with one
  added sentence before the closing "Emit only the single JSON object" line:

  ```python
  _PROTOCOL = (
      "Act ONE STEP AT A TIME. Emit EXACTLY ONE JSON object and then STOP — you will "
      "be given that tool's result before you act again. Do NOT plan or emit multiple "
      "steps at once, and do NOT call finish until you have seen real tool results.\n"
      '  {"tool": "<name>", "args": {...}}\n'
      "When the objective is genuinely met, and only then: "
      '{"tool": "finish", "args": {"summary": "..."}}\n'
      "Before finishing, self-report any surface you tested where neither record_finding "
      "nor record_safe applied (not-applicable, or ran out of time) via coverage_ledger — "
      "this never blocks finishing, it just keeps the report honest about what you "
      "actually covered.\n"
      "Emit only the single JSON object, nothing else."
  )
  ```

  In `src/lalo/scan.py`, add the tool to the shared registry (in the `tools: list[Tool]
  = [...]` list, alongside `access_control_matrix_tool`, line ~1361):

  ```python
      coverage_ledger_tool,
  ```

  and build it once, alongside `access_control_matrix_tool`'s own construction (line
  1179):

  ```python
          coverage_ledger_tool = build_coverage_ledger_tool(agent_graph)
  ```

  (`agent_graph` is the same shared `ReachabilityGraph` instance `access_control_matrix_tool`'s
  neighboring lines already close over — re-read the live surrounding code at
  implementation time to confirm the exact variable name in scope at line 1179, since
  it may differ slightly from `agent_graph` depending on what the enclosing function
  parameter is actually named there.)

  Add the import: `from .graph.coverage_ledger import build_coverage_ledger_tool`.

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_graph_coverage_ledger.py -v
  ```

  Expected: all PASS.

- [ ] **Step 5: Add and run the prompt-content regression test**

  Add to `tests/lalo/test_agent_loop.py`:

  ```python
  def test_protocol_mentions_coverage_ledger_before_finishing() -> None:
      from lalo.agent.loop import _PROTOCOL

      assert "coverage_ledger" in _PROTOCOL
  ```

  ```
  uv run pytest tests/lalo/test_agent_loop.py -k coverage_ledger -v
  ```

  Expected: PASS.

- [ ] **Step 6: Run the full test suite for touched files to confirm no regression**

  ```
  uv run pytest tests/lalo/test_graph_coverage_ledger.py tests/lalo/test_agent_loop.py tests/lalo/test_scan.py -v
  ```

  Expected: all PASS.

- [ ] **Step 7: Commit**

  ```bash
  git add src/lalo/graph/coverage_ledger.py src/lalo/graph/model.py src/lalo/agent/loop.py src/lalo/scan.py tests/lalo/test_graph_coverage_ledger.py tests/lalo/test_agent_loop.py
  git commit -m "feat(graph): add a self-attested coverage_ledger tool

A third coverage signal alongside record_finding (a real finding) and
record_safe (a confirmed working defense) - lets an agent honestly note a
surface neither one covers (not applicable to this target, or ran out of
time before reaching a verdict) instead of it silently reading as 'never
looked at all.' Purely informational: an ordinary agent tool on the
existing graph, never a gate, never wired into loop.py's control flow."
  ```

---

### Task 6: Multi-agent lifecycle — `stop_agent`, background `spawn_agent`, `wait_for_agents`

**Files:**
- Modify: `src/lalo/agent/spawn.py:152-345` (`AgentNode`, `AgentCoordinator`,
  `build_spawn_tools`)
- Modify: `src/lalo/scan.py:1248-1263` (child `AgentLoop` construction)
- Test: `tests/lalo/test_spawn.py` (append)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `AgentNode` gains `stop_reason: str = ""`. `AgentCoordinator` gains
  `mark_stopped(agent_id: str, reason: str) -> None`, `is_stopped(agent_id: str) ->
  bool`, `submit_background(agent_id: str, run: Callable[[], tuple[str, list[str],
  bool]]) -> None`, `wait_for(agent_id: str, timeout: float | None = None) ->
  tuple[str, list[str], bool] | None`, `close() -> None`. `build_spawn_tools` returns
  a 3-tuple now (`spawn_agent`, `view_agent_graph`, `stop_agent`) instead of 2 — every
  call site must be updated. `spawn_agent`'s args gain an optional `background: bool`.
  A new `build_wait_for_agents_tool(coordinator: AgentCoordinator) -> FunctionTool`.

**Context, corrected from the original framing (see "Scope corrections" section of
the design spec):** rather than changing `spawn_agents`' existing, already-tested,
documented barrier semantics ("wait for all of them and get every result back at
once" — its own tool description), the smaller and more surgical way to get a
genuinely selective wait is an optional `background: bool` on the EXISTING single-child
`spawn_agent` tool: a background-spawned child returns its `agent_id` immediately, and
a new `wait_for_agents` tool joins specific ids whenever the caller actually needs
them. `spawn_agents` itself is untouched — zero risk to its existing tests/behavior.

- [ ] **Step 1: Write the failing tests**

  Add to `tests/lalo/test_spawn.py` (the file already has a `_run_child` fixture
  returning a fixed `(summary, finding_ids, success)` tuple, and calls
  `build_spawn_tools(coordinator, run_child, self_id=root_id)` — reuse both):

  ```python
  import threading
  import time


  def test_stop_agent_marks_a_running_agent_stopped() -> None:
      coordinator = AgentCoordinator()
      root_id = coordinator.register_root("root", "mission")
      child_id = coordinator.spawn(root_id, "child", "task")
      spawn_tool, view_tool, stop_tool = build_spawn_tools(
          coordinator, lambda cid, n, t: ("done", [], True), self_id=root_id
      )
      result = stop_tool.run({"agent_id": child_id, "reason": "duplicate of another agent"})
      assert result.ok
      assert coordinator.is_stopped(child_id)
      assert coordinator.node(child_id).stop_reason == "duplicate of another agent"

  def test_stop_agent_rejects_an_unknown_id() -> None:
      coordinator = AgentCoordinator()
      root_id = coordinator.register_root("root", "mission")
      _spawn, _view, stop_tool = build_spawn_tools(
          coordinator, lambda cid, n, t: ("done", [], True), self_id=root_id
      )
      result = stop_tool.run({"agent_id": "agent-999", "reason": "x"})
      assert not result.ok

  def test_stop_agent_rejects_an_already_completed_agent() -> None:
      coordinator = AgentCoordinator()
      root_id = coordinator.register_root("root", "mission")
      child_id = coordinator.spawn(root_id, "child", "task")
      coordinator.record_result(child_id, summary="done", success=True)
      _spawn, _view, stop_tool = build_spawn_tools(
          coordinator, lambda cid, n, t: ("done", [], True), self_id=root_id
      )
      result = stop_tool.run({"agent_id": child_id, "reason": "x"})
      assert not result.ok

  def test_background_spawn_returns_immediately_and_wait_for_agents_joins_it() -> None:
      release = threading.Event()

      def _slow_run_child(child_id: str, name: str, task: str) -> tuple[str, list[str], bool]:
          release.wait(timeout=5)
          return "finished slowly", ["finding-1"], True

      coordinator = AgentCoordinator()
      root_id = coordinator.register_root("root", "mission")
      spawn_tool, _view, _stop = build_spawn_tools(coordinator, _slow_run_child, self_id=root_id)
      wait_tool = build_wait_for_agents_tool(coordinator)

      start = time.monotonic()
      spawn_result = spawn_tool.run({"name": "child", "task": "task", "background": True})
      elapsed = time.monotonic() - start
      assert spawn_result.ok
      assert elapsed < 1.0  # returned immediately, did not block on release
      import re

      match = re.search(r"agent-\d+", spawn_result.observation)
      assert match is not None
      child_id = match.group(0)

      release.set()
      wait_result = wait_tool.run({"agent_ids": [child_id]})
      assert wait_result.ok
      assert "finished slowly" in wait_result.observation
      assert coordinator.node(child_id).status is AgentStatus.COMPLETED

  def test_wait_for_agents_reports_an_unknown_or_already_awaited_id() -> None:
      coordinator = AgentCoordinator()
      wait_tool = build_wait_for_agents_tool(coordinator)
      result = wait_tool.run({"agent_ids": ["agent-999"]})
      assert "error" in result.observation
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```
  uv run pytest tests/lalo/test_spawn.py -k "stop_agent or background_spawn or wait_for_agents" -v
  ```

  Expected: FAIL — `build_spawn_tools` returns a 2-tuple today (`ValueError: not
  enough values to unpack`); `build_wait_for_agents_tool` doesn't exist.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/agent/spawn.py`, add to the imports:

  ```python
  from concurrent.futures import Future
  ```

  Add `stop_reason` to `AgentNode` (after `role: str = "full"`, line 162):

  ```python
      stop_reason: str = ""
  ```

  In `AgentCoordinator.__init__` (currently lines 173-184), add:

  ```python
          self._stopped: set[str] = set()
          self._pending: dict[str, Future[tuple[str, list[str], bool]]] = {}
          self._executor = ThreadPoolExecutor(max_workers=_MAX_PARALLEL_WORKERS)
  ```

  Add these methods to `AgentCoordinator` (after `record_result`, around line 238):

  ```python
      def mark_stopped(self, agent_id: str, reason: str) -> None:
          with self._lock:
              self._stopped.add(agent_id)
              node = self._nodes.get(agent_id)
              if node is not None:
                  node.stop_reason = reason

      def is_stopped(self, agent_id: str) -> bool:
          with self._lock:
              return agent_id in self._stopped

      def submit_background(
          self, agent_id: str, run: Callable[[], tuple[str, list[str], bool]]
      ) -> None:
          with self._lock:
              self._pending[agent_id] = self._executor.submit(run)

      def wait_for(
          self, agent_id: str, timeout: float | None = None
      ) -> tuple[str, list[str], bool] | None:
          with self._lock:
              future = self._pending.get(agent_id)
          if future is None:
              return None
          return future.result(timeout=timeout)

      def close(self) -> None:
          self._executor.shutdown(wait=False, cancel_futures=True)
  ```

  Modify `build_spawn_tools` to return a 3-tuple and add `background` handling.
  Current signature/return (lines 346-352, 462-468):

  ```python
  def build_spawn_tools(
      coordinator: AgentCoordinator,
      run_child: ChildRunner,
      *,
      self_id: str,
      valid_roles: frozenset[str] = frozenset({"full"}),
  ) -> tuple[Tool, Tool, Tool]:
  ```

  In `_spawn`, after the existing `warning = _duplicate_task_warning(...)` and
  `child_id = coordinator.spawn(...)` lines (currently 413-417), branch on
  `background` BEFORE the existing synchronous `run_child(...)` call:

  ```python
          background = bool(args.get("background", False))
          if background:

              def _run_background(
                  _child_id: str = child_id, _name: str = name, _task: str = task
              ) -> tuple[str, list[str], bool]:
                  try:
                      return run_child(_child_id, _name, _task)
                  except Exception as exc:  # noqa: BLE001 - matches the synchronous path's
                      # own crash handling: a crashed background child must still resolve
                      # to a terminal tuple, never leave wait_for_agents hanging on an
                      # exception it has to catch itself.
                      return f"child crashed: {type(exc).__name__}: {exc}", [], False

              coordinator.submit_background(child_id, _run_background)
              return ToolResult(
                  observation=(
                      f"{warning}started {child_id} in the background - call wait_for_agents "
                      f"with this agent_id once you need its result, or stop_agent to cancel it"
                  ),
                  ok=True,
              )
  ```

  (Insert this branch immediately after `child_id = coordinator.spawn(...)`'s
  `try/except SpawnDepthExceededError` block, before the existing `try: summary,
  finding_ids, success = run_child(...)` synchronous line — the synchronous path
  below is otherwise completely unchanged.)

  Add the new `_stop_agent` closure and tool inside `build_spawn_tools` (after
  `_view_graph`, before the `return` statement):

  ```python
      def _stop_agent(args: dict[str, object]) -> ToolResult:
          agent_id = str_arg(args, "agent_id", "").strip()
          reason = str_arg(args, "reason", "no reason given").strip()
          if not agent_id:
              return ToolResult(observation="error: 'agent_id' is required", ok=False)
          if not coordinator.has_node(agent_id):
              return ToolResult(
                  observation=f"error: {agent_id!r} is not a known agent - "
                  "call view_agent_graph to see valid ids",
                  ok=False,
              )
          node = coordinator.node(agent_id)
          if node.status is not AgentStatus.RUNNING:
              return ToolResult(
                  observation=f"error: {agent_id!r} is not running (status: "
                  f"{node.status.value}) - only a running agent can be stopped",
                  ok=False,
              )
          coordinator.mark_stopped(agent_id, reason)
          return ToolResult(
              observation=f"requested stop for {agent_id}: {reason} - it will stop at its "
              "next checkpoint, not necessarily instantly"
          )

      stop_tool = FunctionTool(
          name="stop_agent",
          description=(
              "Request that a running agent (yours or any descendant, per view_agent_graph) "
              "stop at its next checkpoint - e.g. a duplicate specialist, or one whose task "
              "is now known to be moot. Cooperative, not instant. args: "
              '{"agent_id": str, "reason": str}'
          ),
          func=_stop_agent,
      )
  ```

  Update the `return` statement:

  ```python
      return spawn_tool, graph_tool, stop_tool
  ```

  Update `spawn_tool`'s description to mention `background`:

  ```python
              'ignored and the agent\'s own original task continues from its last completed '
              'step), "background": bool (optional, default false - when true, returns '
              "this agent's id immediately without waiting for it to finish; use "
              'wait_for_agents to get its result once you need it)}'
  ```

  (Append this to the existing description string, replacing its current closing
  `)}"` with the text above, keeping everything before it unchanged.)

  Add `build_wait_for_agents_tool` as a new top-level function (after
  `build_spawn_tools`, before `build_parallel_spawn_tool`):

  ```python
  def build_wait_for_agents_tool(coordinator: AgentCoordinator) -> Tool:
      def _wait(args: dict[str, object]) -> ToolResult:
          raw_ids = args.get("agent_ids")
          if not isinstance(raw_ids, list) or not raw_ids:
              return ToolResult(observation="error: 'agent_ids' must be a non-empty list", ok=False)
          reports: list[dict[str, object]] = []
          overall_ok = True
          for raw in raw_ids:
              agent_id = str(raw)
              result = coordinator.wait_for(agent_id)
              if result is None:
                  reports.append(
                      {
                          "agent_id": agent_id,
                          "error": "not a background-spawned agent, or already awaited elsewhere",
                      }
                  )
                  overall_ok = False
                  continue
              summary, finding_ids, success = result
              coordinator.record_result(agent_id, summary=summary, finding_ids=finding_ids, success=success)
              reports.append(
                  {
                      "agent_id": agent_id,
                      "success": success,
                      "summary": summary,
                      "filed_finding_ids": finding_ids,
                  }
              )
              overall_ok = overall_ok and success
          return ToolResult(observation=json.dumps(reports), ok=overall_ok)

      return FunctionTool(
          name="wait_for_agents",
          description=(
              "Block until every listed background-spawned agent (see spawn_agent's "
              "'background' arg) finishes, and get each one's authoritative result. "
              'args: {"agent_ids": list[str]}'
          ),
          func=_wait,
      )
  ```

  In `src/lalo/scan.py`, update the `build_spawn_tools` call site (currently line
  1380-1382) to unpack 3 values and register the new tools:

  ```python
              spawn_tool, view_graph_tool, stop_agent_tool = build_spawn_tools(
                  coordinator, _run_child, self_id=self_id, valid_roles=frozenset(_ROLE_TOOL_NAMES)
              )
              wait_for_agents_tool = build_wait_for_agents_tool(coordinator)
              parallel_spawn_tool = build_parallel_spawn_tool(
                  coordinator, _run_child, self_id=self_id, valid_roles=frozenset(_ROLE_TOOL_NAMES)
              )
              tools += [spawn_tool, parallel_spawn_tool, view_graph_tool, stop_agent_tool, wait_for_agents_tool]
  ```

  Add `build_wait_for_agents_tool` to the existing `from .agent.spawn import
  build_parallel_spawn_tool, build_spawn_tools` import line.

  Compose the per-child `should_stop` with the coordinator's own per-agent flag at
  the child `AgentLoop` construction site (currently line 1256):

  ```python
                  should_stop=lambda cid=child_id: self._should_stop() or coordinator.is_stopped(cid),
  ```

  (`cid=child_id` as a default argument captures the loop variable's value at
  closure-creation time — this construction already runs inside a per-child closure
  body, confirmed by reading the surrounding `_run_child` function, so `child_id`
  itself is already the correct per-call value and the default-arg pattern only
  guards against a future refactor that moves this into a shared loop.)

  Find wherever `AgentCoordinator()` is constructed in `scan.py` (its `__init__`
  call site) and add a `finally: coordinator.close()` around the scan's main run
  block, so the persistent executor added in this task doesn't outlive the scan —
  read the live surrounding function first to place this correctly without
  disturbing existing cleanup ordering (container teardown, journal close, etc.).

- [ ] **Step 4: Run tests to verify they pass**

  ```
  uv run pytest tests/lalo/test_spawn.py -v
  ```

  Expected: all PASS, including every pre-existing test in the file (the 2-tuple →
  3-tuple change means every existing test unpacking `build_spawn_tools`'s return
  must also be updated to a 3-tuple — do this as part of this task, not left broken).

- [ ] **Step 5: Run the full scan suite to confirm no regression**

  ```
  uv run pytest tests/lalo/test_spawn.py tests/lalo/test_scan.py tests/lalo/test_agent_loop.py -v
  ```

  Expected: all PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/agent/spawn.py src/lalo/scan.py tests/lalo/test_spawn.py
  git commit -m "feat(spawn): add stop_agent, background spawn_agent, and wait_for_agents

spawn_agents' own existing wait-for-all-then-join semantics are unchanged -
selective waiting is a new, optional background=true on the existing single-
child spawn_agent tool plus a new wait_for_agents join point, backed by a
persistent per-coordinator thread pool. stop_agent composes a per-agent
cooperative-cancel flag into the same should_stop() checkpoint every agent
already polls, alongside the existing whole-scan-wide stop condition."
  ```

---

### Task 7: Passive HTTP request/response history + replay

**Files:**
- Create: `src/lalo/execution/history.py`
- Modify: `src/lalo/execution/firer.py:129-171` (`HttpFirer`)
- Modify: `src/lalo/execution/tool.py:1-30` (imports, new tool builder)
- Modify: `src/lalo/scan.py:1350-1371` (tool wiring)
- Test: `tests/lalo/test_execution_history.py` (new), `tests/lalo/test_execution_firer.py`
  (append)

**Interfaces:**
- Consumes: `HttpFirer`/`FireResult` (existing, `execution/firer.py`).
- Produces: `RequestHistory`/`HistoryEntry` in the new `history.py` module.
  `HttpFirer` gains `attach_recorder(recorder: RequestHistory) -> None` and records
  every successfully-fired request through its one existing `fire()` choke point. A
  new `build_http_history_tool(history: RequestHistory, firer: HttpFirer) ->
  FunctionTool` in `execution/tool.py`.

**Context, scope note:** `http`, `fire_concurrent`, and `diff_responses` all call
`HttpFirer.fire()` directly and get history recording automatically once it's wired
into that one method. The `browser` tool (`src/lalo/browser/tool.py`, read live this
session) drives Playwright DOM actions directly and never calls `HttpFirer` at all —
instrumenting Playwright's own network layer for history capture is a materially
larger, separate undertaking (a CDP network-event listener inside `BrowserSession`,
not a one-method wrapper) and is explicitly deferred, not silently dropped: it can be
added later as its own task once this HTTP-side history tool is in real use and its
value is confirmed.

- [ ] **Step 1: Write the failing tests**

  Create `tests/lalo/test_execution_history.py`:

  ```python
  from lalo.execution.firer import FireResult
  from lalo.execution.history import RequestHistory


  def _fire_result(**overrides: object) -> FireResult:
      defaults = dict(method="GET", url="https://x/a", fired=True, scope_reason="in_scope", status=200)
      defaults.update(overrides)
      return FireResult(**defaults)  # type: ignore[arg-type]


  def test_record_and_list_round_trips() -> None:
      history = RequestHistory()
      history.record("GET", "https://x/a", {"Accept": "*/*"}, b"", _fire_result())
      entries = history.list()
      assert len(entries) == 1
      assert entries[0].url == "https://x/a"
      assert entries[0].index == 0

  def test_list_filters_by_url_substring_and_method() -> None:
      history = RequestHistory()
      history.record("GET", "https://x/a", {}, b"", _fire_result(url="https://x/a"))
      history.record("POST", "https://x/b", {}, b"", _fire_result(method="POST", url="https://x/b"))
      assert [e.url for e in history.list(url_contains="/b")] == ["https://x/b"]
      assert [e.method for e in history.list(method="post")] == ["POST"]

  def test_get_returns_none_for_an_unknown_index() -> None:
      history = RequestHistory()
      assert history.get(99) is None

  def test_history_drops_oldest_entries_past_max_entries() -> None:
      history = RequestHistory(max_entries=2)
      for i in range(3):
          history.record("GET", f"https://x/{i}", {}, b"", _fire_result(url=f"https://x/{i}"))
      urls = [e.url for e in history.list()]
      assert urls == ["https://x/1", "https://x/2"]
  ```

  Add to `tests/lalo/test_execution_firer.py` (the file already builds an `HttpFirer`
  against a fake/mocked `httpx.Client` — reuse that fixture):

  ```python
  def test_firer_records_a_fired_request_into_an_attached_history() -> None:
      from lalo.execution.history import RequestHistory

      firer = _make_firer()  # existing helper in this file
      history = RequestHistory()
      firer.attach_recorder(history)
      firer.fire("GET", "https://example.com/")
      entries = history.list()
      assert len(entries) == 1
      assert entries[0].url == "https://example.com/"

  def test_firer_with_no_recorder_attached_does_not_error() -> None:
      firer = _make_firer()
      result = firer.fire("GET", "https://example.com/")
      assert result.fired
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```
  uv run pytest tests/lalo/test_execution_history.py tests/lalo/test_execution_firer.py -k "history or recorder" -v
  ```

  Expected: FAIL — `lalo.execution.history` doesn't exist; `HttpFirer` has no
  `attach_recorder`.

- [ ] **Step 3: Write minimal implementation**

  Create `src/lalo/execution/history.py`:

  ```python
  """Passive HTTP request/response history - a byproduct of firing, for later
  listing, inspection, and replay-with-edits. Recorded at HttpFirer.fire()'s
  one existing choke point (see attach_recorder there), so http/
  fire_concurrent/diff_responses all populate it automatically with zero
  change to any of their own call sites.
  """

  from __future__ import annotations

  import threading
  from dataclasses import dataclass, field

  from .firer import FireResult

  _DEFAULT_MAX_ENTRIES = 500


  @dataclass(frozen=True)
  class HistoryEntry:
      index: int
      method: str
      url: str
      request_headers: dict[str, str]
      request_body: bytes
      result: FireResult


  class RequestHistory:
      """Bounded, thread-safe in-memory history for one scan's fired requests."""

      def __init__(self, *, max_entries: int = _DEFAULT_MAX_ENTRIES) -> None:
          self._entries: list[HistoryEntry] = []
          self._max_entries = max_entries
          self._next_index = 0
          self._lock = threading.Lock()

      def record(
          self,
          method: str,
          url: str,
          headers: dict[str, str] | None,
          body: bytes | None,
          result: FireResult,
      ) -> None:
          with self._lock:
              entry = HistoryEntry(
                  index=self._next_index,
                  method=method.upper(),
                  url=url,
                  request_headers=dict(headers or {}),
                  request_body=body or b"",
                  result=result,
              )
              self._next_index += 1
              self._entries.append(entry)
              if len(self._entries) > self._max_entries:
                  # ponytail: oldest-entry eviction, not a ring buffer - fine
                  # at this scan-local, single-digit-thousands scale; a ring
                  # buffer only pays for itself at a size this never reaches.
                  self._entries.pop(0)

      def list(
          self, *, url_contains: str | None = None, method: str | None = None
      ) -> list[HistoryEntry]:
          with self._lock:
              entries = list(self._entries)
          if url_contains:
              entries = [e for e in entries if url_contains.lower() in e.url.lower()]
          if method:
              entries = [e for e in entries if e.method == method.upper()]
          return entries

      def get(self, index: int) -> HistoryEntry | None:
          with self._lock:
              return next((e for e in self._entries if e.index == index), None)
  ```

  In `src/lalo/execution/firer.py`, extract the existing `fire()` body into a
  private `_fire_impl` and make `fire()` a thin recording wrapper. Current `fire()`
  signature (line 170):

  ```python
      def fire(
          self,
          method: str,
          url: str,
          *,
          headers: dict[str, str] | None = None,
          content: bytes | None = None,
      ) -> FireResult:
  ```

  Rename this method to `_fire_impl` (keep its entire existing body byte-for-byte
  unchanged), and add a new thin `fire()` above it:

  ```python
      def fire(
          self,
          method: str,
          url: str,
          *,
          headers: dict[str, str] | None = None,
          content: bytes | None = None,
      ) -> FireResult:
          result = self._fire_impl(method, url, headers=headers, content=content)
          if self._recorder is not None and result.fired:
              self._recorder.record(method, url, headers, content, result)
          return result
  ```

  Add `attach_recorder` and the `_recorder` attribute to `__init__` (currently lines
  132-159):

  ```python
          self._recorder: RequestHistory | None = None
  ```

  (add this line inside `__init__`, alongside `self._breakers: dict[str, _Breaker] =
  {}`)

  ```python
      def attach_recorder(self, recorder: RequestHistory) -> None:
          self._recorder = recorder
  ```

  Add the import (avoiding a circular import — `history.py` imports `FireResult`
  from `firer.py`, so `firer.py` uses a `TYPE_CHECKING`-guarded import for the
  reverse reference):

  ```python
  from typing import TYPE_CHECKING

  if TYPE_CHECKING:
      from .history import RequestHistory
  ```

  In `src/lalo/execution/tool.py`, add the history tool builder after
  `build_dns_query_tool` (end of file, around line 504):

  ```python
  _TRANSFER_ENCODING_HEADER = "transfer-encoding"
  _CONTENT_LENGTH_HEADER = "content-length"


  def _replay_headers(original: dict[str, str], overrides: dict[str, str], body: bytes) -> dict[str, str]:
      """Merge ``overrides`` onto ``original`` for a replay, then fix up the
      two headers a modified body can silently make wrong: drop any
      inherited Transfer-Encoding (chunked framing the new, different-length
      body was never actually chunked for) and recompute Content-Length from
      the ACTUAL body being sent, never trust a stale inherited value."""
      merged = {k: v for k, v in {**original, **overrides}.items() if k.lower() != _TRANSFER_ENCODING_HEADER}
      merged = {k: v for k, v in merged.items() if k.lower() != _CONTENT_LENGTH_HEADER}
      merged["Content-Length"] = str(len(body))
      return merged


  def build_http_history_tool(history: RequestHistory, firer: HttpFirer) -> FunctionTool:
      def _describe(entry: HistoryEntry) -> str:
          status = entry.result.status if entry.result.status is not None else "-"
          return f"[{entry.index}] {entry.method} {entry.url} -> {status}"

      def _history_tool(args: dict[str, object]) -> ToolResult:
          action = str_arg(args, "action", "list").strip() or "list"
          if action == "list":
              url_contains = str_arg(args, "url_contains", "").strip() or None
              method = str_arg(args, "method", "").strip() or None
              entries = history.list(url_contains=url_contains, method=method)
              shown = entries[-50:]
              lines = [_describe(e) for e in shown]
              return ToolResult(observation="\n".join(lines) if lines else "(no history yet)")
          if action == "view":
              index_raw = args.get("index")
              if index_raw is None:
                  return ToolResult(observation="error: 'index' is required for action=view", ok=False)
              entry = history.get(int(index_raw))  # type: ignore[call-overload]
              if entry is None:
                  return ToolResult(observation=f"error: no history entry {index_raw}", ok=False)
              body_text = entry.result.body[:_MAX_BODY_CHARS].decode("utf-8", errors="replace")
              return ToolResult(
                  observation=(
                      f"{entry.method} {entry.url}\nrequest headers={entry.request_headers}\n"
                      f"request body={entry.request_body[:_MAX_BODY_CHARS]!r}\n\n"
                      f"status={entry.result.status} response headers={dict(entry.result.headers)}\n\n"
                      f"{body_text}"
                  )
              )
          if action == "replay":
              index_raw = args.get("index")
              if index_raw is None:
                  return ToolResult(observation="error: 'index' is required for action=replay", ok=False)
              entry = history.get(int(index_raw))  # type: ignore[call-overload]
              if entry is None:
                  return ToolResult(observation=f"error: no history entry {index_raw}", ok=False)
              header_overrides = _headers_arg(args, "headers")
              if isinstance(header_overrides, str):
                  return ToolResult(observation=f"error: {header_overrides}", ok=False)
              body_override = _bytes_arg(args, "body")
              if isinstance(body_override, str):
                  return ToolResult(observation=f"error: {body_override}", ok=False)
              url = str_arg(args, "url", entry.url) or entry.url
              body = body_override if body_override is not None else entry.request_body
              headers = _replay_headers(entry.request_headers, header_overrides or {}, body)
              result = firer.fire(entry.method, url, headers=headers, content=body)
              if not result.fired:
                  return ToolResult(observation=f"not fired: {result.scope_reason}", ok=False)
              body_text = result.body[:_MAX_BODY_CHARS].decode("utf-8", errors="replace")
              return ToolResult(observation=f"status={result.status}\n\n{body_text}")
          return ToolResult(observation=f"error: unknown action {action!r} - use list|view|replay", ok=False)

      return FunctionTool(
          name="http_history",
          description=(
              "List, inspect, or replay (with optional field edits) requests already fired "
              "via http/fire_concurrent/diff_responses - a passive-by-default record of what "
              "you've already sent, so you never have to re-derive a URL/header/body you "
              'fired earlier just to look at it again. args: {"action": "list"|"view"|'
              '"replay", ...}. list: {"url_contains": str (optional), "method": str '
              '(optional)} - shows the most recent 50. view: {"index": int}. replay: '
              '{"index": int, "url": str (optional override), "headers": dict (optional, '
              "merged onto the original - Content-Length is always recomputed and any "
              'inherited Transfer-Encoding always dropped), "body": str (optional override)}'
          ),
          func=_history_tool,
      )
  ```

  Add the new imports at the top of `execution/tool.py`:

  ```python
  from .history import HistoryEntry, RequestHistory
  ```

  In `src/lalo/scan.py`, construct one `RequestHistory` per scan (alongside where
  `firer = HttpFirer(...)` is built), attach it, and add the tool:

  ```python
          history = RequestHistory()
          firer.attach_recorder(history)
  ```

  ```python
      history_tool = build_http_history_tool(history, firer)
  ```

  and add `history_tool` to the `tools: list[Tool] = [...]` list alongside
  `build_http_tool(firer)` (line 1355). Add the imports:
  `from .execution.history import RequestHistory`, and add
  `build_http_history_tool` to the existing `from .execution.tool import
  build_http_tool, ...` line.

  (Read the live surrounding `scan.py` code at implementation time to place the
  `firer = HttpFirer(...)` and `history = RequestHistory()` construction correctly —
  they must be built once per scan, not once per agent, matching how `firer` itself
  is already shared across every agent in the hierarchy.)

- [ ] **Step 4: Run tests to verify they pass**

  ```
  uv run pytest tests/lalo/test_execution_history.py tests/lalo/test_execution_firer.py -v
  ```

  Expected: all PASS.

- [ ] **Step 5: Add a replay-header-fixup unit test and run it**

  Add to `tests/lalo/test_execution_tool.py`:

  ```python
  def test_replay_headers_drops_transfer_encoding_and_recomputes_content_length() -> None:
      from lalo.execution.tool import _replay_headers

      original = {"Content-Length": "3", "Transfer-Encoding": "chunked", "Accept": "*/*"}
      merged = _replay_headers(original, {}, b"a longer body now")
      assert "Transfer-Encoding" not in merged
      assert merged["Content-Length"] == str(len(b"a longer body now"))
      assert merged["Accept"] == "*/*"
  ```

  ```
  uv run pytest tests/lalo/test_execution_tool.py -k replay_headers -v
  ```

  Expected: PASS.

- [ ] **Step 6: Run the full execution suite to confirm no regression**

  ```
  uv run pytest tests/lalo/test_execution_tool.py tests/lalo/test_execution_firer.py tests/lalo/test_execution_history.py tests/lalo/test_scan.py -v
  ```

  Expected: all PASS.

- [ ] **Step 7: Commit**

  ```bash
  git add src/lalo/execution/history.py src/lalo/execution/firer.py src/lalo/execution/tool.py src/lalo/scan.py tests/lalo/test_execution_history.py tests/lalo/test_execution_firer.py tests/lalo/test_execution_tool.py
  git commit -m "feat(execution): add passive HTTP request/response history + replay

Every request fired via http/fire_concurrent/diff_responses is now recorded
as a byproduct at HttpFirer.fire()'s one existing choke point, with a new
http_history tool to list/inspect/replay-with-edits it - the single most
independently-corroborated capability gap this round identified. Browser-
driven traffic capture (Playwright's own network layer) is a separate,
larger undertaking, explicitly deferred rather than attempted here."
  ```

---

### Task 8: Shared identity-normalized baseline/threat-model artifact

**Files:**
- Create: `src/lalo/graph/baseline.py`
- Modify: `src/lalo/graph/model.py:47-65` (`NodeKind`)
- Modify: `src/lalo/scan.py` (tool wiring)
- Test: `tests/lalo/test_graph_baseline.py` (new)

**Interfaces:**
- Consumes: `ReachabilityGraph` (existing).
- Produces: `NodeKind.BASELINE = "baseline"`; a new function
  `build_baseline_tool(graph: ReachabilityGraph, agent_id: str) -> FunctionTool`.

**Context:** A shared, append-only artifact per target identity that every agent in
the hierarchy (root and every spawned child) can read and add to — an architecture
threat model, an inventory of confirmed authentication schemes, a running list of
known internal hostnames — so a later-spawned specialist doesn't have to rediscover
what an earlier one already established. Built as a new node kind on the existing,
already-checkpointed `ReachabilityGraph` (the same pattern `VERIFIED_SAFE`/`NOTE`
already use) rather than a separate artifact file, so it gets crash-safe persistence
for free. Identity normalization (so `https://api.example.com:443/` and
`api.example.com` resolve to the same baseline entry) uses a small local helper — no
existing normalization function was found in `execution/target.py` to reuse (checked
live: `Engagement`/`TargetRule` there do glob-pattern *matching*, not identity
canonicalization).

- [ ] **Step 1: Write the failing tests**

  Create `tests/lalo/test_graph_baseline.py`:

  ```python
  from lalo.graph.baseline import build_baseline_tool
  from lalo.graph.model import NodeKind, ReachabilityGraph


  def test_save_baseline_requires_summary_and_category() -> None:
      graph = ReachabilityGraph()
      tool = build_baseline_tool(graph, "agent-1")
      result = tool.run({"action": "save", "target": "api.example.com"})
      assert not result.ok

  def test_save_then_get_baseline_round_trips() -> None:
      graph = ReachabilityGraph()
      tool = build_baseline_tool(graph, "agent-1")
      saved = tool.run(
          {
              "action": "save",
              "target": "https://api.example.com:443/",
              "category": "authentication",
              "summary": "JWT bearer tokens, no refresh rotation observed",
          }
      )
      assert saved.ok
      got = tool.run({"action": "get", "target": "api.example.com"})
      assert got.ok
      assert "JWT bearer tokens" in got.observation

  def test_get_baseline_for_an_unknown_target_says_so_without_error() -> None:
      graph = ReachabilityGraph()
      tool = build_baseline_tool(graph, "agent-1")
      result = tool.run({"action": "get", "target": "nothing-here.example.com"})
      assert result.ok
      assert "no baseline" in result.observation

  def test_save_twice_for_the_same_identity_is_rejected() -> None:
      graph = ReachabilityGraph()
      tool = build_baseline_tool(graph, "agent-1")
      tool.run({"action": "save", "target": "api.example.com", "category": "c", "summary": "s"})
      result = tool.run({"action": "save", "target": "api.example.com", "category": "c2", "summary": "s2"})
      assert not result.ok
      assert "already exists" in result.observation

  def test_amend_appends_without_overwriting_the_original_summary() -> None:
      graph = ReachabilityGraph()
      tool = build_baseline_tool(graph, "agent-1")
      tool.run({"action": "save", "target": "api.example.com", "category": "c", "summary": "original"})
      amended = tool.run({"action": "amend", "target": "api.example.com", "text": "also found X"})
      assert amended.ok
      got = tool.run({"action": "get", "target": "api.example.com"})
      assert "original" in got.observation
      assert "also found X" in got.observation

  def test_amend_before_any_save_is_rejected() -> None:
      graph = ReachabilityGraph()
      tool = build_baseline_tool(graph, "agent-1")
      result = tool.run({"action": "amend", "target": "api.example.com", "text": "x"})
      assert not result.ok

  def test_https_and_bare_host_resolve_to_the_same_identity() -> None:
      graph = ReachabilityGraph()
      tool = build_baseline_tool(graph, "agent-1")
      tool.run({"action": "save", "target": "https://api.example.com/", "category": "c", "summary": "s"})
      assert len(graph.nodes_of_kind(NodeKind.BASELINE)) == 1
      got = tool.run({"action": "get", "target": "api.example.com:443"})
      assert "s" in got.observation
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```
  uv run pytest tests/lalo/test_graph_baseline.py -v
  ```

  Expected: FAIL — `lalo.graph.baseline` doesn't exist yet.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/graph/model.py`, add to `NodeKind` (alongside `COVERAGE_LEDGER` from
  Task 5):

  ```python
      # A shared, append-only artifact per normalized target identity - see
      # graph/baseline.py. Never overwritten wholesale after its initial
      # save; only ever amended, so a concurrent amendment from a different
      # agent can never lose another's.
      BASELINE = "baseline"
  ```

  Create `src/lalo/graph/baseline.py`:

  ```python
  """The ``baseline`` tool - a shared, append-only threat-model/inventory
  artifact per normalized target identity, readable and appendable by every
  agent in the hierarchy via the same shared graph every other tool already
  reads and writes.
  """

  from __future__ import annotations

  from urllib.parse import urlsplit

  from ..agent.tools import FunctionTool, ToolResult, str_arg
  from ..core.redaction import redact
  from .model import NodeKind, ReachabilityGraph

  _DEFAULT_PORTS = {"http": 80, "https": 443}


  def normalize_target_identity(target: str) -> str:
      """``https://api.example.com:443/path`` and ``api.example.com`` both
      resolve to ``api.example.com`` - host plus a NON-default port only,
      lowercased, scheme and path dropped. A bare host with no scheme
      (``urlsplit`` needs ``//`` to parse a netloc) is handled by prefixing
      one before parsing."""
      candidate = target if "//" in target else f"//{target}"
      parts = urlsplit(candidate)
      host = (parts.hostname or target).lower()
      scheme = (parts.scheme or "https").lower()
      port = parts.port
      if port is not None and _DEFAULT_PORTS.get(scheme) == port:
          port = None
      return f"{host}:{port}" if port else host


  def build_baseline_tool(graph: ReachabilityGraph, agent_id: str) -> FunctionTool:
      def _node_id(target: str) -> tuple[str, str]:
          identity = normalize_target_identity(target)
          return f"baseline-{identity}", identity

      def _baseline(args: dict[str, object]) -> ToolResult:
          action = str_arg(args, "action", "").strip()
          target = str_arg(args, "target", "").strip()
          if not target:
              return ToolResult(observation="error: 'target' is required", ok=False)
          node_id, identity = _node_id(target)

          if action == "save":
              category = str_arg(args, "category", "").strip()
              summary = str_arg(args, "summary", "").strip()
              if not category or not summary:
                  return ToolResult(
                      observation="error: 'category' and 'summary' are required for action=save",
                      ok=False,
                  )
              if graph.has_node(node_id):
                  return ToolResult(
                      observation=f"error: a baseline already exists for {identity!r} - "
                      "use action=amend to add to it, never action=save to overwrite",
                      ok=False,
                  )
              graph.add_node(
                  node_id,
                  NodeKind.BASELINE,
                  identity=identity,
                  category=category,
                  summary=redact(summary),
                  amendments=[],
              )
              return ToolResult(observation=f"saved baseline for {identity}")

          if action == "get":
              if not graph.has_node(node_id):
                  return ToolResult(observation=f"no baseline recorded for {identity}")
              node = graph.node(node_id)
              lines = [f"category: {node.get('category')}", f"summary: {node.get('summary')}"]
              for amendment in node.get("amendments", []):
                  lines.append(f"- amendment by {amendment.get('agent_id', 'unknown')}: {amendment.get('text')}")
              return ToolResult(observation="\n".join(lines))

          if action == "amend":
              text = str_arg(args, "text", "").strip()
              if not text:
                  return ToolResult(observation="error: 'text' is required for action=amend", ok=False)
              if not graph.has_node(node_id):
                  return ToolResult(
                      observation=f"error: no baseline exists yet for {identity!r} - "
                      "use action=save to create the initial one first",
                      ok=False,
                  )
              node = graph.node(node_id)
              amendments = [*node.get("amendments", []), {"text": redact(text), "agent_id": agent_id}]
              graph.add_node(node_id, NodeKind.BASELINE, amendments=amendments)
              return ToolResult(
                  observation=f"amended baseline for {identity} ({len(amendments)} amendment(s) total)"
              )

          return ToolResult(observation=f"error: unknown action {action!r} - use save|get|amend", ok=False)

      return FunctionTool(
          name="baseline",
          description=(
              "A shared, append-only threat-model/inventory note per target - every agent "
              "in the hierarchy reads and adds to the SAME entry for the same target "
              "identity (host[:non-default-port], scheme/path/default-port ignored). "
              'args: {"action": "save"|"get"|"amend", "target": str, ...}. save (once per '
              'target - use amend after): {"category": str, "summary": str}. get: {}. '
              'amend (adds to an existing baseline, never overwrites it): {"text": str}.'
          ),
          func=_baseline,
      )
  ```

  In `src/lalo/scan.py`, build the tool once per scan (it needs `agent_id`, so it is
  actually built PER-AGENT, alongside `build_record_finding_tool(agent_graph)` inside
  `_build_registry`, using that function's own `self_id` parameter):

  ```python
      tools: list[Tool] = [
          ...
          build_baseline_tool(agent_graph, self_id),
          ...
      ]
  ```

  Add `from .graph.baseline import build_baseline_tool` to the imports.

- [ ] **Step 4: Run tests to verify they pass**

  ```
  uv run pytest tests/lalo/test_graph_baseline.py -v
  ```

  Expected: all PASS.

- [ ] **Step 5: Run the full scan suite to confirm no regression**

  ```
  uv run pytest tests/lalo/test_graph_baseline.py tests/lalo/test_scan.py -v
  ```

  Expected: all PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/graph/baseline.py src/lalo/graph/model.py src/lalo/scan.py tests/lalo/test_graph_baseline.py
  git commit -m "feat(graph): add a shared, identity-normalized baseline artifact tool

A threat-model/inventory note per target, shared by every agent in the
hierarchy through the same already-checkpointed graph every other tool
reads and writes - save requires a real category+summary, amend is
append-only and attributed so a concurrent edit from another agent can
never overwrite what a sibling already recorded."
  ```

---

### Task 9: `fix-verification-discipline.md` methodology skill

**Files:**
- Create: `src/lalo/skills/content/methodology/fix-verification-discipline.md`
- Test: none new — covered by the existing structural tests in
  `tests/lalo/test_skills_loader.py` (`test_every_built_in_skill_loads_without_error`
  already globs every file under `skills/content/`, so a new one is picked up with no
  test-file change).

**Interfaces:**
- Consumes: `Finding.code_locations`/`fix_verified`/`fix_verification_notes` (Task 1).
- Produces: a `recall`-able skill named `fix-verification-discipline`.

**Context:** No existing L4L0 skill teaches HOW to re-test a previously-reported
finding against a claimed remediation — `closure-discipline.md` governs closing a
*new* candidate, not re-verifying an *old* one. This is genuinely different work: the
starting point is a known-vulnerable state and a claimed fix, not an unknown surface.

- [ ] **Step 1: Write the file**

  ```markdown
  ---
  name: fix-verification-discipline
  category: methodology
  description: How to re-test a previously reported finding against a claimed fix — ordered verification gates, and when to say the gap is still open rather than confirm a fix that wasn't actually tested
  keywords: [fix verification, regression test, remediation, patch verification, re-test]
  ---

  # Fix Verification Discipline

  Verifying a fix is a different task from finding a vulnerability, with a
  different failure mode: the temptation here is to accept "looks fixed"
  (the obvious symptom is gone) instead of actually re-running the original
  proof. A fix that suppresses the symptom without closing the underlying
  gap is a false negative with a customer's name already on the release
  notes — treat every verification with the same "assume it isn't fixed by
  default" posture [[closure-discipline]] applies to a brand-new candidate.

  ## When This Applies

  You are given (or you discover) a previously filed finding — your own or
  another agent's — plus a claim that it has been remediated: a deployed
  patch, a config change, a library upgrade. Your job is to determine
  whether the vulnerability the ORIGINAL finding described is actually
  closed, using the original evidence as your baseline.

  ## Verification Gates, in Order

  Work through these in order; stop and report `not verified` at the first
  gate that fails rather than skipping ahead to a later one.

  1. **Re-read the original finding in full** — its `evidence_excerpt`,
     `evidence`, `target`, and `param`. You cannot verify a fix for a bug
     you have not re-read the exact original proof of; a summary or your
     own memory of "a SQLi somewhere in that endpoint" is not enough
     precision to re-test correctly.
  2. **Reproduce the ORIGINAL proof exactly first, against the current
     target.** Fire the exact same request (same method, same payload, same
     parameter) the original evidence captured. If it still succeeds, the
     fix does not hold — stop here, do not proceed to variant testing, and
     record `fix_verified: false` with the reproduction as your evidence.
  3. **If the original proof no longer succeeds, test at least two
     plausible bypass variants before calling it fixed** — the specific
     variants depend on the vuln class ([[closure-discipline]]'s own
     per-class validation traps are the starting list): a different
     encoding of the same payload, a different parameter carrying the same
     tainted data, a second HTTP method, a case variation on a
     denylist-style fix. A fix that blocks the literal original payload but
     not an equivalent one is not a real fix, and this is the single most
     common way a "verified" fix later turns out not to be.
  4. **Read the actual code change if you have source access**
     ([[source-aware-review]] applies here directly) — confirm the fix is a
     real control at the point of use (parameterization, output encoding,
     an allowlist check), not a cosmetic change nearby (a renamed variable,
     an added comment, a check on a sibling code path that does not run on
     the vulnerable one). Record the specific before/after location as a
     `code_locations` entry on the finding.
  5. **Confirm no adjacent regression.** A fix narrowly scoped to the exact
     original payload sometimes breaks a legitimate related code path or
     opens a new one (an added allowlist that now over-matches, an added
     try/except that swallows a DIFFERENT error class than intended) — a
     quick check of one adjacent legitimate use case is enough; this is not
     a full re-scan of the surrounding feature.

  ## The Escape Hatch

  If you cannot complete gate 2 or 3 with genuine confidence — the original
  reproduction environment is unavailable, you lack the credentials the
  original finding used, or a bypass variant is plausible but you ran out
  of time to test it — say so explicitly. Do not set `fix_verified: true`
  on a guess. Use `record_finding`'s own `fix_verification_notes` field (or
  `coverage_ledger` with outcome `needs-follow-up`) to name the specific gap
  in your verification, the same honesty [[closure-discipline]]'s own
  `open_proof_gap` state requires for a new finding.

  ## Filing the Result

  A fix-verification result is not a new finding type — it is an update to
  the EXISTING finding. Call `record_finding` again with the same
  `vuln_class`/`target`/`param` (the existing dedup path merges it into the
  original node) and set `fix_verified`/`fix_verification_notes`/
  `code_locations` on that same call. Never delete or silently supersede the
  original finding — a fix that turns out not to hold on a later re-check
  needs the original evidence intact to make sense of what changed.

  ## Summary

  Reproduce the original proof first, exactly, before trying anything else —
  if it still works, you are done and the fix does not hold. If it doesn't,
  test real bypass variants before calling it closed, and read the actual
  code change when you can. Say so honestly, via `fix_verification_notes` or
  a `needs-follow-up` coverage entry, whenever you cannot complete a gate
  with real confidence — a confirmed fix you didn't actually verify is worse
  than an honestly incomplete one.
  ```

- [ ] **Step 2: Verify it loads and is recallable**

  ```
  uv run pytest tests/lalo/test_skills_loader.py -v
  ```

  Expected: all PASS (the new file is picked up automatically by the existing glob-
  based loader test).

  Then, as a manual recall check (not a new automated test — this project's own
  existing convention for a skill-content-only task per Plan 1/prior rounds' skill
  tasks):

  ```
  uv run python -c "
  from lalo.skills.loader import load_skills
  from lalo.skills.recall import recall
  skills = load_skills()
  results = recall('how do I verify a fix actually works', skills)
  assert results and results[0].skill.name == 'fix-verification-discipline', results
  print('OK:', results[0].skill.name)
  "
  ```

  Expected: prints `OK: fix-verification-discipline`.

- [ ] **Step 3: Commit**

  ```bash
  git add src/lalo/skills/content/methodology/fix-verification-discipline.md
  git commit -m "docs(skills): add fix-verification-discipline methodology skill

No existing skill taught how to re-test a previously reported finding
against a claimed fix - closure-discipline governs closing a NEW candidate,
this is the distinct discipline of re-verifying an old one: reproduce the
original proof first, test real bypass variants before calling it closed,
and say so honestly via fix_verification_notes when a gate can't be
completed with genuine confidence."
  ```

---

### Task 10: `dependency-cve-analysis.md` skill + optional `dependency_analyst` spawn role

**Files:**
- Create: `src/lalo/skills/content/methodology/dependency-cve-analysis.md`
- Modify: `src/lalo/scan.py:458-469` (`_SOURCE_REVIEWER_TOOL_NAMES`, `_ROLE_TOOL_NAMES`)
- Modify: `src/lalo/agent/spawn.py` (`spawn_agent`'s tool description role list)
- Test: `tests/lalo/test_scan.py` (append one role-wiring test)

**Interfaces:**
- Consumes: `Finding.package_name`/`reachability`/`contextual_cvss` etc. (Task 1).
- Produces: a `recall`-able skill; `_ROLE_TOOL_NAMES` gains a `"dependency_analyst"`
  entry.

**Context:** Dependency/SCA scanning is a genuinely distinct specialty (manifest
discovery, a best-in-class scanner run through the existing free shell, then a
reachability-before-severity read) worth an optional spawn role the same way
`source_reviewer` already is — never mandatory, never a replacement for the default
`"full"` role, exactly matching this project's own existing role-confinement pattern.
No new tool is needed: manifest discovery and running a scanner both go through the
already-available `run_command` (the free shell), and filing the result goes through
`record_finding`'s now-extended dependency fields (Task 1).

- [ ] **Step 1: Write the skill file**

  ```markdown
  ---
  name: dependency-cve-analysis
  category: methodology
  description: Manifest discovery, running a best-in-class SCA scanner via the free shell, and reachability-before-severity triage for dependency/SCA findings
  keywords: [dependency, sca, cve, sbom, supply chain, npm audit, pip-audit, cargo audit, vulnerable dependency]
  ---

  # Dependency / CVE Analysis

  A scanner reporting "CVE-2023-XXXX affects your installed lodash" is a
  LEAD, not a finding — the vast majority of a raw SCA report's line items
  describe a vulnerable code path the target never actually calls. Filing
  every scanner hit as a finding at the advisory's own severity produces a
  report nobody trusts. This skill governs the discipline that turns a raw
  scanner report into a small number of real, reachability-confirmed
  findings.

  ## Manifest Discovery

  Use the free shell (`run_command`) to find every dependency manifest in
  the workspace or a cloned/mounted source tree — `package.json`/
  `package-lock.json`, `requirements.txt`/`poetry.lock`/`Pipfile.lock`,
  `Cargo.lock`, `go.sum`, `pom.xml`/`build.gradle`, a container image's own
  installed-package list (`dpkg -l`/`apk info` inside a fetched image, or
  from an SBOM if one is already published). A target with no manifest
  reachable at all (black-box, no source access) means this whole class is
  `not-applicable` — record that honestly via `coverage_ledger` rather than
  skipping it silently.

  ## Running a Scanner

  Pick the best-in-class scanner for the ecosystem found, and run it via
  `run_command` — the free shell can install anything it needs. Prefer a
  scanner that reports a specific advisory id and installed-vs-fixed
  version, not one that only reports a bare package name:
  `npm audit --json` / `pnpm audit` for Node, `pip-audit` for Python,
  `cargo audit` for Rust, `govulncheck` for Go, `grype`/`trivy` for a
  container image or SBOM (both handle multiple ecosystems from one scan
  and are a reasonable default when the target spans more than one).

  ## Reachability Before Severity

  A raw advisory's own CVSS score describes the vulnerability in the
  abstract — it says nothing about whether THIS deployment ever calls the
  vulnerable code path. Before filing anything:

  1. **Confirm the package is actually imported/loaded**, not merely listed
     in a lockfile as a transitive dependency of something else that never
     runs (a dev-only tool, an unused optional feature). Grep the actual
     application source/entry points for the import.
  2. **Confirm the specific vulnerable function/code path is actually
     called**, not just that the package is imported for an unrelated
     feature. This is the difference between `reachability: "likely"` (the
     package is loaded and the general area of code runs, but you have not
     traced the exact call) and `reachability: "confirmed"` (you traced a
     real call path from an entry point to the vulnerable function, or
     triggered it directly and observed the vulnerable behavior).
  3. **When you cannot determine reachability at all** (black-box, no
     source access, and the vulnerable behavior is not independently
     triggerable) — use `reachability: "unknown"` and say so; this is an
     honest, legitimate outcome per [[closure-discipline]], never a reason
     to inflate to "likely" out of scanner-report pressure.

  ## Filing the Result

  File via `record_finding` with `vuln_class: "dependency-vulnerability"`
  and the dependency fields set: `package_name`, `installed_version`,
  `ecosystem`, `manifest_path`, `reachability` (with
  `reachability_evidence` stating exactly what you traced, required unless
  `reachability` is `"unknown"`), and `contextual_cvss` — your own assessed
  score for THIS deployment's actual exposure, which can legitimately be
  lower than the advisory's own base score when reachability is partial, or
  should stay equal to it when you confirmed full reachability with no
  mitigating factor. `evidence`/`evidence_excerpt` should be the actual
  scanner output line plus whatever call-path trace you performed, not a
  restatement of the public advisory text.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]] before recording anything. Class-specific
  traps:

  - A vulnerable transitive dependency that is never actually loaded at
    runtime (a build-only tool, a test-only dependency) is not a finding —
    confirm it is a genuine runtime dependency of the deployed artifact.
  - A scanner reporting "fixed in version X" when the installed version is
    ALREADY past X due to a backport (a distro-maintained package with its
    own patched version numbering scheme that doesn't match upstream) is a
    false positive from the scanner itself — check the actual patched
    behavior, not just the version-number comparison, when the ecosystem is
    known to backport (common for OS-packaged software).
  - Severity inherited unmodified from the advisory, with no reachability
    assessment at all, is the single most common quality problem in a raw
    SCA report — never file `contextual_cvss` as a blind copy of the
    advisory score without doing the reachability work above first.

  ## Summary

  Discover manifests, run the right scanner for the ecosystem, then do the
  reachability work before filing anything — an unreachable vulnerable
  dependency is a real fact worth noting (via `coverage_ledger`, outcome
  `actively-ruled-out`, if you specifically confirmed it is not reachable)
  but not a finding, and a finding filed with no reachability evidence at
  all should say `reachability: "unknown"` rather than guess.
  ```

- [ ] **Step 2: Wire the optional `dependency_analyst` role**

  In `src/lalo/scan.py`, modify `_ROLE_TOOL_NAMES` (currently lines 458-469):

  ```python
  _SOURCE_REVIEWER_TOOL_NAMES = frozenset(
      {"run_command", "record_finding", "recall", "query_graph", "note"}
  )

  # Confined identically to source_reviewer (pure reasoning over already-
  # accessible content, no live-firing tools) plus coverage_ledger - a
  # dependency/SCA specialist's whole job (manifest discovery, running a
  # scanner via the free shell, reachability tracing) needs no network-
  # firing tool at all.
  _DEPENDENCY_ANALYST_TOOL_NAMES = frozenset(
      {"run_command", "record_finding", "recall", "query_graph", "note", "coverage_ledger"}
  )

  _ROLE_TOOL_NAMES: dict[str, frozenset[str] | None] = {
      "full": None,
      "source_reviewer": _SOURCE_REVIEWER_TOOL_NAMES,
      "dependency_analyst": _DEPENDENCY_ANALYST_TOOL_NAMES,
  }
  ```

  (This task must run AFTER Task 5, since `_DEPENDENCY_ANALYST_TOOL_NAMES` names
  `coverage_ledger` — if Task 5 has not landed yet in an out-of-order execution, drop
  `"coverage_ledger"` from this frozenset for now and note it as a follow-up; the
  intended final state includes it.)

  In `src/lalo/agent/spawn.py`, `spawn_agent`'s tool description currently states
  `"role": "full"|"source_reviewer"` — update every occurrence of that literal
  string in the file (there are two: `spawn_agent`'s description and
  `spawn_agents`' description) to `"full"|"source_reviewer"|"dependency_analyst"`.

- [ ] **Step 3: Write the role-wiring regression test**

  Add to `tests/lalo/test_scan.py` (the file already has a test asserting
  `_ROLE_TOOL_NAMES["source_reviewer"]`'s exact tool set — mirror it):

  ```python
  def test_dependency_analyst_role_has_no_live_firing_tools() -> None:
      from lalo.scan import _ROLE_TOOL_NAMES

      tools = _ROLE_TOOL_NAMES["dependency_analyst"]
      assert tools is not None
      assert "http" not in tools
      assert "run_command" in tools
      assert "record_finding" in tools
  ```

- [ ] **Step 4: Run tests to verify they pass**

  ```
  uv run pytest tests/lalo/test_scan.py -k dependency_analyst -v
  uv run pytest tests/lalo/test_skills_loader.py -v
  ```

  Expected: all PASS.

- [ ] **Step 5: Run the full scan suite to confirm no regression**

  ```
  uv run pytest tests/lalo/test_scan.py -v
  ```

  Expected: all PASS — the existing self-check inside `_build_registry` (the
  `actual_tools != set(expected_tools)` `AssertionError` guard, read live this
  session) fires only for a role actually IN `_ROLE_TOOL_NAMES` being dispatched with
  a mismatched tool set; adding a third role entry doesn't affect the existing two.

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/skills/content/methodology/dependency-cve-analysis.md src/lalo/scan.py src/lalo/agent/spawn.py tests/lalo/test_scan.py
  git commit -m "feat(scan): add a dependency-cve-analysis skill + optional dependency_analyst role

Manifest discovery, running a best-in-class SCA scanner via the free shell,
and reachability-before-severity triage - confined to the same no-live-
firing tool set as source_reviewer, since this specialty's whole job is
reading already-accessible content and running local tooling. Optional,
never mandatory, alongside the existing full/source_reviewer roles."
  ```

---

### Task 11: `argument-injection.md` skill

**Files:**
- Create: `src/lalo/skills/content/vulnerabilities/argument-injection.md`
- Modify: `src/lalo/skills/content/vulnerabilities/command-injection.md` (one
  cross-reference line)
- Test: none new — covered by the existing loader/structural tests.

**Interfaces:** none — content only.

**Context:** `command-injection.md`'s own description already names "shell
metacharacter and argument injection" together, but its body only covers the
shell-metacharacter case. Argument injection is a distinct technique that works even
when an application correctly avoids a shell entirely (an `argv` array passed
directly to `execve`, no shell metacharacter interpretation possible at all) by
injecting an additional command-line FLAG the target program itself interprets.

- [ ] **Step 1: Write the skill file**

  ```markdown
  ---
  name: argument-injection
  category: vulnerability
  description: Command-line argument/flag injection into an execve-style argv array — a distinct technique from shell metacharacter injection, exploitable even with no shell involved at all
  keywords: [argument injection, flag injection, argv injection, cli injection, wildcard injection]
  ---

  # Argument Injection

  Argument injection targets applications that (correctly) avoid a shell
  entirely — user input goes straight into an `argv` array passed to
  `execve`/`subprocess.run([...])` with no shell metacharacter interpretation
  possible. The gap here is different: if user input becomes one or more
  WHOLE ARGUMENTS (not just a value inside one), an attacker can inject an
  additional flag the target program itself interprets, regardless of shell
  involvement. This is [[command-injection]]'s sibling class, not a subset
  of it — a target hardened against shell metacharacters is often still
  wide open to this.

  ## Attack Surface

  - Any feature that builds an `argv` list where user input controls a
    whole positional argument or is concatenated in a way that can produce
    one (a filename the user names, a URL, a search term passed unquoted
    into an array position).
  - Wrappers around `git`, `ssh`/`scp`, `curl`/`wget`, `tar`, `zip`/`unzip`,
    `rsync`, `ffmpeg`, and any CLI tool with a `-oOption=value`-style or
    long-flag configuration surface.
  - A filename/path an attacker controls that is passed to a tool
    supporting a leading-hyphen-as-flag convention — `find`, `rm`, `chmod`,
    `tar` all treat a filename beginning with `-` as an option, not a name.

  ## Recon

  - Identify the EXACT invocation shape: is user input placed as one
    complete array element, or interpolated inside a larger fixed string
    that becomes one element? Only the former is directly exploitable this
    way; the latter needs a value that, once split by the program's own
    argument parser (rare, but check), still produces a separate flag.
  - Check whether the wrapped tool documents a dangerous flag reachable
    this way before testing blind: `git`'s `--upload-pack=`/`-c
    core.sshCommand=` (arbitrary command execution via a crafted remote
    URL/branch name), `ssh`/`scp`'s `-oProxyCommand=` (arbitrary command
    execution via a crafted hostname), `curl`'s `-o`/`--output` (arbitrary
    file write via a crafted URL argument position), `tar`'s
    `--checkpoint=1 --checkpoint-action=exec=` (arbitrary command execution
    via a crafted archive member name), `wget`'s `--post-file=`.

  ## Techniques

  1. **Leading-hyphen probe.** Supply a value beginning with `-` or `--` in
     the position user input reaches and observe whether the tool's own
     help/error output or behavior changes — confirms the value reaches an
     argument-parsing position, not just a string used as data.
  2. **`--` end-of-options bypass check (defense probe).** If the wrapper
     already prepends a literal `--` before user-controlled arguments (the
     standard, correct defense), confirm it is actually effective: some
     tools interpret a SECOND `--` as data rather than a repeated
     terminator, and a few tools (rare, but check the specific one in play)
     don't honor `--` for every subcommand consistently.
  3. **Known-dangerous-flag injection.** Once the leading-hyphen probe
     confirms argument-position control, attempt the specific dangerous
     flag identified in Recon for that exact tool — e.g. for a Git
     URL/branch field reaching `git clone <value>`, attempt a value like
     `--upload-pack=touch /tmp/proof;` (adjust to the wrapper's actual
     invocation shape) and confirm via a benign, observable side effect on
     the target (a file created, an OAST callback), never a destructive
     command.
  4. **Multi-argument injection via embedded delimiter.** If the value is
     split on whitespace or another delimiter before reaching `argv`
     (confirm this from the invocation code, not assumed), a single input
     value can inject MULTIPLE argv elements — worth testing when the
     single-flag technique alone doesn't reach a dangerous flag but a
     flag-plus-its-value pair would.

  ## Proof Ladder

  - **L1 — argument-position control identified.** User input reaches a
    position that becomes one full argv element, confirmed via a
    leading-hyphen probe changing observable behavior, but no specific
    dangerous flag has been tried yet.
  - **L2 — a non-dangerous flag injection confirmed.** A harmless flag
    (e.g. `--version`, `--help`) injected via user input visibly changes
    the program's behavior, confirming argument injection works in
    principle for this specific wrapper.
  - **L3 — a dangerous flag's effect demonstrated via a benign side
    effect.** A flag with real consequence (file write/read, command
    execution, credential/config exfiltration) is triggered and its effect
    is directly observed (a file created at an attacker-chosen path, an
    OAST callback, a benign command's output captured) — reportable.
  - **L4 — chained to full RCE or a durable compromise.** The injected flag
    itself achieves command execution (e.g. `git`'s `-c
    core.sshCommand=`/`tar`'s checkpoint-action) with a real, benign proof
    command run and its output captured.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]] before recording anything.

  - A leading `-`/`--` in user input being REJECTED outright (a validation
    error, not a behavior change) is the control working correctly — not a
    finding, and worth a `record_safe` if you specifically confirmed the
    rejection is unconditional across every reachable invocation, not just
    the one you happened to test.
  - The wrapper prepending a real, effective `--` terminator before every
    user-controlled argument closes this class for that specific
    invocation — confirm it is present in the ACTUAL invocation code
    (source-aware review) rather than assumed from the tool's general
    documentation, since a wrapper can add `--` in one call site and miss
    it in a sibling one.
  - A behavior change from the leading-hyphen probe alone (L1) is not
    itself a finding — many tools simply print "unknown option" and exit
    cleanly, which is the safe, expected behavior for a hardened wrapper;
    only a confirmed dangerous-flag EFFECT (L3+) is reportable.

  ## Impact

  Arbitrary command execution (via a tool's own command-invocation flags:
  `ssh -oProxyCommand`, `tar --checkpoint-action`, `git -c
  core.sshCommand`), arbitrary file read/write (via `-o`/`--output`-style
  flags), and credential/config exfiltration (via a flag that dumps
  internal state or reads an attacker-chosen config file) — often reaching
  full RCE with no shell metacharacter ever needed, on a target explicitly
  hardened against [[command-injection]]'s own shell-based variant.

  ## Summary

  Confirm the invocation shape places user input as a whole argv element
  first, then probe with a leading hyphen before trying anything dangerous.
  A wrapper hardened against shell metacharacters can still be wide open to
  this — never assume the shell-injection control also covers it without
  checking the argument-parsing boundary specifically.
  ```

- [ ] **Step 2: Add the cross-reference in `command-injection.md`**

  Read the live file's `## Summary` section (or equivalent closing section) and add
  one sentence naming `[[argument-injection]]` as the sibling class for a shell-free
  invocation — e.g., appended to the end of its final paragraph:
  `"A target that avoids a shell entirely is not automatically safe from this
  family — see [[argument-injection]] for the sibling technique that works purely
  through argv-level flag injection, no shell metacharacter required."` Insert this
  as an additive sentence; do not remove or restructure any existing text in the
  file.

- [ ] **Step 3: Verify both files load and the new skill is recallable**

  ```
  uv run pytest tests/lalo/test_skills_loader.py -v
  ```

  Expected: all PASS.

  ```
  uv run python -c "
  from lalo.skills.loader import load_skills
  from lalo.skills.recall import recall
  skills = load_skills()
  results = recall('argument injection flag', skills)
  assert results and results[0].skill.name == 'argument-injection', results
  print('OK:', results[0].skill.name)
  "
  ```

  Expected: prints `OK: argument-injection`.

- [ ] **Step 4: Commit**

  ```bash
  git add src/lalo/skills/content/vulnerabilities/argument-injection.md src/lalo/skills/content/vulnerabilities/command-injection.md
  git commit -m "docs(skills): add argument-injection as command-injection's sibling class

A target hardened against shell metacharacters (no shell involved at all,
argv passed directly to execve) can still be wide open to argument/flag
injection - a distinct technique with its own proof ladder, cross-referenced
from command-injection.md rather than folded into it."
  ```

---

### Task 12: Cloud-provider-specific skills — AWS, Azure, GCP

**Files:**
- Create: `src/lalo/skills/content/vulnerabilities/aws-security.md`
- Create: `src/lalo/skills/content/vulnerabilities/azure-security.md`
- Create: `src/lalo/skills/content/vulnerabilities/gcp-security.md`
- Test: none new — existing loader/structural tests cover all three automatically.

**Interfaces:** none — content only. Each cross-references the existing generic
`[[cloud-iam-privilege-escalation]]`/`[[cloud-iam-storage-misconfiguration]]` skills
rather than restating their content.

- [ ] **Step 1: Write `aws-security.md`**

  ```markdown
  ---
  name: aws-security
  category: vulnerability
  description: AWS-specific attack surface — IMDS credential theft, S3/Lambda/IAM specifics beyond the generic cloud-IAM skills, and a per-class proof ladder
  keywords: [aws, s3, iam, lambda, ec2, imds, sts, cloudtrail, kms]
  ---

  # AWS-Specific Security

  This skill covers AWS-specific mechanisms and gotchas; the generic
  cross-provider privilege-escalation and storage-misconfiguration
  methodology lives in [[cloud-iam-privilege-escalation]] and
  [[cloud-iam-storage-misconfiguration]] — apply both together rather than
  duplicating that reasoning here.

  ## Attack Surface

  - EC2/ECS/Lambda instance metadata (IMDS) reachable via an SSRF primitive
    on any service running in the account.
  - S3 bucket policies, ACLs, and pre-signed URLs; overly broad
    `sts:AssumeRole` trust policies; Lambda execution-role over-privilege;
    Cognito identity-pool unauthenticated-role grants.
  - CloudTrail/GuardDuty logging gaps that would hide exploitation.

  ## Recon

  - From any SSRF foothold, probe `http://169.254.169.254/latest/meta-data/`
    (IMDSv1) and confirm whether IMDSv2's session-token requirement (a
    `PUT` for a token before any `GET`) is actually enforced — IMDSv1 being
    reachable at all from an SSRF primitive is itself a real, reportable
    finding on modern AWS given IMDSv2 has been the recommended default for
    years.
  - Enumerate the current role's effective permissions via `aws sts
    get-caller-identity` then `aws iam simulate-principal-policy` (or, more
    reliably against opaque policies, direct trial calls) rather than
    trusting the account's own IAM policy documents at face value — an
    explicit `Deny` elsewhere, or an SCP at the organization level, can
    silently narrow what a policy document alone suggests is allowed.
  - Check S3 bucket policy AND the separate "Block Public Access" account/
    bucket-level settings independently — a bucket policy allowing public
    read is still blocked if Block Public Access is on, and vice versa a
    restrictive-looking policy can be overridden by a permissive ACL if
    Block Public Access is off.

  ## Techniques

  1. **IMDS credential theft via SSRF**, per Recon above — once temporary
     credentials are retrieved from `iam/security-credentials/<role>`,
     confirm their actual scope via `sts get-caller-identity` and a handful
     of read-only trial calls before assuming account-wide access.
  2. **Lambda execution-role over-privilege.** A function with an
     overly-broad execution role (common: `s3:*` on `*` instead of the
     specific bucket the function needs) reachable via any code-execution
     primitive in that function (a deserialization bug, an injected
     environment-variable read) inherits that role's full scope.
  3. **S3 pre-signed URL scope check.** Confirm a pre-signed URL is scoped
     to the specific object/method/expiry it claims — a URL generated with
     an overly broad prefix or excessive expiry is a durable-access finding
     distinct from the bucket policy itself.
  4. **Cross-account trust-policy overreach.** A role's trust policy
     granting `sts:AssumeRole` to `"*"` or an overly broad external
     account/condition is a durable privilege-escalation path — confirm by
     attempting the assume-role from outside the expected trusted
     principal.

  ## Proof Ladder

  Follow [[cloud-iam-privilege-escalation]]'s own proof ladder — this skill
  supplies AWS-specific techniques to reach each of its stated levels, not
  a separate ladder.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]]. IMDSv2 enforcement (a required session
  token) confirmed present is the control working correctly, not a finding
  — confirm this explicitly with a token-less `GET` attempt rather than
  assuming from account-level configuration alone, since enforcement can be
  set per-instance. A `Deny` further up the SCP hierarchy that blocks an
  otherwise-broad-looking IAM policy from ever taking effect is a real
  control — verify with an actual trial call before reporting the policy
  document's stated permissions as exploitable.

  ## Impact

  Full account compromise via a role with excessive trust or execution
  permissions; data exposure via a misconfigured S3 bucket or an
  over-scoped pre-signed URL; lateral movement across AWS accounts via an
  overly broad cross-account trust policy.

  ## Summary

  IMDS credential theft from any SSRF foothold is the single most common
  and most impactful AWS-specific path — always check IMDSv2 enforcement
  explicitly. Beyond that, this skill supplies AWS-specific mechanisms;
  [[cloud-iam-privilege-escalation]] supplies the general escalation
  methodology they feed into.
  ```

- [ ] **Step 2: Write `azure-security.md`**

  ```markdown
  ---
  name: azure-security
  category: vulnerability
  description: Azure-specific attack surface — IMDS/managed-identity token theft, Storage/Key Vault/Entra ID specifics beyond the generic cloud-IAM skills, and a per-class proof ladder
  keywords: [azure, entra id, azure ad, managed identity, key vault, blob storage, arm]
  ---

  # Azure-Specific Security

  Azure-specific mechanisms and gotchas; apply alongside
  [[cloud-iam-privilege-escalation]] and
  [[cloud-iam-storage-misconfiguration]] for the general methodology.

  ## Attack Surface

  - Azure Instance Metadata Service (IMDS) and managed-identity token
    endpoints reachable via SSRF on any compute resource (VM, App Service,
    Function, Container Instance).
  - Storage account access keys vs. Shared Access Signatures (SAS) vs.
    Entra ID (Azure AD) RBAC — three independent access paths to the same
    blob/queue/table data, each with its own misconfiguration surface.
  - Entra ID app registrations with overly broad API permissions (especially
    an application-type Graph API permission granted admin consent, which
    acts account-wide rather than delegated to a signed-in user).
  - ARM/Bicep template outputs or deployment logs leaking a provisioning-
    time secret.

  ## Recon

  - From an SSRF foothold, probe
    `http://169.254.169.254/metadata/identity/oauth2/token` with the
    required `Metadata: true` header — confirm whether a managed identity
    is attached to the compromised resource at all (many are not) before
    assuming this path is live.
  - Enumerate a storage account's actual access paths independently: check
    for a still-enabled account key (older, broader-scoped, harder to
    rotate selectively), any long-lived or overly-permissive SAS token
    embedded in client-side code or a config file, and the RBAC role
    assignments on the account/container.
  - For Entra ID, distinguish delegated permissions (scoped to what the
    signed-in user could already do) from application permissions with
    admin consent (scoped to everything the permission allows, account-
    wide) — the latter on an app registration reachable via a compromised
    client secret or certificate is a full-tenant-scope finding.

  ## Techniques

  1. **Managed-identity token theft via SSRF**, per Recon — once a token is
     retrieved, confirm its actual resource/scope via a trial call (e.g. to
     Azure Resource Manager or Microsoft Graph) rather than assuming
     account-wide access from the token's mere presence.
  2. **Storage access-path downgrade check.** If Entra ID RBAC on a
     container looks properly scoped, still check whether a legacy account
     key or a broad SAS token provides an independent, more permissive path
     to the same data — a properly configured RBAC role does not close this
     class if either bypass path is still live.
  3. **App-registration admin-consent overreach.** Confirm an application
     permission with admin consent is actually necessary for the app's
     stated function — a Mail.ReadWrite or Directory.ReadWrite.All granted
     to an app that only needs to read a single calendar is a real,
     reportable overreach even before any exploitation.

  ## Proof Ladder

  Follow [[cloud-iam-privilege-escalation]]'s own proof ladder for
  escalation impact, and [[cloud-iam-storage-misconfiguration]]'s for a
  storage-access finding.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]]. A resource with NO managed identity
  attached means the IMDS token-theft path is simply not applicable there —
  confirm this explicitly (a 400/404 from the identity endpoint) rather
  than reporting IMDS reachability alone as a finding; IMDS being network-
  reachable is expected and not itself a vulnerability without a live
  identity behind it. Delegated (not application) Graph permissions scoped
  tightly to what the app's own UI actually exercises is the control
  working as designed.

  ## Impact

  Tenant-wide compromise via an over-consented app registration or a stolen
  managed-identity token with broad resource scope; data exposure via a
  legacy storage account key or an overly permissive SAS token bypassing
  otherwise-correct RBAC.

  ## Summary

  Always confirm a managed identity is actually attached before assuming
  IMDS token theft is live, and always check for a legacy-key or SAS-token
  bypass path independently of RBAC — a correctly scoped RBAC role does not
  close this class if either older path still works.
  ```

- [ ] **Step 3: Write `gcp-security.md`**

  ```markdown
  ---
  name: gcp-security
  category: vulnerability
  description: GCP-specific attack surface — metadata-service token theft, service-account/IAM binding specifics beyond the generic cloud-IAM skills, and a per-class proof ladder
  keywords: [gcp, google cloud, service account, iam, gcs, cloud functions, workload identity]
  ---

  # GCP-Specific Security

  GCP-specific mechanisms and gotchas; apply alongside
  [[cloud-iam-privilege-escalation]] and
  [[cloud-iam-storage-misconfiguration]] for the general methodology.

  ## Attack Surface

  - GCE/Cloud Run/Cloud Functions metadata service reachable via SSRF,
    exposing the attached service account's OAuth2 access token.
  - Overly broad IAM role bindings at the project/folder/organization level
    (especially a legacy Editor/Owner role, or a custom role that
    over-grants beyond a resource-specific predefined role).
  - GCS bucket IAM (uniform bucket-level access) vs. legacy ACLs — a bucket
    with uniform access enabled is governed entirely by IAM, but one
    without it can have a permissive object ACL independent of the bucket's
    own IAM policy.
  - Workload Identity Federation trust configurations allowing an external
    (non-Google) identity provider to impersonate a GCP service account.

  ## Recon

  - From an SSRF foothold, probe
    `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
    with the required `Metadata-Flavor: Google` header — confirm the
    attached service account's actual scope via
    `.../service-accounts/default/scopes` before assuming broad access.
  - Enumerate the effective IAM policy at every level (project, folder,
    organization) via `gcloud projects get-iam-policy` — a binding granted
    at a HIGHER level (folder/org) than the resource you're testing is easy
    to miss if you only check the resource's own policy.
  - For a GCS bucket, check whether uniform bucket-level access is enabled;
    if not, check for a legacy `allUsers`/`allAuthenticatedUsers` ACL grant
    independently of the bucket's IAM policy.

  ## Techniques

  1. **Metadata-service token theft via SSRF**, per Recon — confirm the
     token's actual scope via a trial call to the relevant API rather than
     assuming project-wide access from the token's mere presence.
  2. **Legacy Editor/Owner role check.** A service account or user still
     holding the legacy `roles/editor` or `roles/owner` (rather than a
     scoped predefined or custom role) is itself a reportable overreach
     given these broadly imply near-total project control — confirm via
     the IAM policy, then demonstrate concrete impact from that scope.
  3. **Workload Identity Federation trust overreach.** An overly broad
     `attribute-condition` (or none at all) on a workload identity pool
     provider lets ANY token from the trusted external IdP impersonate the
     bound service account, not just the intended workload — confirm the
     condition actually restricts to the expected subject/repository/
     environment.
  4. **GCS ACL bypass check.** With uniform bucket-level access disabled,
     confirm whether a legacy object or bucket ACL grants broader access
     than the bucket's own IAM policy suggests.

  ## Proof Ladder

  Follow [[cloud-iam-privilege-escalation]]'s own proof ladder for
  escalation impact, and [[cloud-iam-storage-misconfiguration]]'s for a
  storage-access finding.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]]. A metadata-service token whose scopes are
  narrowly restricted (e.g. only `logging.write`) is the control working
  correctly even though the endpoint itself is reachable — confirm the
  actual scope via the token, not just that the endpoint answered. Uniform
  bucket-level access being enabled closes the legacy-ACL bypass path
  entirely for that bucket — verify this setting explicitly before testing
  for an ACL bypass that cannot exist once it's on.

  ## Impact

  Project-wide compromise via a legacy Editor/Owner role or an
  over-permissioned service account token stolen via SSRF; external-identity
  impersonation of a GCP service account via an under-restricted Workload
  Identity Federation trust condition; data exposure via a legacy GCS ACL
  bypassing an otherwise-correct IAM policy.

  ## Summary

  Always confirm a stolen metadata-service token's actual scope before
  assuming project-wide access, and always check for a legacy Editor/Owner
  role or a legacy ACL bypass independently of an otherwise-correct-looking
  IAM policy or uniform-bucket-access setting.
  ```

- [ ] **Step 4: Verify all three load and are recallable**

  ```
  uv run pytest tests/lalo/test_skills_loader.py -v
  ```

  Expected: all PASS.

  ```
  uv run python -c "
  from lalo.skills.loader import load_skills
  from lalo.skills.recall import recall
  skills = load_skills()
  for q, expected in [('aws imds credential theft', 'aws-security'), ('azure managed identity token', 'azure-security'), ('gcp service account metadata', 'gcp-security')]:
      results = recall(q, skills)
      assert results and results[0].skill.name == expected, (q, results)
  print('OK')
  "
  ```

  Expected: prints `OK`.

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/skills/content/vulnerabilities/aws-security.md src/lalo/skills/content/vulnerabilities/azure-security.md src/lalo/skills/content/vulnerabilities/gcp-security.md
  git commit -m "docs(skills): add AWS/Azure/GCP-specific security skills

Complements the existing generic cloud-iam-privilege-escalation/
cloud-iam-storage-misconfiguration skills with provider-specific mechanisms
(IMDS/metadata-service token theft, provider-specific IAM/storage gotchas)
rather than duplicating the general escalation methodology."
  ```

---

### Task 13: Framework-specific skills — Django, FastAPI, NestJS, Next.js

**Files:**
- Create: `src/lalo/skills/content/vulnerabilities/django-security.md`
- Create: `src/lalo/skills/content/vulnerabilities/fastapi-security.md`
- Create: `src/lalo/skills/content/vulnerabilities/nestjs-security.md`
- Create: `src/lalo/skills/content/vulnerabilities/nextjs-security.md`
- Test: none new — existing loader/structural tests cover all four automatically.

**Interfaces:** none — content only. Each cross-references the relevant existing
generic skill ([[ssrf]], [[insecure-deserialization]], [[access-control]],
[[mass-assignment]], [[prototype-pollution]]) rather than restating it.

- [ ] **Step 1: Write `django-security.md`**

  ```markdown
  ---
  name: django-security
  category: vulnerability
  description: Django-specific attack surface — QuerySet injection edge cases, DEBUG-mode information disclosure, signing/session internals, and a per-class proof ladder
  keywords: [django, python web framework, queryset, orm injection, debug mode]
  ---

  # Django-Specific Security

  Django's own ORM and middleware close most of the generic classes by
  default; this skill covers where Django-specific mechanisms create their
  own distinct gaps, framework-specific escalations of [[sql-injection]],
  [[access-control]], and [[information-disclosure]].

  ## Attack Surface

  - Raw SQL escape hatches: `.raw()`, `.extra()` (deprecated but still
    present in older codebases), and any `cursor.execute()` with
    string-formatted (not parameterized) input.
  - `QuerySet` filter keys built from user-controlled strings passed via
    `**kwargs` to `.filter()`/`.exclude()` — Django's field-lookup syntax
    (`__gt`, `__contains`, `__isnull`, and critically `__year`/date-based
    lookups that can trigger a slow query) becomes attacker-controlled if
    the KEY itself, not just the value, comes from user input.
  - `DEBUG = True` in a production-reachable deployment — Django's own
    debug error page discloses the full settings module (including
    `SECRET_KEY` if not filtered), installed apps, and local variable state
    at the point of the exception.
  - `django.core.signing`/session-cookie internals: a leaked `SECRET_KEY`
    (via the DEBUG page above, a leaked `.env`, or a weak/default value)
    allows forging any signed cookie or session, not just re-reading one.

  ## Recon

  - Trigger a genuine unhandled exception (an invalid type on a normally-
    validated parameter, a malformed multipart body) and check whether the
    response is Django's own yellow debug traceback page rather than a
    generic 500 — this is the highest-value single check for this
    framework given how much it discloses at once.
  - Grep accessible source (if available) for `.raw(`, `.extra(`, and any
    `**request.GET`/`**request.POST` spread directly into a `.filter()` or
    `.exclude()` call — the field-lookup-key-injection pattern is easy to
    miss without seeing the actual call site.
  - Check whether `SECRET_KEY` is Django's own well-known insecure
    development default (`django-insecure-...` prefix, or older
    versions' placeholder values) — a leaked or default key is a full
    session/signing compromise on its own, worth testing directly.

  ## Techniques

  1. **Field-lookup-key injection.** Where user input controls a filter
     KEY (not just a value) reaching `.filter(**{user_key: value})`, probe
     with Django's own lookup suffixes to confirm the key is unsanitized:
     `__isnull=True` (bypasses an expected exact-match filter entirely,
     returning unintended rows), a chained relation traversal
     (`related_model__field`) that reaches data outside the intended
     query's scope, or a deliberately slow lookup for a DoS-adjacent signal
     (report only as a note, per this project's own non-destructive
     testing discipline — never actually execute a resource-exhaustion
     attack).
  2. **DEBUG-page triggering**, per Recon — once triggered, extract
     `SECRET_KEY` (if present and not filtered by Django's own
     `SAFE_SETTINGS`/sensitive-variable masking, which is not applied to
     every custom setting) and any other credential visible in the local
     variable dump.
  3. **Signed-cookie/session forgery**, once `SECRET_KEY` is known — use
     `django.core.signing.dumps`/a compatible forgery script to mint a
     session or signed value that the application will accept as
     legitimate; confirm by presenting it and observing the authenticated
     response.

  ## Proof Ladder

  - **L1** — a Django-specific mechanism identified (a raw-SQL escape
    hatch, a user-controlled filter key, `DEBUG` possibly enabled) but not
    yet confirmed exploitable.
  - **L2** — the mechanism confirmed reachable (the debug page actually
    renders; the filter-key injection changes the returned row set) but no
    concrete secret/data exposure demonstrated yet.
  - **L3** — a concrete secret or unintended data extracted (`SECRET_KEY`
    from the debug page, out-of-scope rows via lookup-key injection) —
    reportable.
  - **L4** — the extracted secret used to forge a session/signed value that
    the application accepts, demonstrating full authentication bypass.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]]. `DEBUG = True` confirmed disabled (a
  generic error page, no traceback) closes the debug-disclosure path
  entirely — do not report DEBUG-mode risk speculatively without actually
  triggering an exception and observing the response. A `.filter()` call
  built from a fixed, developer-authored key (never from `request.GET`/
  `request.POST` directly) is not vulnerable regardless of how the VALUE is
  validated — confirm the KEY's own source, not just the value's.

  ## Impact

  Full settings/secret disclosure and subsequent session/signing forgery
  via a triggered debug page; data exposure or access-control bypass via
  field-lookup-key injection reaching unintended rows or relations.

  ## Summary

  The Django debug page is the single highest-value target — always try to
  trigger a genuine unhandled exception first. Separately, always check
  whether a filter KEY (not just its value) is user-controlled before
  assuming Django's ORM parameterization protects a `.filter()` call the
  same way it protects a raw value.
  ```

- [ ] **Step 2: Write `fastapi-security.md`**

  ```markdown
  ---
  name: fastapi-security
  category: vulnerability
  description: FastAPI-specific attack surface — Pydantic validation-bypass edge cases, dependency-injection auth gaps, background-task/async pitfalls, and a per-class proof ladder
  keywords: [fastapi, pydantic, starlette, python async web framework, dependency injection]
  ---

  # FastAPI-Specific Security

  FastAPI's Pydantic-based validation and dependency-injection system
  prevent whole classes of bugs by default, but create their own distinct
  gaps when a developer works around them — a framework-specific
  escalation of [[access-control]] and [[mass-assignment]].

  ## Attack Surface

  - A response model (`response_model=`) that differs from the actual
    returned object — FastAPI serializes based on the response model, so a
    developer relying on this for redaction can be wrong if the model
    itself is too permissive or a field is aliased incorrectly.
  - Auth enforced via a route-level `Depends(get_current_user)` — a route
    that FORGETS to declare this dependency is entirely unauthenticated,
    with no visual cue in the route decorator itself the way a
    decorator-based framework's `@login_required` would give.
  - Pydantic model `.dict()`/`.model_dump()` used directly to build a
    database update — any extra field the client sends that happens to
    match a model attribute (even one marked `Optional` and not intended
    to be client-settable) can flow straight into a mass-assignment.
  - `BackgroundTasks` running after the response is already sent — an
    error inside a background task is invisible to the client and often
    under-logged, and a background task that itself does unsafe work (an
    unvalidated file operation, an SSRF-shaped external call) is a
    lower-visibility surface than the main request path.

  ## Recon

  - Enumerate every route via the auto-generated OpenAPI schema
    (`/openapi.json`, unless explicitly disabled) and cross-reference
    against which ones actually declare an auth dependency — a route
    present in the schema with no `Depends(...)` matching the app's own
    auth pattern is a strong lead, not yet a confirmed finding (some routes
    are legitimately public).
  - Check whether a model used for a WRITE endpoint reuses a broader model
    also used for reads — a shared model with more fields than the write
    endpoint's own documented request body suggests can indicate a
    mass-assignment surface via extra JSON keys.
  - Confirm whether Pydantic's `extra` config is set to `"forbid"` (rejects
    unknown fields, the safer default in Pydantic v2 for most models) or
    left permissive.

  ## Techniques

  1. **Dependency-injection auth-gap probe.** For each route the OpenAPI
     schema exposes with no obvious auth dependency, send an unauthenticated
     request and confirm whether it succeeds where a sibling, clearly-
     protected route would reject it — this is [[access-control]]'s own
     methodology, applied to this framework's specific "forgotten
     decorator" failure mode.
  2. **Mass-assignment via extra JSON keys.** Send extra fields in a write
     request's JSON body beyond the documented schema and observe whether
     they take effect (a role/privilege field flipped, a foreign-key
     ownership field changed) — this is [[mass-assignment]]'s methodology,
     specifically checking whether `.model_dump()` output flows unfiltered
     into a persistence call.
  3. **Response-model over-exposure check.** Compare the actual JSON
     returned against the documented `response_model` — a field present in
     the response but absent from the schema (or a nested object the
     response model doesn't actually constrain) indicates the developer's
     redaction assumption doesn't hold at runtime.

  ## Proof Ladder

  Follow [[access-control]]'s ladder for an auth-gap finding and
  [[mass-assignment]]'s ladder for a write-endpoint finding — this skill
  supplies the FastAPI-specific recon and technique, not a separate ladder.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]]. A route legitimately intended to be public
  (a health check, a login endpoint itself) having no auth dependency is
  expected, not a finding — confirm the route's actual intended
  sensitivity before reporting a missing dependency. `extra="forbid"`
  confirmed set on the write model closes the extra-JSON-key mass-
  assignment path entirely for that endpoint.

  ## Impact

  Full authentication bypass on a route missing its intended dependency;
  privilege escalation or unauthorized data modification via mass-
  assignment through an unfiltered `.model_dump()`; sensitive data exposure
  via a response model that doesn't actually constrain what's serialized.

  ## Summary

  Cross-reference the auto-generated OpenAPI schema against the app's own
  auth-dependency pattern to find routes missing it — this framework gives
  no visual decorator cue the way others do. Separately, always check
  whether write-endpoint `.model_dump()` output is filtered before
  reaching a persistence call.
  ```

- [ ] **Step 3: Write `nestjs-security.md`**

  ```markdown
  ---
  name: nestjs-security
  category: vulnerability
  description: NestJS-specific attack surface — Guard/Interceptor ordering gaps, class-transformer/class-validator bypass edge cases, and a per-class proof ladder
  keywords: [nestjs, nest, typescript backend framework, guard, interceptor, class-validator]
  ---

  # NestJS-Specific Security

  NestJS's decorator-based Guards/Interceptors/Pipes enforce auth and
  validation declaratively, which creates a distinct framework-specific
  failure mode when the DECORATOR ORDER or SCOPE doesn't do what a
  developer assumes — a framework-specific escalation of
  [[access-control]] and [[mass-assignment]].

  ## Attack Surface

  - `@UseGuards()` applied at the controller (class) level vs. the
    individual route (method) level — a guard intended to protect an
    entire controller that is instead only applied to some of its routes
    (or applied but then a specific route uses `@Public()`/a custom
    bypass decorator incorrectly) leaves siblings unprotected.
  - Global guards registered via `APP_GUARD` vs. per-module/per-controller
    guards — a route in a module that never imports the guard-providing
    module can be unprotected even when the "global" guard looks like it
    should apply everywhere.
  - `class-validator`/`class-transformer` DTOs with `whitelist: true` not
    enabled globally on the `ValidationPipe` — without it, extra fields
    beyond the DTO's own declared properties pass through to whatever
    consumes the validated object, the same mass-assignment shape as an
    unfiltered FastAPI `.model_dump()`.
  - A custom `@Roles()`/`RolesGuard` implementation with a logic bug
    (checking `some()` role match when `every()` was intended, or checking
    against a stale/cached user-role claim from the JWT rather than a
    fresh database read after a role change).

  ## Recon

  - Read the actual module wiring (not just individual controller files)
    to determine which guards are TRULY global (`APP_GUARD` in the root
    `AppModule`) versus scoped to a specific feature module — a route in
    an unimported or lazily-loaded module can silently bypass an
    apparently-global guard.
  - Check the `ValidationPipe`'s global configuration (usually in
    `main.ts`) for `whitelist: true` and `forbidNonWhitelisted: true` —
    their absence means extra DTO fields are silently accepted (whitelist)
    or silently stripped without erroring (forbidNonWhitelisted absent),
    each with a different exploitability implication worth confirming
    directly rather than assuming from the setting's mere presence.
  - Read any custom Guard's actual role-check logic for an `Array.some()`
    vs. `Array.every()` mismatch against the endpoint's documented
    intended access policy.

  ## Techniques

  1. **Per-route guard-gap probe**, following [[access-control]]'s own
     methodology — for every route in a controller whose SIBLING routes
     are protected, test the specific route unauthenticated/under-
     privileged and compare.
  2. **Extra-field mass-assignment via DTO whitelist gap**, following
     [[mass-assignment]]'s methodology — send extra JSON fields beyond the
     DTO's declared shape and confirm whether they reach the persistence
     layer when `whitelist`/`forbidNonWhitelisted` is not enabled.
  3. **Role-check logic probe.** Where a custom Guard checks membership in
     a role array, test with a role set crafted to exercise the specific
     `some()`/`every()` distinction (e.g. a user with one qualifying role
     among several required ones, if the endpoint is meant to require ALL
     of them).

  ## Proof Ladder

  Follow [[access-control]]'s ladder for a guard-gap finding and
  [[mass-assignment]]'s ladder for a DTO-whitelist finding.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]]. A route confirmed covered by a genuinely
  global `APP_GUARD` (verified in the root module's actual providers array,
  not assumed from naming) is the control working correctly. `whitelist:
  true` confirmed set on the global `ValidationPipe` closes the extra-
  field mass-assignment path for every DTO in the application at once —
  verify this one global setting before testing each DTO individually.

  ## Impact

  Authentication/authorization bypass on a route missing effective guard
  coverage; privilege escalation or unauthorized data modification via a
  DTO whitelist gap; access-control bypass via a role-check logic error in
  a custom Guard.

  ## Summary

  Read the actual module wiring to determine which guards are truly
  global versus module-scoped before assuming a route is protected — a
  route in an unimported module can silently bypass an apparently-global
  guard. Separately, one global `ValidationPipe` setting
  (`whitelist`/`forbidNonWhitelisted`) determines the DTO mass-assignment
  exposure for the whole application at once.
  ```

- [ ] **Step 4: Write `nextjs-security.md`**

  ```markdown
  ---
  name: nextjs-security
  category: vulnerability
  description: Next.js-specific attack surface — API-route/middleware auth gaps, Server Actions/RSC data-exposure edge cases, and a per-class proof ladder
  keywords: [nextjs, next.js, react server components, server actions, middleware, api routes]
  ---

  # Next.js-Specific Security

  Next.js blends server and client code in one project in a way that
  creates its own distinct failure modes — a framework-specific
  escalation of [[access-control]], [[information-disclosure]], and
  [[csrf]].

  ## Attack Surface

  - `middleware.ts` used as the SOLE auth check for a set of routes — its
    `matcher` config can have gaps (a route pattern that doesn't actually
    match what the developer intended, especially with dynamic segments or
    trailing-slash variations), and a route handler reachable directly
    (bypassing the expected page-render path) may not re-check auth itself.
  - Server Actions (`"use server"` functions) — each one is a real,
    independently-callable network endpoint the moment it's exported, even
    though it reads like a plain function call in the calling component;
    a Server Action performing no additional auth/ownership check of its
    own inherits none of the calling page's own access control.
  - React Server Components accidentally serializing more than intended
    into the client bundle/payload — a server-only secret or an internal
    object passed as a prop to a Client Component crosses the server/
    client boundary and becomes visible in the page source or RSC payload.
  - `getServerSideProps`/API routes reading environment variables without
    the `NEXT_PUBLIC_` prefix distinction — a variable meant to stay
    server-only that is mistakenly given the `NEXT_PUBLIC_` prefix is
    bundled into client-side JavaScript at build time.

  ## Recon

  - Read `middleware.ts`'s `matcher` config against the actual route tree
    and test edge cases directly: a trailing slash, a case variation, a
    route one level deeper than the matcher pattern's own wildcard depth
    covers.
  - Grep for `"use server"` directives and treat each exported function as
    its own endpoint — check whether it re-validates the caller's
    identity/ownership independently, or only relies on the calling page
    having already checked (which an attacker calling the action's own
    generated endpoint directly bypasses entirely).
  - Diff the server-rendered page source and any RSC payload against what
    the corresponding React component's props actually need — an object
    passed wholesale to a Client Component (rather than the specific
    fields it uses) is a common source of accidental over-serialization.

  ## Techniques

  1. **Middleware matcher-gap probe.** Request the protected route's exact
     path with common variations (trailing slash, differing case, an
     encoded segment) and confirm the middleware's auth check actually
     fires for each — a gap here fully bypasses the intended protection.
  2. **Server Action direct-call probe.** Call a Server Action's generated
     endpoint directly (its `Next-Action` header-driven POST, discoverable
     from the client bundle or by simply invoking it from a page context
     other than the one it was written for) with a different user's
     identity/session and confirm whether it enforces the same ownership
     check the calling page assumed.
  3. **Client-payload secret scan.** Search the actual rendered page
     source and any RSC payload/`__NEXT_DATA__` blob for a value that
     should have stayed server-only (an internal id scheme, a third-party
     API key, unredacted user data beyond what the visible UI needs).

  ## Proof Ladder

  Follow [[access-control]]'s ladder for a middleware/Server-Action gap and
  [[information-disclosure]]'s ladder for an over-serialization finding.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]]. A Server Action confirmed to independently
  re-validate the caller's identity/ownership (not merely relying on the
  calling page's own prior check) is the control working correctly even
  though the action is technically callable directly. A value present in
  the client bundle that is already intentionally public (confirmed via
  the `NEXT_PUBLIC_` prefix and a check that it carries no actual secret
  value) is expected behavior, not a finding.

  ## Impact

  Full access-control bypass via a middleware matcher gap or an
  unauthenticated/unauthorized direct call to a Server Action; sensitive
  data or secret exposure via over-serialization into the client bundle or
  RSC payload.

  ## Summary

  Treat every exported Server Action as its own independently-callable
  endpoint requiring its own auth/ownership check, never assuming the
  calling page's own check carries over. Separately, always test
  middleware matcher edge cases directly rather than trusting the config's
  stated intent.
  ```

- [ ] **Step 5: Verify all four load and are recallable**

  ```
  uv run pytest tests/lalo/test_skills_loader.py -v
  ```

  Expected: all PASS.

  ```
  uv run python -c "
  from lalo.skills.loader import load_skills
  from lalo.skills.recall import recall
  skills = load_skills()
  for q, expected in [
      ('django debug mode secret key', 'django-security'),
      ('fastapi dependency injection auth', 'fastapi-security'),
      ('nestjs guard interceptor', 'nestjs-security'),
      ('nextjs server action middleware', 'nextjs-security'),
  ]:
      results = recall(q, skills)
      assert results and results[0].skill.name == expected, (q, results)
  print('OK')
  "
  ```

  Expected: prints `OK`.

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/skills/content/vulnerabilities/django-security.md src/lalo/skills/content/vulnerabilities/fastapi-security.md src/lalo/skills/content/vulnerabilities/nestjs-security.md src/lalo/skills/content/vulnerabilities/nextjs-security.md
  git commit -m "docs(skills): add Django/FastAPI/NestJS/Next.js-specific security skills

Framework-specific escalations of the existing generic access-control/
mass-assignment/information-disclosure skills - each covers the specific
mechanism (DEBUG-page disclosure, dependency-injection auth gaps, Guard
scoping, Server Action/middleware boundaries) that makes this framework's
own failure mode distinct."
  ```

---

### Task 14: `oauth-oidc.md` protocol skill

**Files:**
- Create: `src/lalo/skills/content/vulnerabilities/oauth-oidc.md`
- Test: none new — existing loader/structural tests cover it automatically.

**Interfaces:** none — content only. GraphQL is already fully covered by the
existing `vulnerabilities/graphql.md` (confirmed by reading it live this session —
see "Scope corrections" above), so only OAuth/OIDC is written here.

- [ ] **Step 1: Write the skill file**

  ```markdown
  ---
  name: oauth-oidc
  category: vulnerability
  description: OAuth 2.0/OIDC protocol-level security — redirect_uri validation gaps, PKCE/state omission, token-endpoint confusion, and a per-class proof ladder
  keywords: [oauth, oauth2, oidc, openid connect, pkce, redirect_uri, authorization code, implicit flow]
  ---

  # OAuth 2.0 / OIDC

  OAuth/OIDC's security rests almost entirely on a handful of parameters
  being validated exactly, not approximately — `redirect_uri`, `state`,
  and PKCE's `code_verifier`/`code_challenge` pair. This skill covers the
  protocol-level gaps in how a relying party or authorization server
  validates them, distinct from [[jwt]] (which covers the TOKEN itself
  once issued) and the "nOAuth" mutable-claim account-takeover technique
  already covered in [[jwt]]'s own OIDC section.

  ## Attack Surface

  - The authorization endpoint's `redirect_uri` validation — exact match
    vs. prefix match vs. no validation at all.
  - Presence and validation of `state` (CSRF protection for the
    authorization flow) and PKCE (`code_challenge`/`code_verifier`,
    protection against authorization-code interception).
  - The token endpoint's handling of `grant_type`/`client_id`/
    `client_secret` — confusion between a public client (SPA/mobile,
    should never hold a secret) and a confidential client's flow.
  - Any custom-built authorization server (vs. a well-known managed IdP)
    is higher-risk by default — the well-known providers have had these
    exact gaps hardened over years of public research.

  ## Recon

  - Identify the flow in use (authorization code, authorization code +
    PKCE, implicit — the latter deprecated and itself a finding if still
    in use for a new integration) and whether the client is public or
    confidential.
  - Test the actual `redirect_uri` validation directly rather than reading
    documentation about it: register/observe the expected value, then try
    a subdomain variation, a path-suffix addition, a different scheme, and
    an open-redirect-shaped value on the SAME registered host (a redirect
    endpoint on the legitimate host that itself forwards elsewhere).
  - Check whether `state` is present, unique per request, and actually
    verified on callback (vs. merely echoed back and ignored) — a present-
    but-unchecked `state` parameter is functionally the same gap as a
    missing one.

  ## Techniques

  1. **`redirect_uri` validation-strength probe.** Attempt each variation
     from Recon in turn; a successful authorization-code delivery to an
     attacker-controlled or attacker-reachable URI (an open redirect on
     the legitimate host counts, since it forwards the code onward) is the
     core exploitation primitive this class is built around.
  2. **CSRF-via-missing/unchecked-`state` probe.** Initiate an
     authorization flow as the attacker, capture the resulting
     authorization code/callback URL, and have the victim's browser follow
     it (a standard CSRF delivery) — if the relying party accepts it and
     links the attacker's OAuth identity to the victim's existing session,
     this is a full account-linking/takeover primitive, not merely a CSRF
     nuisance.
  3. **PKCE downgrade/omission check.** For a public client, confirm PKCE
     is actually REQUIRED by the authorization server (not merely
     supported) — attempt the authorization code exchange without a
     `code_verifier` and confirm it is rejected; if accepted, an
     intercepted authorization code (via the `redirect_uri` primitive
     above, a referrer leak, or a malicious app on the same device) can be
     exchanged by the attacker directly.
  4. **Client confusion / token-endpoint parameter-pollution check.**
     Attempt to exchange a code intended for a public client using a
     confidential client's endpoint behavior (or vice versa), and check
     whether supplying an unexpected `client_id`/multiple `client_id`
     values in the token request produces confused-deputy behavior.

  ## Proof Ladder

  - **L1** — a validation gap identified (loose `redirect_uri` matching,
    missing `state`, PKCE not enforced) but not yet demonstrated end-to-end.
  - **L2** — a single hop of the gap demonstrated in isolation (an
    authorization code successfully delivered to a variant redirect URI;
    an authorization request accepted with no `state`) without yet
    completing a full account-impact chain.
  - **L3** — the gap chained to a concrete, observed account-level effect:
    an authorization code intercepted and exchanged by the attacker, or a
    victim's account linked to an attacker-controlled OAuth identity via
    CSRF — reportable.
  - **L4** — full account takeover: the attacker gains an authenticated
    session as the victim through the chained gap, reproducible on a
    second run.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]]. `redirect_uri` confirmed validated by
  EXACT string match against a pre-registered allowlist (not merely
  "starts with" or "same host") closes the redirect-uri primitive
  entirely — confirm the actual match algorithm by testing variations
  directly, never by reading a client registration UI's stated value
  alone. `state` confirmed cryptographically random, unique per request,
  and actually verified against the session on callback is the control
  working correctly.

  ## Impact

  Full account takeover via a chained redirect_uri/state/PKCE gap;
  authorization-code theft and replay; cross-account linking via CSRF on
  the authorization callback.

  ## Summary

  Test `redirect_uri`/`state`/PKCE validation directly with real variation
  attempts — documentation or a registration UI's stated policy is not
  evidence of the actual server-side validation strength. A chain across
  more than one of these three usually produces the highest-severity,
  clearest-to-reproduce finding in this class.
  ```

- [ ] **Step 2: Verify it loads and is recallable**

  ```
  uv run pytest tests/lalo/test_skills_loader.py -v
  ```

  Expected: all PASS.

  ```
  uv run python -c "
  from lalo.skills.loader import load_skills
  from lalo.skills.recall import recall
  skills = load_skills()
  results = recall('oauth redirect_uri pkce state', skills)
  assert results and results[0].skill.name == 'oauth-oidc', results
  print('OK:', results[0].skill.name)
  "
  ```

  Expected: prints `OK: oauth-oidc`.

- [ ] **Step 3: Commit**

  ```bash
  git add src/lalo/skills/content/vulnerabilities/oauth-oidc.md
  git commit -m "docs(skills): add oauth-oidc protocol skill

Protocol-level OAuth 2.0/OIDC gaps (redirect_uri validation strength,
state/PKCE omission, token-endpoint client confusion) - distinct from jwt.md,
which covers the issued token itself. GraphQL is already fully covered by
the existing graphql.md skill, confirmed by reading it live, so no separate
protocols/graphql.md file is needed."
  ```

---

### Task 15: Technology-specific skills — Auth0, Electron, Firebase, Grafana/Prometheus, LLM applications, Supabase

**Files:**
- Create: `src/lalo/skills/content/vulnerabilities/auth0.md`
- Create: `src/lalo/skills/content/vulnerabilities/electron-desktop-apps.md`
- Create: `src/lalo/skills/content/vulnerabilities/firebase.md`
- Create: `src/lalo/skills/content/vulnerabilities/grafana-prometheus.md`
- Create: `src/lalo/skills/content/vulnerabilities/llm-applications.md`
- Create: `src/lalo/skills/content/vulnerabilities/supabase.md`
- Test: none new — existing loader/structural tests cover all six automatically.

**Interfaces:** none — content only. `llm-applications.md` cross-references the
existing [[llm-prompt-injection]] skill (application-architecture-level gaps around
an LLM feature, distinct from prompt-injection technique itself).

- [ ] **Step 1: Write `auth0.md`**

  ```markdown
  ---
  name: auth0
  category: vulnerability
  description: Auth0-specific attack surface — Rule/Action misconfiguration, tenant/connection confusion, and a per-class proof ladder
  keywords: [auth0, identity provider, rules, actions, tenant]
  ---

  # Auth0

  Auth0-specific gaps center on custom Rules/Actions (arbitrary JavaScript
  a tenant admin writes to run during login) and connection/tenant
  configuration — an escalation surface [[oauth-oidc]]'s generic protocol
  methodology doesn't cover.

  ## Attack Surface

  - Custom Rules/Actions running arbitrary tenant-authored JavaScript
    during the login pipeline — a bug here (an insecure API call, a
    hardcoded credential, an injection into a downstream call) is a
    tenant-specific vulnerability layered on top of Auth0's own platform
    security.
  - Multiple connections (database, social, enterprise) on one tenant —
    an account-linking Rule that links identities by email without
    verifying the email is actually verified on the incoming connection
    is the same mutable-claim account-takeover shape [[jwt]] already
    documents for generic OIDC, specific to how Auth0 exposes it.
  - Auth0's Management API credentials (a machine-to-machine application)
    with overly broad scopes, if leaked, allow full tenant administration.

  ## Recon

  - Where source or configuration access exists, read every Rule/Action's
    actual code for a hardcoded secret, an unvalidated external call, or
    an account-linking decision based on an unverified claim.
  - Enumerate the tenant's configured connections and check whether any
    social/enterprise connection's `email_verified` claim is actually
    checked before an account-linking Rule uses email as the linking key.

  ## Techniques

  1. **Unverified-email account linking**, the Auth0-specific instance of
     the mutable-claim takeover technique in [[jwt]] — register via a
     connection that allows an unverified or attacker-chosen email and
     confirm whether a linking Rule grants access to an existing account
     sharing that email.
  2. **Rule/Action code-injection or logic-bug exploitation** — direct
     source review of any accessible custom Rule/Action code, applying
     [[source-aware-review]]'s methodology.

  ## Proof Ladder

  Follow [[oauth-oidc]]'s ladder for the protocol-level portion of any
  finding; a confirmed Rule/Action code vulnerability follows whatever
  class its actual bug shape belongs to (e.g. [[command-injection]] if the
  Rule shells out unsafely).

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]]. An account-linking Rule that explicitly
  checks `email_verified === true` before linking closes the unverified-
  email path — confirm this check exists in the actual Rule code, not from
  the connection's general description.

  ## Impact

  Account takeover via unverified-email account linking; arbitrary
  compromise via a vulnerable custom Rule/Action; full tenant compromise
  via leaked Management API credentials.

  ## Summary

  Read the tenant's actual Rules/Actions code and connection configuration
  directly — this is where Auth0-specific risk concentrates, on top of
  whatever the underlying OAuth/OIDC protocol-level checks in
  [[oauth-oidc]] already cover.
  ```

- [ ] **Step 2: Write `electron-desktop-apps.md`**

  ```markdown
  ---
  name: electron-desktop-apps
  category: vulnerability
  description: Electron-specific attack surface — nodeIntegration/contextIsolation misconfiguration, IPC handler trust boundaries, and a per-class proof ladder
  keywords: [electron, desktop app, nodeintegration, contextisolation, ipc, preload script]
  ---

  # Electron Desktop Applications

  An Electron app's renderer process is a Chromium web page; if it can
  reach Node.js APIs directly, any client-side vulnerability that would
  normally be confined to the browser sandbox ([[xss]] chief among them)
  escalates directly to native code execution on the user's machine.

  ## Attack Surface

  - `nodeIntegration: true` and/or `contextIsolation: false` on any
    `BrowserWindow` that renders content influenced by remote/untrusted
    data (a loaded URL, a rendered Markdown/HTML preview, chat content).
  - The preload script's exposed API surface (`contextBridge.exposeInMainWorld`)
    — an overly broad exposed function (e.g. one wrapping raw
    `fs`/`child_process` access with no argument validation) hands the
    renderer a native-code-execution primitive even with
    `contextIsolation: true` correctly enabled.
  - IPC handlers (`ipcMain.handle`/`ipcMain.on`) that trust the renderer's
    arguments without validating them the same way a server would validate
    a network request — the renderer is not a trusted process boundary
    just because it's the same application.
  - `webSecurity: false`, or a `will-navigate`/`new-window` handler that
    doesn't restrict navigation to expected origins, allowing a loaded
    remote page to navigate to and execute in a more privileged context.

  ## Recon

  - Read the actual `BrowserWindow` construction options for
    `nodeIntegration`/`contextIsolation`/`webSecurity`/`sandbox` — this is
    the single highest-value check, since it determines whether ANY
    renderer-side bug (XSS especially) escalates to RCE at all.
  - Read the preload script in full and catalog every function exposed via
    `contextBridge` — for each, identify what native capability it
    ultimately reaches and whether its arguments are validated before use.
  - Read every `ipcMain.handle`/`ipcMain.on` registration and check what
    it does with the arguments it receives from the renderer.

  ## Techniques

  1. **XSS-to-RCE escalation check.** If `nodeIntegration: true` or
     `contextIsolation: false` on a window rendering untrusted content, any
     confirmed [[xss]] there escalates directly — demonstrate by having the
     injected script call a Node.js global (`require('child_process')`)
     and execute a benign command, proving native code execution rather
     than just script execution in a sandbox.
  2. **Preload-bridge argument-injection probe.** For each exposed
     `contextBridge` function wrapping a native capability, call it from
     the renderer's DevTools/console (or via a confirmed XSS) with
     adversarial arguments (a path-traversal-shaped file path, a command-
     injection-shaped string) and confirm whether the underlying native
     call validates them.
  3. **IPC-handler trust-boundary probe.** Send unexpected/adversarial
     arguments to an `ipcMain` handler the same way you would fuzz an API
     endpoint, applying whatever class the handler's actual native
     operation belongs to (path traversal, command injection, SSRF).

  ## Proof Ladder

  - **L1** — a risky configuration identified (`nodeIntegration`/
    `contextIsolation` misconfigured, or a preload function wrapping a
    native capability with no visible validation) but not yet exploited.
  - **L2** — the risky configuration confirmed reachable from
    attacker-influenced content (an XSS lands in the affected window; the
    preload function is callable with adversarial arguments) with no
    native-code effect demonstrated yet.
  - **L3** — a benign native-code effect demonstrated (a proof file
    written/read, a benign command executed) via the escalation path —
    reportable.
  - **L4** — full, reliable native code execution reproducible from a
    remote/untrusted content source with no additional local access
    required.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]]. `contextIsolation: true` combined with a
  preload script exposing only narrowly-scoped, argument-validated
  functions (confirmed by reading the actual preload code, not assumed
  from the setting alone) closes the direct-Node-access escalation path
  even if the renderer itself is later found vulnerable to XSS.

  ## Impact

  Native code execution on the end user's machine from a renderer-side
  vulnerability that would otherwise be sandbox-confined in an ordinary
  browser context — full desktop compromise, not merely a web-application-
  scoped impact.

  ## Summary

  Always start with the `BrowserWindow` construction options —
  `nodeIntegration`/`contextIsolation`/`webSecurity`/`sandbox` determine
  whether every other finding in this application escalates to native code
  execution or stays browser-sandbox-confined. Then read the preload
  script and IPC handlers as their own, separate trust boundary.
  ```

- [ ] **Step 3: Write `firebase.md`**

  ```markdown
  ---
  name: firebase
  category: vulnerability
  description: Firebase-specific attack surface — Firestore/Realtime Database security-rule gaps, Cloud Functions trigger trust, and a per-class proof ladder
  keywords: [firebase, firestore, realtime database, security rules, cloud functions]
  ---

  # Firebase

  Firebase's security model puts most enforcement in declarative Security
  Rules evaluated CLIENT-side-callable but SERVER-enforced — the entire
  class here is rules that look restrictive but have a logic gap, since
  the client SDK itself enforces nothing on its own.

  ## Attack Surface

  - Firestore/Realtime Database security rules — the actual enforcement
    boundary for every direct client read/write; a permissive default
    (`allow read, write: if true;` left from initial scaffolding) or a
    rule with a logic gap is a direct, unmediated data-access
    vulnerability.
  - Cloud Functions triggered by a database write (`onCreate`/`onUpdate`)
    that trust the written data's shape/origin without revalidating it —
    since the trigger fires on ANY write that gets past the security
    rules, a rule gap upstream becomes a function-level trust violation
    downstream too.
  - Firebase Authentication custom claims used for authorization in
    security rules — a claim set via a Cloud Function with insufficient
    validation of who can request it is a privilege-escalation path.

  ## Recon

  - Obtain or infer the actual deployed security rules (via the Firebase
    console/CLI if access exists, or by direct probing if not) rather than
    assuming from the application's own client-side query patterns — a
    client only ever querying its own documents proves nothing about
    whether the RULES would also allow querying someone else's.
  - Identify every custom claim used in a security rule (`request.auth.token.<claim>`)
    and trace how it gets set — a claim set by a Cloud Function
    triggered by a user-writable document (rather than an admin-only
    action) is a strong escalation lead.

  ## Techniques

  1. **Direct rule-boundary probe**, applying [[access-control]]'s
     methodology directly against the Firestore/RTDB REST API or client
     SDK: attempt to read/write a document outside your own expected scope
     (another user's document, a collection the UI never queries) and
     observe whether the rules actually reject it.
  2. **Custom-claim escalation via trigger.** If a custom claim is set by a
     Cloud Function reacting to a user-writable event, attempt to trigger
     that function with attacker-controlled input to obtain a claim you
     should not have, then confirm the claim now grants elevated access in
     a security rule that trusts it.
  3. **List/query-based over-exposure check.** Even with per-document
     rules correctly scoped, check whether a COLLECTION-level list/query
     operation (rather than a get-by-id) inadvertently returns documents
     the rules would individually deny — a rules gap specific to how
     Firestore evaluates list queries against per-document rules.

  ## Proof Ladder

  Follow [[access-control]]'s own proof ladder — this skill supplies the
  Firebase-specific mechanism to reach it.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]]. A security rule confirmed to check
  `request.auth.uid == resource.data.ownerId` (or an equivalent real
  ownership check) on every read/write path for a collection is the
  control working correctly — confirm this against the ACTUAL deployed
  rules text, not the application's client-side query behavior alone.

  ## Impact

  Direct, unmediated read/write access to any user's data via a security-
  rule gap; privilege escalation via a custom claim set through an
  insufficiently-validated Cloud Function trigger.

  ## Summary

  The application's own client-side query behavior proves nothing about
  what the security rules actually allow — always obtain or directly probe
  the real rules, since Firebase's entire enforcement boundary lives
  there, not in the client code.
  ```

- [ ] **Step 4: Write `grafana-prometheus.md`**

  ```markdown
  ---
  name: grafana-prometheus
  category: vulnerability
  description: Grafana/Prometheus-specific attack surface — unauthenticated metrics/API exposure, data-source proxy SSRF, dashboard-injection, and a per-class proof ladder
  keywords: [grafana, prometheus, observability, metrics, alertmanager, data source proxy]
  ---

  # Grafana / Prometheus

  Observability stacks are frequently deployed with weaker access control
  than the application they monitor, on the assumption that "it's just
  metrics" — in practice, metrics and dashboards routinely leak internal
  topology, business data, and outright secrets, and Grafana's data-source
  proxy is a real SSRF primitive.

  ## Attack Surface

  - Prometheus's own `/metrics`, `/api/v1/query`, and `/api/v1/label/.../values`
    endpoints, and Alertmanager's API — commonly deployed with no
    authentication at all, reachable internally or occasionally externally.
  - Grafana's data-source proxy (`/api/datasources/proxy/:id/...`) —
    forwards a request to the configured backend (Prometheus, InfluxDB,
    Elasticsearch, a cloud provider's monitoring API) using the
    data source's OWN stored credentials; if the proxy path or query is
    insufficiently restricted, this is a direct SSRF primitive against
    whatever internal network the Grafana server itself can reach.
  - Grafana's default/weak admin credentials (`admin`/`admin` unchanged),
    and public dashboard sharing (`Share > Public dashboard`) potentially
    exposing an internal metric set to unauthenticated external viewers.
  - Alert notification channel configuration (webhook URLs, Slack/email
    credentials) visible to any user with dashboard-editing rights, not
    just admins, in some role configurations.

  ## Recon

  - Probe for unauthenticated Prometheus/Alertmanager endpoints directly —
    `/metrics`, `/api/v1/query?query=up`, `/api/v1/status/config` (the
    latter can disclose scrape target internals, occasionally credentials
    embedded in scrape configs).
  - Enumerate configured data sources in Grafana (via the UI/API if
    authenticated at any level) and identify which ones proxy to an
    internal-only backend — this is the SSRF-relevant subset.
  - Check the Grafana version against known default-credential and
    public-dashboard-related advisories for that specific version.

  ## Techniques

  1. **Unauthenticated Prometheus/Alertmanager data exposure**, direct
     probing per Recon — confirm what business/internal data the exposed
     metrics actually reveal (customer counts, internal hostnames, request
     patterns by endpoint) beyond generic system metrics.
  2. **Data-source proxy SSRF.** Via an authenticated (even low-privilege)
     Grafana session, attempt to manipulate the proxied query/path to
     reach an internal host/port the data source's own configured backend
     wouldn't normally serve — confirmed via a benign, observable response
     difference or an OAST callback, applying [[ssrf]]'s own methodology
     through this specific proxy mechanism.
  3. **Default-credential and public-dashboard check.** Attempt the
     well-known default admin credentials directly; separately, enumerate
     any dashboards shared via the public-link feature and assess what
     they expose to an unauthenticated viewer.

  ## Proof Ladder

  Follow [[ssrf]]'s own proof ladder for the data-source-proxy primitive;
  an unauthenticated data-exposure finding follows
  [[information-disclosure]]'s ladder.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]]. Metrics endpoints confirmed to require
  authentication (a 401/403 on direct probe) close this specific exposure
  path. A data-source proxy confirmed to restrict the proxied request to
  only the specific query shape the dashboard needs (not an arbitrary
  path/host) closes the SSRF primitive for that data source.

  ## Impact

  Internal topology and business-data disclosure via unauthenticated
  metrics endpoints; SSRF against internal infrastructure via the data-
  source proxy, using that data source's own stored, often privileged
  credentials; full Grafana compromise via default credentials.

  ## Summary

  Always probe for unauthenticated metrics/Alertmanager access directly —
  this is commonly deployed with weaker access control than the primary
  application. Separately, the data-source proxy is a genuine SSRF
  primitive worth testing on its own, not just an internal implementation
  detail.
  ```

- [ ] **Step 5: Write `llm-applications.md`**

  ```markdown
  ---
  name: llm-applications
  category: vulnerability
  description: LLM-application architecture-level attack surface — plugin/tool-calling trust boundaries, RAG data-source poisoning, and a per-class proof ladder (application design, distinct from prompt-injection technique itself)
  keywords: [llm application, rag, retrieval augmented generation, tool calling, agent security, vector database]
  ---

  # LLM Application Security

  This skill covers APPLICATION-ARCHITECTURE gaps in a system built around
  an LLM — where the untrusted-input boundary actually is, and what the
  LLM's own output is allowed to DO — distinct from
  [[llm-prompt-injection]], which covers the injection TECHNIQUE itself.
  Apply both together: prompt injection is usually the delivery mechanism,
  the gaps here are what makes it consequential.

  ## Attack Surface

  - Tool/function-calling where the LLM's OWN output selects and
    parameterizes a real action (a database query, an API call, a file
    operation, a code-execution sandbox) with insufficient validation of
    the LLM-chosen arguments before they execute — the LLM's output is
    attacker-influenceable the moment any untrusted content (a document it
    reads, a webpage it browses, a tool's own output) enters its context,
    so an unvalidated tool argument is functionally the same trust
    violation as an unvalidated user input.
  - RAG (retrieval-augmented generation) pipelines where the vector
    database/document store can be written to (directly or via an
    application feature) by a lower-trust actor than the one who queries
    it — a poisoned document injected into the retrieval corpus becomes
    part of a LATER, higher-trust user's context.
  - Conversation/session memory persisted and later replayed into a new
    context — if one user's adversarial input can be persisted (a shared
    document, a multi-tenant memory store with an isolation gap) and later
    retrieved into a DIFFERENT user's session.
  - System-prompt/instruction leakage treated as a confidentiality boundary
    when it also contains a real secret (an API key, an internal policy
    meant to stay undisclosed) rather than being purely a behavior
    specification.

  ## Recon

  - Map every tool/function the LLM can call and, for each, identify what
    happens with NO further validation if the LLM supplies an arbitrary,
    adversarial value for each parameter — this is the single most
    consequential thing to establish before attempting any prompt-
    injection technique at all.
  - Identify every place untrusted content enters the LLM's context (a
    user message, a retrieved document, a browsed page, a prior tool's
    output) and whether the application treats ALL of them as equally
    untrusted, or incorrectly trusts one channel (commonly: retrieved
    documents) more than direct user input.
  - For a RAG system, identify who can write to the retrieval corpus and
    whether that writer population is a strict subset of (or overlaps
    with, at a lower trust level than) the query population.

  ## Techniques

  1. **Tool-argument injection via untrusted content**, building on
     [[llm-prompt-injection]]'s own technique — plant an instruction in a
     channel the LLM will read (a document it's asked to summarize, a
     webpage it browses) directing it to call a real tool with an
     attacker-chosen argument, and confirm the tool actually executes with
     no independent validation.
  2. **RAG corpus poisoning.** If the retrieval corpus is writable by a
     lower-trust actor, insert a document containing an instruction
     targeting a LATER query from a higher-trust user, then trigger a
     query that would plausibly retrieve it, and confirm the injected
     instruction reaches and influences that later user's response.
  3. **Cross-session memory bleed check.** If conversation memory is
     persisted, attempt to plant content in one session and confirm
     whether it becomes retrievable in a DIFFERENT user's/tenant's session
     — a multi-tenancy isolation gap in the memory store, not a prompt-
     injection technique per se.
  4. **System-prompt secret-leakage check.** Attempt to have the model
     disclose its system prompt/instructions (a known family of prompt-
     injection techniques, see [[llm-prompt-injection]]) and, separately,
     assess whether anything disclosed constitutes an actual secret
     (credential, internal policy meant to stay confidential) versus
     merely revealing intended behavior — only the former is a
     confidentiality finding.

  ## Proof Ladder

  - **L1** — an unvalidated tool-argument path or an untrusted-content
    channel identified, but no actual injected instruction has been
    delivered through it yet.
  - **L2** — an injected instruction delivered through the identified
    channel and confirmed to influence the model's own output/tool
    selection, but the triggered tool call's real-world effect not yet
    observed.
  - **L3** — a concrete real-world effect observed from the triggered tool
    call (a benign file written, a query executed against unintended
    scope, a cross-session memory bleed confirmed) — reportable.
  - **L4** — the effect chained to a durable, high-impact outcome (data
    exfiltration across a tenant boundary, a destructive action on
    a resource outside the intended scope, reliable cross-session
    compromise) reproducible on a second run.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]]. A tool-calling layer confirmed to validate
  every LLM-supplied argument against the SAME rules a direct, untrusted
  user input to that action would face (an allowlist, a scope check, a
  parameterized query) closes the tool-argument-injection path regardless
  of how susceptible the model itself is to prompt injection — the model's
  own susceptibility only matters if something downstream trusts its
  output uncritically. A system prompt disclosing only intended-behavior
  description with no actual credential or confidential policy is not a
  confidentiality finding, even if disclosure itself was unintended.

  ## Impact

  Arbitrary action execution (data exfiltration, unauthorized queries,
  destructive operations) via unvalidated LLM-chosen tool arguments;
  cross-user/cross-tenant compromise via RAG corpus poisoning or memory-
  store isolation gaps; credential/secret exposure via genuine system-
  prompt leakage.

  ## Summary

  The tool-calling validation boundary is the single highest-leverage
  thing to check first — if every LLM-chosen argument is validated as
  rigorously as a direct user input would be, most prompt-injection
  technique success ([[llm-prompt-injection]]) becomes far less
  consequential. Separately, always check who can write to a RAG corpus
  relative to who queries it.
  ```

- [ ] **Step 6: Write `supabase.md`**

  ```markdown
  ---
  name: supabase
  category: vulnerability
  description: Supabase-specific attack surface — Row Level Security policy gaps, service-role-key exposure, Postgres function trust boundaries, and a per-class proof ladder
  keywords: [supabase, row level security, rls, postgres, service role key, anon key]
  ---

  # Supabase

  Supabase exposes a Postgres database directly to clients via
  PostgREST, with Row Level Security (RLS) policies as the ENTIRE
  enforcement boundary — the direct analog of Firebase's security rules,
  specific to Postgres's own RLS mechanism and Supabase's two-key model.

  ## Attack Surface

  - Row Level Security policies (or their absence) on every table exposed
    via the auto-generated REST/GraphQL API — a table with RLS disabled
    entirely, or enabled with an overly permissive policy, is a direct,
    unmediated data-access vulnerability the same shape as a Firestore
    rules gap.
  - The `anon`/`service_role` key distinction — the `service_role` key
    bypasses RLS entirely and must never reach client-side code; its
    presence in a client bundle, a mobile app binary, or a leaked
    environment file is a full, unmediated database-bypass credential.
  - Postgres functions exposed via RPC (`supabase.rpc(...)`) marked
    `SECURITY DEFINER` — these run with the DEFINING user's privileges
    (often elevated) rather than the calling user's, so an insufficiently
    validated `SECURITY DEFINER` function is a privilege-escalation path
    independent of RLS entirely.
  - Storage bucket policies (Supabase Storage has its own RLS-like policy
    system, separate from the database's) with a similar permissive-
    default risk.

  ## Recon

  - For every table reachable via the REST API (`/rest/v1/<table>`), check
    whether RLS is enabled at all and, if so, read the actual policy
    definitions where source/config access exists — a table's mere
    presence in the schema does not mean RLS is enforced on it.
  - Search client-side code/bundles/mobile binaries for the `service_role`
    key specifically (distinct from the intentionally-public `anon` key) —
    check the JWT payload's own `role` claim if only a bare key string is
    found, since `service_role` and `anon` keys are both JWTs signed with
    the project's JWT secret and differ only in this claim.
  - Enumerate RPC-exposed Postgres functions and identify which are marked
    `SECURITY DEFINER`.

  ## Techniques

  1. **Direct RLS-boundary probe**, applying [[access-control]]'s
     methodology against the REST/GraphQL API using the `anon` key (or an
     authenticated low-privilege user's key): attempt to read/write rows
     outside the expected scope and observe whether RLS actually rejects
     it.
  2. **`service_role`-key exposure scan**, per Recon — if found client-
     side, confirm its actual role via the JWT payload and demonstrate the
     bypass by reading/writing a row an RLS policy would otherwise deny,
     using that key directly.
  3. **`SECURITY DEFINER` function privilege-escalation probe.** Call the
     function with adversarial arguments and confirm whether it performs
     an operation the CALLING user's own privileges would not otherwise
     permit, applying [[access-control]]'s methodology to this specific
     Postgres mechanism.

  ## Proof Ladder

  Follow [[access-control]]'s own proof ladder — this skill supplies the
  Supabase-specific mechanisms (RLS, key model, `SECURITY DEFINER`) to
  reach it.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]]. RLS confirmed enabled on a table with a
  policy checking `auth.uid() = owner_id` (or an equivalent real ownership
  condition) on every operation is the control working correctly — confirm
  against the actual policy definition, not the application's own client-
  side query behavior. A found key confirmed to carry the `anon` role via
  its JWT payload (not `service_role`) is expected and intentionally
  public.

  ## Impact

  Direct, unmediated read/write access to any row via a missing or
  permissive RLS policy; full database bypass via a leaked `service_role`
  key; privilege escalation via an insufficiently validated `SECURITY
  DEFINER` function.

  ## Summary

  Check RLS enablement and policy definitions directly for every exposed
  table — a table's presence in the API is not evidence either way.
  Separately, always distinguish an `anon` key from a `service_role` key
  by its JWT payload before treating a found key as either benign or
  catastrophic.
  ```

- [ ] **Step 7: Verify all six load and are recallable**

  ```
  uv run pytest tests/lalo/test_skills_loader.py -v
  ```

  Expected: all PASS.

  ```
  uv run python -c "
  from lalo.skills.loader import load_skills
  from lalo.skills.recall import recall
  skills = load_skills()
  for q, expected in [
      ('auth0 rules actions account linking', 'auth0'),
      ('electron nodeintegration contextisolation', 'electron-desktop-apps'),
      ('firebase firestore security rules', 'firebase'),
      ('grafana prometheus data source proxy', 'grafana-prometheus'),
      ('llm rag tool calling agent', 'llm-applications'),
      ('supabase row level security service role key', 'supabase'),
  ]:
      results = recall(q, skills)
      assert results and results[0].skill.name == expected, (q, results)
  print('OK')
  "
  ```

  Expected: prints `OK`.

- [ ] **Step 8: Commit**

  ```bash
  git add src/lalo/skills/content/vulnerabilities/auth0.md src/lalo/skills/content/vulnerabilities/electron-desktop-apps.md src/lalo/skills/content/vulnerabilities/firebase.md src/lalo/skills/content/vulnerabilities/grafana-prometheus.md src/lalo/skills/content/vulnerabilities/llm-applications.md src/lalo/skills/content/vulnerabilities/supabase.md
  git commit -m "docs(skills): add Auth0/Electron/Firebase/Grafana-Prometheus/LLM-application/Supabase skills

Six technology-specific skills, each covering the mechanism that makes that
technology's own failure mode distinct from the generic classes it would
otherwise map to (access-control, ssrf, information-disclosure) - llm-
applications.md specifically covers application-architecture trust
boundaries (tool-calling validation, RAG corpus poisoning), distinct from
llm-prompt-injection.md's injection technique itself."
  ```

---

### Task 16: Recon, diff-scoped review, and supply-chain skills

**Files:**
- Create: `src/lalo/skills/content/methodology/asset-discovery.md`
- Create: `src/lalo/skills/content/methodology/infrastructure-lifecycle-trust.md`
- Create: `src/lalo/skills/content/methodology/diff-scoped-review.md`
- Create: `src/lalo/skills/content/vulnerabilities/npx-package-confusion.md`
- Test: none new — existing loader/structural tests cover all four automatically.

**Interfaces:** none — content only. `diff-scoped-review.md` cross-references
[[source-aware-review]] (general source review methodology; this is the
incremental/changed-surface-only variant of it).

- [ ] **Step 1: Write `asset-discovery.md`**

  ```markdown
  ---
  name: asset-discovery
  category: methodology
  description: Passive and semi-passive asset/subdomain discovery methodology — expanding the declared attack surface honestly, without exceeding the operator-declared engagement scope
  keywords: [asset discovery, subdomain enumeration, attack surface mapping, passive recon, osint]
  ---

  # Asset Discovery

  Before testing anything, establish what actually exists across the
  declared engagement's scope — a subdomain or service the operator never
  explicitly named but which resolves within an already-authorized wildcard
  scope rule is legitimately in scope; one that resolves to a genuinely
  different, undeclared host is not, no matter how it was found.

  ## Method, Cheapest First

  1. **Certificate-transparency lookups** for every declared root domain —
     the cheapest, fully passive source of subdomain names, requiring no
     traffic to the target at all.
  2. **DNS enumeration** via the `dns_query` tool against likely naming
     patterns and any names surfaced by certificate transparency — resolve
     each candidate and confirm it actually falls within an authorized
     scope rule (per the engagement's own wildcard/host rules) before
     treating it as in scope.
  3. **Passive third-party datasets** the free shell can query (a
     reverse-DNS/IP-history lookup, a search-engine-indexed subdomain
     listing) where reachable without violating the engagement's own
     no-third-party-service constraints, if any are stated.
  4. **Active service fingerprinting**, only once a candidate host is
     confirmed in scope — this is where `recon`'s existing port/service
     scanning methodology takes over; asset discovery's own job ends at
     "this host is in scope and exists," not at characterizing it.

  ## Scope Discipline

  A discovered asset is tested ONLY if it genuinely falls within an
  already-authorized engagement rule (an exact host match, or a subdomain
  matching an authorized wildcard) — discovery never expands scope on its
  own. A discovered host that looks related (a shared naming convention, a
  shared certificate) but does not actually match an authorized rule is
  reported as a NOTE for the operator's own awareness, never tested.

  ## Validation and False-Positive Discipline

  A hostname appearing in certificate-transparency logs does not mean it
  currently resolves or is currently in production use — confirm active
  DNS resolution before spending further effort on a candidate. A resolved
  host returning a generic parking-page/default-vhost response is a real,
  existing asset worth noting as low-priority, not a false positive to
  discard silently.

  ## Summary

  Passive sources first, active fingerprinting only after scope
  confirmation — and scope confirmation is never optional regardless of
  how a candidate was discovered.
  ```

- [ ] **Step 2: Write `infrastructure-lifecycle-trust.md`**

  ```markdown
  ---
  name: infrastructure-lifecycle-trust
  category: methodology
  description: Infrastructure-lifecycle trust gaps — dangling DNS records, decommissioned-but-still-trusted resources, and stale CI/CD deployment artifacts
  keywords: [dangling dns, subdomain takeover lifecycle, decommissioned infrastructure, stale deployment, orphaned resource]
  ---

  # Infrastructure Lifecycle Trust

  Infrastructure that was once legitimately provisioned and later
  decommissioned — without cleaning up every reference to it — is a
  recurring, high-value gap distinct from [[subdomain-takeover]]'s own
  narrower CNAME-to-deprovisioned-service technique: this is about the
  broader lifecycle (a DNS record, a firewall allowlist entry, a CI/CD
  deployment target, a trust relationship) outliving the resource it once
  pointed to.

  ## Attack Surface

  - A DNS record (not only a CNAME — an A record, an MX record, an NS
    delegation) pointing to an IP/service that has since been released
    back to a cloud provider's shared pool, reachable by re-claiming that
    same resource.
  - A firewall/security-group rule or an allowlist entry still trusting an
    IP range or identity that was reassigned after the original resource
    was decommissioned.
  - A CI/CD pipeline still configured to deploy to, or pull secrets from,
    an environment/target that no longer serves its original purpose but
    is still reachable and still holds valid credentials.
  - An old, still-resolving staging/demo subdomain running a stale,
    unpatched version of the application, discovered via
    [[asset-discovery]], that shares authentication/session infrastructure
    with production.

  ## Recon

  - For every discovered ([[asset-discovery]]) host/record, check whether
    it appears to serve its ORIGINAL purpose or something inconsistent
    with it (a "staging" or "demo"-named host serving a default cloud-
    provider landing page, or nothing at all) — this mismatch is the core
    signal for this whole class.
  - Where CI/CD configuration is accessible (a `.github/workflows`,
    `.gitlab-ci.yml`, or equivalent file, or a build history the target
    exposes), check deployment targets and referenced secrets/environments
    against what actually still exists.

  ## Techniques

  1. **Dangling-record reclamation check**, generalizing
     [[subdomain-takeover]]'s technique beyond CNAME-to-SaaS: for a record
     resolving to a cloud-provider-owned IP/resource, attempt to determine
     (via the provider's own documented resource-claiming mechanism, never
     by actually claiming a resource you do not control unless the
     engagement scope explicitly authorizes it) whether that specific
     resource is currently unclaimed and re-claimable.
  2. **Stale-staging-environment probe.** Test a discovered
     staging/demo/legacy host for a known vulnerability already patched in
     production, and separately check whether it shares session cookies,
     an auth token signing key, or a database with production — if so, a
     compromise there escalates directly to production impact.
  3. **CI/CD stale-target check.** Where visible, confirm whether a
     pipeline's configured deployment target or referenced secret is for a
     resource that still exists and is still under the operator's control.

  ## Proof Ladder

  - **L1** — a lifecycle mismatch identified (a record/config referencing
    something that looks decommissioned) but not yet confirmed exploitable.
  - **L2** — the referenced resource confirmed to no longer be under the
    expected owner's control (via a documented, non-destructive check),
    but no actual reclamation/exploitation attempted.
  - **L3** — the gap demonstrated with a benign proof (a claimed resource
    serving a benign marker page reachable via the dangling record; a
    stale staging environment's shared-credential exposure confirmed)
    within the authorized engagement scope — reportable.
  - **L4** — the gap chained to production impact (a shared signing key or
    session mechanism between a compromised stale environment and
    production, confirmed).

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]]. Never actually claim/register a
  third-party resource (a cloud IP, a SaaS subdomain slug) unless the
  engagement's own scope explicitly authorizes that specific action — most
  engagements do not, and the correct default is to demonstrate
  reclaimability via documentation/provider-tooling evidence rather than
  performing the claim. A record confirmed to still point to a resource
  genuinely under the operator's own control (even if the resource's
  PURPOSE looks outdated) is not a dangling-record finding.

  ## Impact

  Full subdomain/service takeover via a reclaimable dangling record;
  production compromise via a stale staging environment sharing
  credentials or signing keys with production; unauthorized deployment or
  secret exposure via a stale CI/CD target.

  ## Summary

  Look for the mismatch between what a record/config still claims and what
  actually exists today — this is the core signal. Never perform an actual
  third-party resource claim without explicit engagement authorization;
  demonstrate reclaimability through documented evidence instead.
  ```

- [ ] **Step 3: Write `diff-scoped-review.md`**

  ```markdown
  ---
  name: diff-scoped-review
  category: methodology
  description: Incremental, diff-scoped source review — prioritizing what actually changed since a known-good baseline, for a CI/PR-triggered or re-engagement scan
  keywords: [diff review, incremental scan, pull request review, changed files, regression scope]
  ---

  # Diff-Scoped Review

  [[source-aware-review]] covers reviewing source code in general; this
  skill covers the DISTINCT situation where a known-good baseline exists
  (a prior scan's own findings/coverage, or a specific commit/tag) and the
  actual task is to prioritize what CHANGED since then, rather than
  re-reviewing the entire codebase from scratch every time.

  ## When This Applies

  A mission explicitly scopes you to a diff (a specific commit range, a
  pull request, "changes since the last scan"), or a prior scan's own
  `baseline`/`coverage_ledger` entries are available for the same target
  identity and a re-engagement's real value is in what's new, not
  re-confirming what a prior pass already covered.

  ## Method

  1. **Establish the actual diff** — the specific commit range or file set
     that changed, via `run_command` (`git diff --name-only <base>..<head>`
     or equivalent) rather than assuming from a PR description alone,
     which can understate scope (a generated lockfile change, a config
     touched incidentally by a broader refactor).
  2. **Read the prior baseline first**, if one exists — call `baseline`
     (action=get) for this target's identity, and `coverage_ledger`
     (action=list) for what a prior pass already tested and its outcome.
     Never re-derive from scratch what a trustworthy prior pass already
     established; extend it.
  3. **Prioritize changed files by risk shape**: a change touching
     authentication/authorization logic, an input-handling boundary, a
     dependency version bump, or a new endpoint/route is high priority
     regardless of diff size; a change confined to styling, a comment, or
     test-only code is low priority — apply [[source-aware-review]]'s own
     "production code vs. test fixture" and "git-tracked vs. untracked"
     filters to each changed file before spending time tracing it.
  4. **Re-test any FINDING from the prior baseline whose code path was
     touched by the diff** — a fix, a refactor, or an unrelated change near
     a previously-reported finding's location all warrant a
     [[fix-verification-discipline]] pass even if the diff wasn't intended
     to be a fix.
  5. **File new findings and coverage entries exactly as any other scan
     would** — a diff-scoped scan produces the same `record_finding`/
     `coverage_ledger` output shape as a full scan; only the SELECTION of
     what to spend time on is different.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]] to every new candidate exactly as in a full
  scan — diff-scoping changes what you prioritize looking at, never how
  rigorously you validate what you find. A file appearing in the diff
  purely due to a mechanical reformat (confirm via the actual diff content,
  not just the file being listed) needs no security review at all.

  ## Summary

  Read the prior baseline and coverage ledger before doing any new work,
  establish the real diff via the actual git history rather than a
  description, and prioritize by risk shape rather than treating every
  changed line equally — but validate anything found with the exact same
  rigor a full scan would.
  ```

- [ ] **Step 4: Write `npx-package-confusion.md`**

  ```markdown
  ---
  name: npx-package-confusion
  category: vulnerability
  description: Package-runner supply-chain identity confusion — typosquatting, dependency confusion between public and private registries, and a per-class proof ladder
  keywords: [npx, package confusion, typosquatting, dependency confusion, supply chain, package runner]
  ---

  # Package-Runner / Dependency Confusion

  A package name alone is not proof of identity — `npx <name>`, `pip
  install <name>`, `go run <module>`, and similar package-runner
  invocations resolve a bare name against whatever registry/resolution
  order is configured, which an attacker can exploit if that resolution
  is ambiguous or misconfigured, distinct from
  [[dependency-cve-analysis]]'s own reachability-of-a-known-CVE concern.

  ## Attack Surface

  - Any CI/CD pipeline, build script, or onboarding/setup script invoking
    `npx <package>` (or an equivalent package-runner for another
    ecosystem) with a package name that has never been explicitly pinned
    to a specific registry/scope — `npx` in particular will silently
    install and run an arbitrary public-registry package if the named one
    isn't already cached locally.
  - Internal/private package names referenced from a public build
    configuration (a public GitHub Action, a public Dockerfile, a
    published error message or stack trace) without an explicit
    scope/registry pin — an attacker who identifies the internal name can
    publish an identically-named PUBLIC package, and dependency-resolution
    tools that check the public registry alongside or instead of the
    private one will resolve to the attacker's package (classic dependency
    confusion).
  - A typosquatted package name resembling a popular or internally-used
    one, reachable if a script or a developer's own command has a plausible
    typo path.

  ## Recon

  - Grep build scripts, CI/CD configuration, and Dockerfiles for
    `npx <name>`/`pip install <name>`/equivalent invocations with no
    explicit registry/version pin, and separately for any private/internal
    package name referenced from a file that is itself publicly visible
    (a public repo, a public container image, a public error page).
  - Check the package manager's actual configured resolution order (an
    `.npmrc`/`pip.conf`/equivalent) for whether a private registry is
    checked BEFORE the public one, and whether scoping (`@internal-org/`)
    is enforced consistently everywhere the package is referenced, not
    just in the primary application manifest.

  ## Techniques

  1. **Public-registry namesquat check (non-destructive).** Without
     actually publishing anything (publishing a real package under a
     victim's expected name is intrusive and outside this project's
     non-destructive testing discipline unless the engagement explicitly
     authorizes it), confirm whether the exact internal package name is
     CURRENTLY UNCLAIMED on the relevant public registry — an unclaimed
     name matching an internally-referenced one, combined with resolution
     configuration that would check the public registry, is itself a
     reportable finding without needing to actually claim it.
  2. **Resolution-order confirmation.** Where configuration access exists,
     directly confirm (read the actual `.npmrc`/equivalent, not just the
     application's `package.json`) whether a scoped or unscoped internal
     package name could resolve to a public-registry package under any
     realistic misconfiguration or missing-scope scenario.
  3. **Unpinned package-runner invocation check.** For each `npx`-style
     invocation with no explicit version/registry pin found in Recon,
     assess whether an attacker able to publish or update a public package
     under that exact name could have their code executed the next time
     that script runs.

  ## Proof Ladder

  - **L1** — an unpinned package-runner invocation or an internally-
    referenced package name visible from public-facing configuration
    identified, but registry resolution behavior not yet confirmed.
  - **L2** — the actual resolution order confirmed (via configuration
    read) to be exploitable in principle (would check/prefer the public
    registry for this name) but the target name confirmed still claimed
    privately/unclaimed publicly with no live exploitation attempted.
  - **L3** — the exact target package name confirmed CURRENTLY UNCLAIMED
    on the relevant public registry while still being referenced by a live
    build/CI process with resolution configuration that would prefer or
    fall through to it — reportable without an actual publish.
  - **L4** — with explicit engagement authorization only, an actual benign
    proof-of-concept package published and its execution in the target's
    own pipeline confirmed; never performed without that explicit,
    documented authorization given the third-party (public registry)
    impact involved.

  ## Validation and False-Positive Discipline

  Apply [[closure-discipline]]. A private package name confirmed to be
  correctly scoped (`@internal-org/name`, with the registry configuration
  confirmed to resolve that scope to the private registry exclusively, no
  fallback) closes this path even if the bare, unscoped name is
  technically unclaimed publicly. Never actually publish a real package
  under a victim-identical name without EXPLICIT engagement authorization
  — the default finding is the confirmed-unclaimed-name-plus-exploitable-
  resolution-order combination (L3), which is sufficient to report without
  that step.

  ## Impact

  Arbitrary code execution in a CI/CD pipeline, a developer's local
  environment, or a production build process via a confused/squatted
  package resolving to attacker-published code — often with the elevated
  access a CI/CD credential or build-time secret grants.

  ## Summary

  Registry resolution order and scope enforcement is the real control here
  — confirm the actual configuration, not just whether the current
  application manifest references the correct package. A confirmed-
  unclaimed name plus an exploitable resolution path is a reportable
  finding on its own, with no need to actually publish anything absent
  explicit engagement authorization.
  ```

- [ ] **Step 5: Verify all four load and are recallable**

  ```
  uv run pytest tests/lalo/test_skills_loader.py -v
  ```

  Expected: all PASS.

  ```
  uv run python -c "
  from lalo.skills.loader import load_skills
  from lalo.skills.recall import recall
  skills = load_skills()
  for q, expected in [
      ('subdomain discovery certificate transparency', 'asset-discovery'),
      ('dangling dns decommissioned infrastructure', 'infrastructure-lifecycle-trust'),
      ('diff scoped pull request review baseline', 'diff-scoped-review'),
      ('npx dependency confusion typosquat', 'npx-package-confusion'),
  ]:
      results = recall(q, skills)
      assert results and results[0].skill.name == expected, (q, results)
  print('OK')
  "
  ```

  Expected: prints `OK`.

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/skills/content/methodology/asset-discovery.md src/lalo/skills/content/methodology/infrastructure-lifecycle-trust.md src/lalo/skills/content/methodology/diff-scoped-review.md src/lalo/skills/content/vulnerabilities/npx-package-confusion.md
  git commit -m "docs(skills): add asset-discovery, infrastructure-lifecycle-trust, diff-scoped-review, and npx-package-confusion skills

Passive-first asset discovery with strict scope discipline; the broader
infrastructure-lifecycle-trust gap beyond subdomain-takeover's own CNAME
technique; an incremental diff-scoped review methodology building on the
new baseline/coverage_ledger tools; and package-runner/dependency-
confusion supply-chain identity confusion, distinct from
dependency-cve-analysis.md's known-CVE-reachability concern."
  ```

---

### Task 17: Workspace seed-at-creation for the runtime container

**Files:**
- Modify: `src/lalo/runtime/container.py` (`RuntimeContainer`)
- Test: `tests/lalo/test_runtime_container.py` (append)

**Interfaces:**
- Consumes: nothing.
- Produces: `RuntimeContainer.seed_files(files: dict[str, bytes], *, dest_dir: str |
  None = None) -> None`.

**Context, and the three smaller items deferred:** of the four small standalone
capability items originally grouped together (workspace-seed-at-creation, an
orchestrator-side remote-spec-fetch step, additional spec-driven-intake
improvements, per-tool-output spill-to-file on truncation), this is the one with the
clearest, smallest, most independently valuable scope: seeding a container's
workspace with pre-existing content (a spec file, a wordlist, a small script) at any
point after `start()`, via `docker cp` reading a tar stream from stdin — never a live
bind-mount, preserving this module's own one non-negotiable line. The other three are
deferred, not dropped: an orchestrator-side remote-spec-fetch step and further
spec-driven-intake improvements both depend on reading the current intake pipeline in
detail (a separate, real investigation this planning pass did not have scope to do
justice to), and per-tool-output spill-to-file is a genuine but low-priority precision
improvement to `agent/loop.py`'s existing truncation behavior, best done as its own
small follow-up task once this round's larger items have shipped and freed up review
bandwidth — cramming all four into one task risked under-specifying three of them
just to hit a number.

- [ ] **Step 1: Write the failing test**

  Add to `tests/lalo/test_runtime_container.py` (the file already has live-Docker-
  gated tests using `docker_available()` as a skip condition — reuse that pattern for
  a real integration test, plus one hermetic unit test for the tar-building logic
  that needs no Docker daemon at all):

  ```python
  import tarfile
  import io


  def test_seed_files_raises_when_container_not_started() -> None:
      container = RuntimeContainer()
      with pytest.raises(ContainerError, match="not started"):
          container.seed_files({"a.txt": b"hello"})


  @pytest.mark.skipif(not docker_available(), reason="requires a running docker daemon")
  def test_seed_files_writes_content_into_a_running_container() -> None:
      container = RuntimeContainer()
      container.start()
      try:
          container.seed_files({"spec.json": b'{"ok": true}', "sub/dir/note.txt": b"hi"})
          result = container.exec(f"cat {container.config.workdir}/spec.json")
          assert result.exit_code == 0
          assert '{"ok": true}' in result.stdout
          result2 = container.exec(f"cat {container.config.workdir}/sub/dir/note.txt")
          assert result2.exit_code == 0
          assert "hi" in result2.stdout
      finally:
          container.stop()
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_runtime_container.py -k seed_files -v
  ```

  Expected: FAIL — `RuntimeContainer` has no `seed_files` method (`AttributeError`).

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/runtime/container.py`, add to the imports:

  ```python
  import io
  import tarfile
  ```

  Add the method to `RuntimeContainer` (after `exec_streaming`, before `stop`):

  ```python
      def seed_files(self, files: dict[str, bytes], *, dest_dir: str | None = None) -> None:
          """Seed the container's workspace with pre-existing content at any
          point after start() - via ``docker cp`` reading a tar stream from
          stdin, never a live host bind-mount (this module's own one non-
          negotiable line, see its module docstring). ``files`` maps a
          relative path to its raw bytes; ``dest_dir`` defaults to this
          container's own configured workdir.
          """
          if not self._started:
              raise ContainerError("cannot seed files: container not started")
          dest = dest_dir or self.config.workdir
          buffer = io.BytesIO()
          with tarfile.open(fileobj=buffer, mode="w") as tar:
              for rel_path, content in files.items():
                  info = tarfile.TarInfo(name=rel_path)
                  info.size = len(content)
                  tar.addfile(info, io.BytesIO(content))
          try:
              result = subprocess.run(  # noqa: S603 - resolved binary; destination is this
                  # container's own workdir, and content is caller-supplied, not
                  # attacker-supplied network input.
                  [_docker_bin(), "cp", "-", f"{self._name}:{dest}"],
                  input=buffer.getvalue(),
                  capture_output=True,
                  timeout=30,
              )
          except subprocess.TimeoutExpired as exc:
              raise ContainerError(f"seeding files timed out: {exc}") from exc
          if result.returncode != 0:
              raise ContainerError(
                  f"seeding files failed: {result.stderr.decode(errors='replace').strip()}"
              )
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_runtime_container.py -k seed_files -v
  ```

  Expected: `test_seed_files_raises_when_container_not_started` PASSES immediately;
  `test_seed_files_writes_content_into_a_running_container` PASSES if a Docker daemon
  is available locally, SKIPPED otherwise (matching this file's own existing
  live-Docker-gated test convention).

- [ ] **Step 5: Run the full runtime-container suite to confirm no regression**

  ```
  uv run pytest tests/lalo/test_runtime_container.py -v
  ```

  Expected: all PASS (or skipped where Docker-gated).

- [ ] **Step 6: Commit**

  ```bash
  git add src/lalo/runtime/container.py tests/lalo/test_runtime_container.py
  git commit -m "feat(runtime): add seed_files for seeding a container's workspace post-start

Via docker cp reading a tar stream from stdin - never a live bind-mount,
preserving this module's one non-negotiable line. Lets an intake or spec-
driven-scan feature stage pre-existing content (a spec file, a wordlist)
into a running container's workspace without a host mount."
  ```

## Self-review

**Spec coverage:** §3.1 (Task 1: schema extensions) ✓. §3.2/coverage-adjacent SARIF
work (Tasks 2, 3, 4) ✓. §3.4 (Task 5: coverage ledger, reframed as an ordinary tool
per the corrected scope) ✓. §3.5 (Task 6: multi-agent lifecycle, reframed to a
smaller `background`/`wait_for_agents` shape per the corrected scope) ✓. §3.5's
passive-history item (Task 7) ✓. §3.6 (Task 8: baseline artifact) ✓. §3.7's
fix-verification methodology (Task 9) and dependency/SCA capability (Task 10) ✓.
§3.8's ~18 skill playbooks (Tasks 11–16, 19 files total, with GraphQL correctly
recorded as already covered rather than re-created) ✓. §3.9's smaller standalone
additions: workspace-seeding (Task 17) done; the other three explicitly deferred
with reasons in Task 17's own context note, not silently dropped.

**Placeholder scan:** no "TBD"/"TODO"/"add appropriate handling" anywhere above —
every step shows real code, real skill-file content, or an exact command.

**Type/signature consistency:** `Finding`'s new fields (Task 1) match
`FindingRecord`'s identical field set exactly (name and type), which Task 2's
`_build_fixes` and Task 3's `_coverage_results` both consume via the same
`FindingRecord` type. `AgentCoordinator.wait_for`'s return type
(`tuple[str, list[str], bool] | None`) matches `ChildRunner`'s existing return shape
exactly, and `wait_for_agents`' consumption of it (Task 6) unpacks the identical
3-tuple. `RequestHistory.record`'s parameters (Task 7) match `HttpFirer.fire`'s own
call signature (`method, url, headers, content`) so the wrapper in `fire()` passes
them through unchanged. `build_baseline_tool`/`build_coverage_ledger_tool` (Tasks 5,
8) both take `graph: ReachabilityGraph` as their first parameter, matching every
other `build_*_tool` function in the codebase (`build_record_finding_tool`,
`build_note_tool`, etc.).

