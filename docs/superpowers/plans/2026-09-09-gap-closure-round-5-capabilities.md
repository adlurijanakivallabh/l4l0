# Gap Closure Round 5 — Capabilities Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline
> execution, no subagent dispatch — operator's standing instruction this session).
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the capability-superset gaps found by a 13-way exhaustive function-level
read of a studied reference agent's real source, cross-checked against live L4L0 code —
honest-coverage positive assertions, report content richness, browser-auth parity,
runtime correctness/isolation hardening, doc-only methodology refinements, packaged
CI/CD integration, per-agent narrative log splitting, and LLM-call cancellation.

**Architecture:** Every task is additive: a new optional tool, a new optional field
(agent-authored, rendered deterministically — never invented at render time), a new
graph node kind, or a correctness/isolation hardening with no behavior change on the
success path. Nothing here is a gate, permission check, or default restriction.

**Tech Stack:** Python 3.13, pytest, stdlib only (`hashlib`, `threading`) except where a
task explicitly says otherwise (Playwright's own `storage_state` API, already a
dependency via `browser/session.py`).

**Spec:** `docs/superpowers/specs/2026-09-09-gap-closure-round-5-design.md`, Parts B1-B8.

## Global Constraints

- No CLI/TUI — Task 18 (B6, CI/CD) is a standalone script outside `src/lalo/` driving
  the existing GUI HTTP API non-interactively, never a new interactive command.
- No restrictions/gates of any kind — every mechanism below is additive capability or a
  correctness fix. `record_safe` (Task 1) never blocks anything; the runtime-hardening
  tasks (10-15) are self-checks/retries/classifications, never permission checks.
- No reference-project names in code/comments/docs/commit messages — generic phrasing
  ("a studied reference agent's own X"), per CLAUDE.md's clean-room policy. Re-verified
  via a full non-diff-scoped repo grep this session (commit `5e00aea`) — hold strictly.
- Agent-driven methodology stays primary — Task 16's doc-only additions are optional
  skill/prompt guidance the agent may apply, never a mandatory Python gate.
- Full non-live suite + `ruff check`/`ruff format --check` + `mypy` + reference-name-leak
  grep + `git fsck --full` after every task. Any GUI-visible change gets a live
  Playwright check before being called done (Tasks 6, 7, 9, 19 touch rendered
  markdown/html output an operator sees — verify the actual rendered page, not just the
  unit test, per this project's standing frontend-change convention).
- Every file path/signature below was read live from the current source this same
  session, immediately before this plan was written — where a task instructs "confirm
  against the live file first," that's a genuine remaining uncertainty flagged
  honestly, not a placeholder; resolve it by reading, never by guessing.

---

### Task 1: `record_safe` tool + `NodeKind.VERIFIED_SAFE`

**Files:**
- Modify: `src/lalo/graph/model.py` (`NodeKind` enum, add one member)
- Modify: `src/lalo/findings/tool.py` (new `build_record_safe_tool`, alongside the
  existing `build_record_finding_tool`)
- Modify: `src/lalo/scan.py`'s `_build_registry` (wire the new tool in, unconditionally —
  matches every other always-present tool like `record_finding`/`note`, not a
  role-gated one)
- Test: `tests/lalo/test_findings_tool.py` (append)

**Interfaces:**
- Consumes: `ReachabilityGraph.add_node(node_id: str, kind: NodeKind, **attrs) ->
  None` (existing).
- Produces: `NodeKind.VERIFIED_SAFE = "verified_safe"` (new enum member) —
  `build_coverage_summary` (Task 2) reads nodes of this kind. `build_record_safe_tool(graph:
  ReachabilityGraph) -> FunctionTool`, tool name `"record_safe"`.

- [ ] **Step 1: Write the failing test**

  First confirm `NodeKind`'s exact current members (verified this session:
  `ENDPOINT`/`PARAM`/`IDENTITY`/`SESSION`/`FINDING`/`EVIDENCE`/`FINGERPRINT`/`SERVICE`/`NOTE`)
  and `build_record_finding_tool`'s import/dispatch shape in `findings/tool.py` (the
  existing pattern: `FunctionTool(name=..., description=..., func=_record_finding)`
  returned from a `build_x_tool(graph) -> FunctionTool` factory) — `build_record_safe_tool`
  follows the identical shape.

  Append to `tests/lalo/test_findings_tool.py`:

  ```python
  def test_record_safe_lands_a_verified_safe_node_never_a_finding() -> None:
      graph = ReachabilityGraph()
      tool = build_record_safe_tool(graph)
      result = tool.run(
          {
              "vuln_class": "sql-injection",
              "target": "https://x.example.com/search",
              "param": "q",
              "defense_mechanism": "parameterized query confirmed via source read at app/db.py:42",
          }
      )
      assert result.ok is True
      (node_id,) = graph.nodes_of_kind(NodeKind.VERIFIED_SAFE)
      node = graph.node(node_id)
      assert node["vuln_class"] == "sql-injection"
      assert node["target"] == "https://x.example.com/search"
      assert node["param"] == "q"
      assert "parameterized query" in node["defense_mechanism"]
      # Never lands as (or alongside) a FINDING - this is evidence of absence,
      # not a vulnerability record, and must never be confused with one.
      assert graph.nodes_of_kind(NodeKind.FINDING) == []


  def test_record_safe_requires_vuln_class_target_and_defense_mechanism() -> None:
      graph = ReachabilityGraph()
      tool = build_record_safe_tool(graph)
      result = tool.run({"vuln_class": "sql-injection", "target": "https://x.example.com/"})
      assert result.ok is False
      assert "defense_mechanism" in result.observation


  def test_record_safe_target_is_redacted_the_same_way_record_finding_is() -> None:
      graph = ReachabilityGraph()
      tool = build_record_safe_tool(graph)
      tool.run(
          {
              "vuln_class": "sql-injection",
              "target": "https://x.example.com/reset?token=verysecrettoken1234567890",
              "defense_mechanism": "parameterized",
          }
      )
      (node_id,) = graph.nodes_of_kind(NodeKind.VERIFIED_SAFE)
      assert "verysecrettoken1234567890" not in graph.node(node_id)["target"]
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_findings_tool.py -k record_safe -v
  ```

  Expected: `ImportError: cannot import name 'build_record_safe_tool'` (collection
  failure) or, once the import is added but the function doesn't exist yet,
  `AttributeError`/`NameError` — the tool doesn't exist.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/graph/model.py`, add to `NodeKind` (after `SERVICE`, before `NOTE` — or
  after `NOTE`, matching whichever position reads better against the live enum's own
  ordering; confirm the exact live ordering first):

  ```python
      SERVICE = "service"
      # Evidence of absence-of-vulnerability: an agent specifically tested this
      # vuln_class/target/param and confirmed it's properly defended, with a
      # stated reason. Never a FINDING - this closes the "tested and clean" vs
      # "never looked" ambiguity CoverageSummary's own binary assessed/
      # not_assessed split can't express (see build_coverage_summary).
      VERIFIED_SAFE = "verified_safe"
      NOTE = "note"
  ```

  In `src/lalo/findings/tool.py`, add (near `build_record_finding_tool`, reusing its
  existing `safe_target_url`/`redact` imports):

  ```python
  def build_record_safe_tool(graph: ReachabilityGraph) -> FunctionTool:
      def _record_safe(args: dict[str, object]) -> ToolResult:
          vuln_class = str_arg(args, "vuln_class").strip()
          target_raw = str_arg(args, "target").strip()
          defense_mechanism = str_arg(args, "defense_mechanism").strip()
          if not vuln_class or not target_raw or not defense_mechanism:
              return ToolResult(
                  observation=(
                      "error: 'vuln_class', 'target', and 'defense_mechanism' are "
                      "all required"
                  ),
                  ok=False,
              )
          target = safe_target_url(target_raw)
          param = redact(str(args["param"])) if args.get("param") else None
          node_id = f"safe-{uuid.uuid4().hex[:12]}"
          graph.add_node(
              node_id,
              NodeKind.VERIFIED_SAFE,
              vuln_class=vuln_class,
              target=target,
              param=param,
              defense_mechanism=redact(defense_mechanism),
          )
          return ToolResult(
              observation=(
                  f"recorded {node_id}: {vuln_class} on {target} confirmed safe "
                  f"- {defense_mechanism}"
              )
          )

      return FunctionTool(
          name="record_safe",
          description=(
              "Record that you specifically tested a vulnerability class against a "
              "target/param and confirmed it's properly defended - evidence of "
              "absence, never a finding. Never required and never a gate on "
              "anything else you do; use it whenever you've genuinely verified a "
              "surface is clean, so the report can say so with a real reason "
              'instead of staying silent. args: {"vuln_class": str, "target": str, '
              '"param": str (optional), "defense_mechanism": str (required - why '
              "you believe this is safe, e.g. \"parameterized query confirmed via "
              'source read at app/db.py:42\")}'
          ),
          func=_record_safe,
      )
  ```

  (`str_arg`/`uuid` — confirm both are already imported at the top of `findings/tool.py`
  matching `build_record_finding_tool`'s own usage; add `import uuid` if not already
  present — `record_finding` already generates ids via `f"finding-{uuid.uuid4().hex[:12]}"`
  so `uuid` is almost certainly already imported.)

  In `src/lalo/scan.py`'s `_build_registry`, add the tool unconditionally alongside the
  existing `build_record_finding_tool(graph)`/`build_note_tool(graph)` calls (confirm the
  exact existing line by grepping `build_record_finding_tool(` in `scan.py` first):

  ```python
  tools.append(build_record_safe_tool(graph))
  ```

  and the import alongside the existing `from .findings.tool import build_record_finding_tool`:

  ```python
  from .findings.tool import build_record_finding_tool, build_record_safe_tool
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_findings_tool.py -v
  uv run pytest tests/lalo/test_scan.py -q
  ```

  Expected: all pass; the `test_scan.py` run is a non-breaking check that wiring a new
  always-present tool doesn't disturb any test asserting an exact tool-name list.

  ```
  uv run ruff check src/lalo/graph/model.py src/lalo/findings/tool.py src/lalo/scan.py tests/lalo/test_findings_tool.py
  uv run ruff format src/lalo/graph/model.py src/lalo/findings/tool.py src/lalo/scan.py tests/lalo/test_findings_tool.py
  uv run mypy src/lalo/graph/model.py src/lalo/findings/tool.py src/lalo/scan.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/graph/model.py src/lalo/findings/tool.py src/lalo/scan.py tests/lalo/test_findings_tool.py
  git commit -m "$(cat <<'EOF'
  feat(L4L0): record_safe tool for positive "tested and confirmed clean" evidence

  NodeKind.VERIFIED_SAFE + build_record_safe_tool let an agent assert it
  specifically tested a vuln_class/target/param and confirmed it's properly
  defended, with a required defense_mechanism reason - evidence of absence,
  never a FINDING, never a gate on anything else. Closes the highest-
  confidence gap from this round's research (surfaced independently across
  4 separate research chunks): CoverageSummary's binary assessed/
  not_assessed split can't distinguish "tested this, genuinely clean" from
  "nobody ever looked."

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 2: Coverage renders "assessed, clean" separately from "not assessed"

**Files:**
- Modify: `src/lalo/report/coverage.py` (`CoverageSummary`, `build_coverage_summary`)
- Modify: `src/lalo/report/markdown.py`, `src/lalo/report/html.py` (Coverage section
  rendering)
- Test: `tests/lalo/test_report_coverage.py`, and whichever files already test the
  Coverage section in markdown/html output (grep `Coverage` in `tests/lalo/`)

**Interfaces:**
- Consumes: `NodeKind.VERIFIED_SAFE` (Task 1), `ReachabilityGraph.nodes_of_kind(kind) ->
  list[str]` (existing).
- Produces: `CoverageSummary.verified_safe: list[str]` (new field — vuln_class names
  with at least one `VERIFIED_SAFE` node and no `FINDING`), plus
  `CoverageSummary.safe_reasons: dict[str, str]` (vuln_class -> the first
  `defense_mechanism` reason recorded for it, for direct rendering). Callers of
  `build_coverage_summary` unaffected — it gains an optional `graph: ReachabilityGraph
  | None = None` parameter (default `None` preserves every existing call site's exact
  current behavior with an empty `verified_safe`/`safe_reasons`).

- [ ] **Step 1: Write the failing test**

  First read `report/coverage.py` in full (already confirmed this session:
  `CoverageSummary(assessed: list[str], not_assessed: list[str])`,
  `build_coverage_summary(skills: list[Skill], records: list[FindingRecord]) ->
  CoverageSummary`) and confirm every existing call site of `build_coverage_summary`
  (grep `build_coverage_summary(` across `src/lalo/`) so the new optional `graph`
  parameter doesn't break any of them.

  Append to `tests/lalo/test_report_coverage.py` (reuse whichever `Skill`/`FindingRecord`
  construction helpers the file already has):

  ```python
  def test_a_vuln_class_with_only_a_verified_safe_node_is_assessed_and_clean() -> None:
      graph = ReachabilityGraph()
      graph.add_node("safe-1", NodeKind.VERIFIED_SAFE, vuln_class="sql-injection",
                      target="https://x.example.com/", param=None,
                      defense_mechanism="parameterized query, source-confirmed")
      skills = [_skill("sql-injection"), _skill("xss")]  # reuse existing helper
      summary = build_coverage_summary(skills, records=[], graph=graph)
      assert "sql-injection" in summary.verified_safe
      assert "sql-injection" not in summary.not_assessed
      assert "xss" in summary.not_assessed
      assert "parameterized" in summary.safe_reasons["sql-injection"]


  def test_a_class_with_both_a_finding_and_a_verified_safe_node_stays_assessed_not_safe() -> None:
      """A FINDING always wins - a class isn't "confirmed clean" if a real
      finding also exists for it (e.g. a different param on the same class)."""
      graph = ReachabilityGraph()
      graph.add_node("safe-1", NodeKind.VERIFIED_SAFE, vuln_class="sql-injection",
                      target="https://x.example.com/other", param=None,
                      defense_mechanism="parameterized")
      records = [_record(vuln_class="sql-injection")]  # reuse existing helper
      summary = build_coverage_summary([_skill("sql-injection")], records, graph=graph)
      assert "sql-injection" in summary.assessed
      assert "sql-injection" not in summary.verified_safe


  def test_build_coverage_summary_with_no_graph_behaves_exactly_as_before() -> None:
      summary = build_coverage_summary([_skill("sql-injection")], records=[])
      assert summary.verified_safe == []
      assert summary.safe_reasons == {}
      assert summary.not_assessed == ["sql-injection"]
  ```

  (`_skill`/`_record` — reuse this file's own existing zero-boilerplate helpers for
  building a minimal `Skill`/`FindingRecord`; adjust names to match whatever's actually
  there.)

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_report_coverage.py -v
  ```

  Expected: `TypeError: build_coverage_summary() got an unexpected keyword argument
  'graph'` — the parameter doesn't exist yet.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/report/coverage.py`:

  ```python
  @dataclass
  class CoverageSummary:
      assessed: list[str]
      not_assessed: list[str]
      # Vuln classes with a record_safe assertion and no FINDING - "tested
      # this, genuinely clean," distinct from "nobody ever looked" (the rest
      # of not_assessed). A class with BOTH a finding and a safe assertion
      # stays in `assessed`, never here - a real finding always wins.
      verified_safe: list[str] = field(default_factory=list)
      safe_reasons: dict[str, str] = field(default_factory=dict)

      @property
      def total_known_classes(self) -> int:
          return len(self.assessed) + len(self.not_assessed)


  def build_coverage_summary(
      skills: list[Skill],
      records: list[FindingRecord],
      *,
      graph: ReachabilityGraph | None = None,
  ) -> CoverageSummary:
      """Compare the skill library's vulnerability classes against filed findings
      (and, if `graph` is given, against record_safe assertions too)."""
      known = sorted(
          {skill.name.lower() for skill in skills if skill.category == SkillCategory.VULNERABILITY}
      )
      seen = {record.vuln_class.strip().lower() for record in records}
      safe_classes: dict[str, str] = {}
      if graph is not None:
          for node_id in graph.nodes_of_kind(NodeKind.VERIFIED_SAFE):
              node = graph.node(node_id)
              vuln_class = str(node.get("vuln_class", "")).strip().lower()
              if vuln_class and vuln_class not in safe_classes:
                  safe_classes[vuln_class] = str(node.get("defense_mechanism", ""))
      assessed = [name for name in known if name in seen]
      verified_safe = [name for name in known if name not in seen and name in safe_classes]
      not_assessed = [
          name for name in known if name not in seen and name not in safe_classes
      ]
      return CoverageSummary(
          assessed=assessed,
          not_assessed=not_assessed,
          verified_safe=verified_safe,
          safe_reasons={name: safe_classes[name] for name in verified_safe},
      )
  ```

  (Add `field` to the existing `from dataclasses import dataclass` import if not already
  present, and `from ..graph.model import NodeKind, ReachabilityGraph` — confirm these
  aren't already imported under different names first.)

  Wire the actual `graph` argument through from wherever `build_coverage_summary` is
  currently called in `scan.py`/`report/writer.py` (grep the real call site — it's
  already holding a `graph: ReachabilityGraph` in scope at that point, since it's the
  same graph `collect_findings(graph)` reads from).

  In `report/markdown.py`/`report/html.py`'s Coverage section rendering (confirm exact
  current text first — this session's own earlier work already rendered "Assessed: ... /
  Not assessed: ..." with a caveat sentence), add a third line only when
  `verified_safe` is non-empty:

  ```python
  if coverage.verified_safe:
      lines.append(f"**Assessed, confirmed clean:** {', '.join(coverage.verified_safe)}")
      for cls in coverage.verified_safe:
          lines.append(f"- *{cls}*: {coverage.safe_reasons[cls]}")
  ```

  (Match this project's own existing list-rendering style in whichever function already
  builds the Coverage section — read it first, adapt formatting to match exactly rather
  than inventing a new style.)

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_report_coverage.py -v
  uv run pytest tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py tests/lalo/test_scan.py -q
  ```

  ```
  uv run ruff check src/lalo/report/coverage.py src/lalo/report/markdown.py src/lalo/report/html.py tests/lalo/test_report_coverage.py
  uv run ruff format src/lalo/report/coverage.py src/lalo/report/markdown.py src/lalo/report/html.py tests/lalo/test_report_coverage.py
  uv run mypy src/lalo/report/coverage.py src/lalo/report/markdown.py src/lalo/report/html.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/report/coverage.py src/lalo/report/markdown.py src/lalo/report/html.py tests/lalo/test_report_coverage.py
  git commit -m "$(cat <<'EOF'
  feat(report): render "assessed, confirmed clean" coverage separately

  CoverageSummary gains verified_safe/safe_reasons, derived from record_safe
  (Task 1) assertions on the graph: a vuln_class with a safe assertion and
  no finding renders as "tested this, genuinely clean" with the agent's own
  stated reason, instead of the same "not assessed" bucket a never-tested
  class falls into. A class with both a finding and a safe assertion stays
  assessed, never safe - a real finding always wins.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 3: `Finding.prerequisites` and `Finding.impact` fields

**Files:**
- Modify: `src/lalo/findings/model.py` (`Finding` dataclass, both optional new fields)
- Modify: `src/lalo/findings/tool.py` (`_record_finding` reads both from `args`, threads
  onto the graph node and into `Finding(...)`)
- Modify: `src/lalo/report/collect.py` (`FindingRecord`, `collect_findings`)
- Modify: `src/lalo/report/markdown.py`, `src/lalo/report/html.py` (render both fields)
- Test: `tests/lalo/test_findings_model.py`, `tests/lalo/test_findings_tool.py`,
  `tests/lalo/test_report_collect.py`, `tests/lalo/test_report_markdown.py`

**Interfaces:**
- Produces: `Finding.prerequisites: str = ""`, `Finding.impact: str = ""`
  (`findings/model.py`); `FindingRecord.prerequisites: str = ""`, `FindingRecord.impact:
  str = ""` (`report/collect.py`) — both optional, agent-authored at `record_finding`
  time, never invented at render time.

- [ ] **Step 1: Write the failing test**

  Append to `tests/lalo/test_findings_tool.py` (reuse the existing `_file`-style helper
  pattern already in `test_report_sarif.py`/this file):

  ```python
  def test_record_finding_captures_prerequisites_and_impact() -> None:
      graph = ReachabilityGraph()
      ToolRegistry([build_record_finding_tool(graph)]).dispatch(
          "record_finding",
          {
              **_MINIMAL_VALID_ARGS,  # reuse this file's own existing minimal-args fixture
              "prerequisites": "none - publicly accessible endpoint",
              "impact": "full account takeover for any user whose email is known",
          },
      )
      (finding_id,) = graph.nodes_of_kind(NodeKind.FINDING)
      node = graph.node(finding_id)
      assert node["prerequisites"] == "none - publicly accessible endpoint"
      assert node["impact"] == "full account takeover for any user whose email is known"


  def test_record_finding_defaults_prerequisites_and_impact_to_empty_string() -> None:
      graph = ReachabilityGraph()
      ToolRegistry([build_record_finding_tool(graph)]).dispatch(
          "record_finding", _MINIMAL_VALID_ARGS
      )
      (finding_id,) = graph.nodes_of_kind(NodeKind.FINDING)
      node = graph.node(finding_id)
      assert node.get("prerequisites", "") == ""
      assert node.get("impact", "") == ""
  ```

  (`_MINIMAL_VALID_ARGS` — confirm this file's real existing fixture name for "the
  smallest valid `record_finding` args dict"; if none exists, use `test_report_sarif.py`'s
  own `_file`'s `args` dict as the template instead.)

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_findings_tool.py -k prerequisites_and_impact -v
  ```

  Expected: `KeyError: 'prerequisites'` — neither field exists on the graph node yet.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/findings/model.py`'s `Finding` dataclass, add both fields (after
  `source_location`, the current last field):

  ```python
      source_location: str | list[dict[str, str]] | None = None
      # Both optional (default ""), agent-authored at record_finding time -
      # what access/credentials an attacker needs before this is reachable,
      # and what an attacker can DO with it (business-consequence framed,
      # distinct from `description`'s "what the bug is"). Neither is required
      # -  an empty string renders as "(none stated)", matching every other
      # optional narrative field's own existing convention.
      prerequisites: str = ""
      impact: str = ""
  ```

  In `src/lalo/findings/tool.py`'s `_record_finding`, thread both through (reading them
  the same way every other optional string field like `counterevidence` already is —
  confirm the exact existing pattern first, likely `str(fields.get("prerequisites",
  ""))` given `validate_finding_fields`'s own required-vs-optional field handling):

  ```python
          prerequisites = redact(str(args.get("prerequisites", "")))
          impact = redact(str(args.get("impact", "")))
  ```

  and pass both into the `Finding(...)` constructor call and the new-node `attrs` dict
  (both places `source_location`/`finding.source_location` already appear — add
  `prerequisites`/`impact` alongside each, plus into the merge branch's `merge_fields`
  from Task 3 of the bugfix plan if that task landed first — confirm by reading the live
  merge branch before deciding whether to add these two fields there too; if the
  bugfix-plan Task 3 hasn't landed yet, just add them to the plain merge dict that
  exists today).

  Add both to the tool's own `description` string (the JSON-shape hint every
  `record_finding` caller reads), matching the existing style for `source_location`'s
  own optional-field documentation.

  In `src/lalo/report/collect.py`'s `FindingRecord`, add both fields (after
  `source_location`):

  ```python
      source_location: str | list[dict[str, str]] | None = None
      prerequisites: str = ""
      impact: str = ""
  ```

  and in `collect_findings`, read both off the node (after the existing
  `source_location=node.get("source_location")` line):

  ```python
              prerequisites=str(node.get("prerequisites", "")),
              impact=str(node.get("impact", "")),
  ```

  In `report/markdown.py`'s `render_finding_md` and `report/html.py`'s equivalent
  finding renderer, add both as their own labeled lines, positioned right after the
  existing `**Class:**`/severity block and before `### Description` (matching the
  reference-informed field-ordering the round-5 spec describes — Prerequisites/Impact
  read naturally right after the identifying/severity metadata, before the narrative
  sections):

  ```python
      if record.prerequisites:
          lines.append(f"**Prerequisites:** {record.prerequisites}")
      if record.impact:
          lines.append(f"**Impact:** {record.impact}")
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_findings_tool.py tests/lalo/test_findings_model.py tests/lalo/test_report_collect.py tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py -v
  ```

  ```
  uv run ruff check src/lalo/findings/model.py src/lalo/findings/tool.py src/lalo/report/collect.py src/lalo/report/markdown.py src/lalo/report/html.py
  uv run ruff format src/lalo/findings/model.py src/lalo/findings/tool.py src/lalo/report/collect.py src/lalo/report/markdown.py src/lalo/report/html.py
  uv run mypy src/lalo/findings/model.py src/lalo/findings/tool.py src/lalo/report/collect.py src/lalo/report/markdown.py src/lalo/report/html.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/findings/model.py src/lalo/findings/tool.py src/lalo/report/collect.py src/lalo/report/markdown.py src/lalo/report/html.py tests/lalo/test_findings_model.py tests/lalo/test_findings_tool.py tests/lalo/test_report_collect.py tests/lalo/test_report_markdown.py
  git commit -m "$(cat <<'EOF'
  feat(findings): optional Prerequisites/Impact fields, agent-authored

  Both optional (default ""), captured at record_finding time and rendered
  as their own labeled lines - Prerequisites states what access an attacker
  needs before this is reachable; Impact states what they can DO with it,
  kept distinct from description's "what the bug is." Pure schema + render
  additions, no new agent reasoning required at report time.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 4: `Finding.exploitation_steps` — numbered reproduction narration

**Files:**
- Modify: `src/lalo/findings/model.py`, `src/lalo/findings/tool.py`,
  `src/lalo/report/collect.py` (same three-file shape as Task 3)
- Modify: `src/lalo/report/markdown.py`, `src/lalo/report/html.py` (render above the
  existing raw-evidence blob list)
- Test: matching Task 3's test files

**Interfaces:**
- Produces: `Finding.exploitation_steps: list[str] = field(default_factory=list)`,
  `FindingRecord.exploitation_steps: list[str] = field(default_factory=list)`. Never
  replaces `evidence`/`evidence_excerpt` — `is_grounded()` keeps operating on those
  exactly as before; this is purely additive narration.

- [ ] **Step 1: Write the failing test**

  Append to `tests/lalo/test_findings_tool.py`:

  ```python
  def test_record_finding_captures_ordered_exploitation_steps() -> None:
      graph = ReachabilityGraph()
      ToolRegistry([build_record_finding_tool(graph)]).dispatch(
          "record_finding",
          {
              **_MINIMAL_VALID_ARGS,
              "exploitation_steps": [
                  "Authenticate as a low-privilege user via POST /login",
                  "Request GET /api/admin/users/1 directly with the low-priv session token",
              ],
          },
      )
      (finding_id,) = graph.nodes_of_kind(NodeKind.FINDING)
      node = graph.node(finding_id)
      assert node["exploitation_steps"] == [
          "Authenticate as a low-privilege user via POST /login",
          "Request GET /api/admin/users/1 directly with the low-priv session token",
      ]


  def test_record_finding_defaults_exploitation_steps_to_empty_list() -> None:
      graph = ReachabilityGraph()
      ToolRegistry([build_record_finding_tool(graph)]).dispatch(
          "record_finding", _MINIMAL_VALID_ARGS
      )
      (finding_id,) = graph.nodes_of_kind(NodeKind.FINDING)
      assert graph.node(finding_id).get("exploitation_steps", []) == []
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_findings_tool.py -k exploitation_steps -v
  ```

  Expected: `KeyError: 'exploitation_steps'`.

- [ ] **Step 3: Write minimal implementation**

  Same three-file pattern as Task 3. `Finding`/`FindingRecord` both get:

  ```python
      exploitation_steps: list[str] = field(default_factory=list)
  ```

  `findings/tool.py` reads it the same way `evidence` is already read as a list
  (`_as_evidence_list`-style coercion — reuse that helper if it's generic enough, or add
  a small `_as_str_list(args.get("exploitation_steps")) -> list[str]` mirroring its
  shape) and redacts each entry the same way evidence blobs already are:

  ```python
          exploitation_steps = [redact(str(s)) for s in args.get("exploitation_steps") or []]
  ```

  Thread into `Finding(...)`, the new-node `attrs` dict, and `FindingRecord`/
  `collect_findings` exactly like Task 3's two fields.

  In `report/markdown.py`/`report/html.py`, render as a numbered list positioned right
  above the existing `### Evidence` section (never replacing it):

  ```python
      if record.exploitation_steps:
          lines.append("### Exploitation Steps\n")
          lines.extend(
              f"{i}. {step}" for i, step in enumerate(record.exploitation_steps, start=1)
          )
          lines.append("")
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_findings_tool.py tests/lalo/test_findings_model.py tests/lalo/test_report_collect.py tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py -v
  ```

  ```
  uv run ruff check src/lalo/findings/model.py src/lalo/findings/tool.py src/lalo/report/collect.py src/lalo/report/markdown.py src/lalo/report/html.py
  uv run ruff format src/lalo/findings/model.py src/lalo/findings/tool.py src/lalo/report/collect.py src/lalo/report/markdown.py src/lalo/report/html.py
  uv run mypy src/lalo/findings/model.py src/lalo/findings/tool.py src/lalo/report/collect.py src/lalo/report/markdown.py src/lalo/report/html.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/findings/model.py src/lalo/findings/tool.py src/lalo/report/collect.py src/lalo/report/markdown.py src/lalo/report/html.py tests/lalo/test_findings_model.py tests/lalo/test_findings_tool.py tests/lalo/test_report_collect.py tests/lalo/test_report_markdown.py
  git commit -m "$(cat <<'EOF'
  feat(findings): optional ordered exploitation_steps narration

  Agent-authored ordered reproduction steps, rendered as a numbered list
  above the existing raw evidence blobs (which stay exactly as-is - this is
  additive narration, evidence-grounding still operates on evidence/
  evidence_excerpt unchanged).

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 5: Executive summary — confidence rollup + Critical Findings list

**Files:**
- Modify: `src/lalo/report/collect.py` (`ExecutiveSummary`, wherever it's built)
- Modify: `src/lalo/report/markdown.py`, `src/lalo/report/html.py`
- Test: `tests/lalo/test_report_collect.py`, markdown/html test files

**Interfaces:**
- Produces: `ExecutiveSummary.by_confidence: dict[str, int]` (keys `"high"`/`"medium"`/
  `"low"`, bucketed from `FindingRecord.confidence.score`: High ≥ 80, Medium ≥ 50, Low <
  50 — matching `findings/confidence.py`'s existing 0-100 scale), `ExecutiveSummary.
  critical_findings: list[str]` (titles where `effective_severity == "critical"`). Pure
  aggregation over already-collected records — zero new agent-facing surface.

- [ ] **Step 1: Write the failing test**

  First find the exact function that builds `ExecutiveSummary` today (grep
  `ExecutiveSummary(` in `report/collect.py` — likely a `build_executive_summary(records:
  list[FindingRecord]) -> ExecutiveSummary` alongside `collect_findings`/
  `build_coverage_summary`; confirm the real name).

  Append to `tests/lalo/test_report_collect.py`:

  ```python
  def test_executive_summary_buckets_by_confidence_band() -> None:
      records = [
          _record(confidence_score=90),  # reuse this file's own record-builder helper
          _record(confidence_score=60),
          _record(confidence_score=20),
      ]
      summary = build_executive_summary(records)
      assert summary.by_confidence == {"high": 1, "medium": 1, "low": 1}


  def test_executive_summary_lists_critical_finding_titles() -> None:
      records = [
          _record(title="Unauth RCE via SSTI", display_severity="critical"),
          _record(title="Reflected XSS", display_severity="medium"),
      ]
      summary = build_executive_summary(records)
      assert summary.critical_findings == ["Unauth RCE via SSTI"]
  ```

  (`_record`'s exact keyword-argument shape — confirm by reading this test file's own
  existing helper; it must already support setting a title/severity/confidence somehow
  since other existing tests in this file exercise `by_severity`/`by_vuln_class`.)

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_report_collect.py -k "by_confidence_band or critical_finding_titles" -v
  ```

  Expected: `AttributeError: 'ExecutiveSummary' object has no attribute 'by_confidence'`.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/report/collect.py`:

  ```python
  @dataclass
  class ExecutiveSummary:
      total_findings: int
      by_severity: dict[str, int]
      by_vuln_class: dict[str, int]
      highest_severity: str | None
      by_confidence: dict[str, int] = field(default_factory=dict)
      critical_findings: list[str] = field(default_factory=list)
  ```

  In whichever function builds it (confirmed name from Step 1), add the two
  computations alongside the existing severity/vuln_class tallies:

  ```python
      by_confidence: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
      for record in records:
          score = record.confidence.score
          band = "high" if score >= 80 else "medium" if score >= 50 else "low"
          by_confidence[band] += 1
      critical_findings = [
          record.title for record in records if record.effective_severity == "critical"
      ]
  ```

  and thread both into the `ExecutiveSummary(...)` construction.

  In `report/markdown.py`/`report/html.py`'s Executive Summary section (find the
  existing `**By severity:**`/`**By category:**` lines), add:

  ```python
      if summary.by_confidence:
          conf_line = ", ".join(f"{band}: {count}" for band, count in summary.by_confidence.items() if count)
          if conf_line:
              lines.append(f"**By confidence:** {conf_line}")
      if summary.critical_findings:
          lines.append("**Critical Findings:**")
          lines.extend(f"- {title}" for title in summary.critical_findings)
  ```

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_report_collect.py tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py -v
  ```

  ```
  uv run ruff check src/lalo/report/collect.py src/lalo/report/markdown.py src/lalo/report/html.py
  uv run ruff format src/lalo/report/collect.py src/lalo/report/markdown.py src/lalo/report/html.py
  uv run mypy src/lalo/report/collect.py src/lalo/report/markdown.py src/lalo/report/html.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/report/collect.py src/lalo/report/markdown.py src/lalo/report/html.py tests/lalo/test_report_collect.py
  git commit -m "$(cat <<'EOF'
  feat(report): executive summary confidence rollup + Critical Findings list

  Pure aggregation over already-collected FindingRecords, zero new agent-
  facing surface: a High/Medium/Low confidence-band count alongside the
  existing severity/category breakdown, and a top-of-report shortlist of
  critical-severity finding titles.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 6: Findings-Overview master table

**Files:**
- Modify: `src/lalo/report/markdown.py`, `src/lalo/report/html.py`
- Test: `tests/lalo/test_report_markdown.py`, `tests/lalo/test_report_html.py`

**Interfaces:**
- Consumes: `list[FindingRecord]` (existing, already available at the point
  `render_report_md`/`render_report_html` iterate records into detail sections).
- Produces: no new data type — a pure render addition.

- [ ] **Step 1: Write the failing test**

  Append to `tests/lalo/test_report_markdown.py`:

  ```python
  def test_render_report_md_includes_a_findings_overview_table() -> None:
      records = [_record(finding_id="finding-1", title="SQLi", vuln_class="sql-injection")]
      rendered = render_report_md(records, _coverage(), summary=_summary(records))
      assert "## Findings Overview" in rendered
      assert "| finding-1 | SQLi | sql-injection |" in rendered.replace("  ", " ") or (
          "finding-1" in rendered and "SQLi" in rendered
      )
  ```

  (Loosen the exact table-formatting assertion to whatever this project's own markdown
  table style actually produces once written — the meaningful assertion is that a
  scannable table section exists near the top, listing every finding's id/title/class,
  not the exact whitespace.)

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_report_markdown.py -k findings_overview -v
  ```

  Expected: `"## Findings Overview" not in rendered`.

- [ ] **Step 3: Write minimal implementation**

  In `render_report_md`, insert a new section right before the existing `## Findings\n`
  header (so it reads as an index before the verdict-grouped detail sections):

  ```python
      if records:
          lines.append("## Findings Overview\n")
          lines.append("| ID | Title | Class | Severity | Confidence |")
          lines.append("|---|---|---|---|---|")
          for record in records:
              lines.append(
                  f"| [{record.finding_id}](#{record.finding_id}) | {record.title} | "
                  f"{record.vuln_class} | {record.effective_severity.upper()} | "
                  f"{record.confidence.score} |"
              )
          lines.append("")
  ```

  (The `#{record.finding_id}` anchor already exists — `render_finding_md` emits `<a
  id="{record.finding_id}"></a>` per finding, confirmed this session — so this table's
  links land correctly with zero new anchor plumbing.)

  Mirror the equivalent HTML table in `report/html.py`'s own section-building function,
  matching its existing `<table>` styling conventions (find an existing `<table>` block
  in that file — e.g. the stat-chips or a coverage table — and match its class/CSS
  usage rather than inventing new styling).

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py -v
  ```

  ```
  uv run ruff check src/lalo/report/markdown.py src/lalo/report/html.py
  uv run ruff format src/lalo/report/markdown.py src/lalo/report/html.py
  uv run mypy src/lalo/report/markdown.py src/lalo/report/html.py
  ```

  Live-verify: generate a report against a run with 2+ findings (a fixture or a real
  live run) and open the HTML output in a browser to confirm the table actually renders
  and its links jump to the right finding section.

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/report/markdown.py src/lalo/report/html.py tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py
  git commit -m "$(cat <<'EOF'
  feat(report): a Findings-Overview master table before the detail sections

  One row per finding (id/title/class/severity/confidence), linking to each
  finding's existing anchor - a scannable index a reader hits before the
  verdict-grouped detail sections, replacing the under-serving anchor-link
  list as the report's top-level navigation.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 7: Attack-surface/recon report section

**Files:**
- Modify: `src/lalo/report/collect.py` (new `AttackSurfaceSummary` + a builder reading
  the graph directly), `src/lalo/report/markdown.py`, `src/lalo/report/html.py`,
  `src/lalo/report/writer.py` (thread the graph-derived summary through)
- Test: `tests/lalo/test_report_collect.py`, markdown/html test files

**Interfaces:**
- Consumes: `ReachabilityGraph.nodes_of_kind(NodeKind.ENDPOINT | SERVICE | FINGERPRINT)`
  (existing) — reads data `recon/facts.py`'s `merge_facts()` gate already captures.
- Produces: `AttackSurfaceSummary` (new frozen dataclass in `report/collect.py`:
  `endpoints: list[str]`, `services: list[str]`, `fingerprints: list[str]`), a new
  `build_attack_surface_summary(graph: ReachabilityGraph) -> AttackSurfaceSummary`.
  `write_report` gains an optional `attack_surface: AttackSurfaceSummary | None = None`
  parameter (default `None` — a caller that doesn't pass it renders no new section,
  preserving every existing call site's exact output).

- [ ] **Step 1: Write the failing test**

  First confirm `ENDPOINT`/`SERVICE`/`FINGERPRINT` node attribute shapes by reading
  `graph/model.py` and whatever code currently creates them (`recon/facts.py`'s
  `merge_facts`) — confirm what identifying attribute each carries (e.g. an `ENDPOINT`
  node likely has a `path`/`method` or is keyed by URL as its own node id; a `SERVICE`
  node likely carries `port`/`name`; a `FINGERPRINT` node likely carries a
  `technology`/`version` string) before writing the summary builder, since guessing
  wrong attribute names here would silently produce an empty section.

  Append to `tests/lalo/test_report_collect.py`:

  ```python
  def test_build_attack_surface_summary_reads_endpoints_services_fingerprints() -> None:
      graph = ReachabilityGraph()
      # Use the SAME node-construction shape recon/facts.py's own merge_facts
      # actually uses - confirmed by reading that file first, adjust the
      # kwargs below to match its real attribute names exactly.
      graph.add_node("https://x.example.com/api/users", NodeKind.ENDPOINT, method="GET")
      graph.add_node("service-1", NodeKind.SERVICE, name="nginx", port=443)
      graph.add_node("fp-1", NodeKind.FINGERPRINT, technology="Express", version="4.18")

      summary = build_attack_surface_summary(graph)
      assert any("api/users" in e for e in summary.endpoints)
      assert any("nginx" in s for s in summary.services)
      assert any("Express" in f for f in summary.fingerprints)
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_report_collect.py -k attack_surface -v
  ```

  Expected: `ImportError: cannot import name 'build_attack_surface_summary'`.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/report/collect.py`:

  ```python
  @dataclass(frozen=True)
  class AttackSurfaceSummary:
      """Recon-level facts, independent of any specific finding - what was
      actually probed, so a tested-but-clean surface is visible in the
      delivered report rather than only ever showing up if it produced a
      finding."""

      endpoints: list[str]
      services: list[str]
      fingerprints: list[str]


  def build_attack_surface_summary(graph: ReachabilityGraph) -> AttackSurfaceSummary:
      endpoints = sorted(graph.nodes_of_kind(NodeKind.ENDPOINT))
      services = []
      for node_id in graph.nodes_of_kind(NodeKind.SERVICE):
          node = graph.node(node_id)
          name = node.get("name", node_id)
          port = node.get("port")
          services.append(f"{name}:{port}" if port else str(name))
      fingerprints = []
      for node_id in graph.nodes_of_kind(NodeKind.FINGERPRINT):
          node = graph.node(node_id)
          tech = node.get("technology", node_id)
          version = node.get("version")
          fingerprints.append(f"{tech} {version}" if version else str(tech))
      return AttackSurfaceSummary(
          endpoints=endpoints, services=sorted(services), fingerprints=sorted(fingerprints)
      )
  ```

  (Adjust the exact attribute-name lookups — `name`/`port`/`technology`/`version` — to
  match whatever `recon/facts.py`'s real node-construction code actually sets, confirmed
  in Step 1; the shape above is a reasonable best guess pending that confirmation, not a
  final answer to copy blindly.)

  Thread `attack_surface` through `write_report`'s signature and into
  `render_report_md`/`render_report_html`, rendering a new `## Attack Surface` section
  (endpoints/services/fingerprints as three short bulleted lists) positioned after
  Coverage and before Findings — independent of any specific finding, matching the
  spec's own framing. In `scan.py`, pass `attack_surface=build_attack_surface_summary(graph)`
  at the existing `write_report(...)` call site.

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_report_collect.py tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py tests/lalo/test_scan.py -v
  ```

  ```
  uv run ruff check src/lalo/report/collect.py src/lalo/report/markdown.py src/lalo/report/html.py src/lalo/report/writer.py src/lalo/scan.py
  uv run ruff format src/lalo/report/collect.py src/lalo/report/markdown.py src/lalo/report/html.py src/lalo/report/writer.py src/lalo/scan.py
  uv run mypy src/lalo/report/collect.py src/lalo/report/markdown.py src/lalo/report/html.py src/lalo/report/writer.py src/lalo/scan.py
  ```

  Live-verify the rendered HTML section against a real run with recon facts on the
  graph.

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/report/collect.py src/lalo/report/markdown.py src/lalo/report/html.py src/lalo/report/writer.py src/lalo/scan.py tests/lalo/test_report_collect.py tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py
  git commit -m "$(cat <<'EOF'
  feat(report): a dedicated Attack Surface section, independent of findings

  Surfaces what recon/facts.py's merge_facts() gate already captured
  (endpoints/services/fingerprints) as its own report section - previously
  this data existed only on the graph and never reached the delivered
  report unless it happened to also produce a finding.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 8: Render branches on `FindingRecord.reproduced`

**Files:**
- Modify: `src/lalo/report/markdown.py`, `src/lalo/report/html.py`
- Test: `tests/lalo/test_report_markdown.py`, `tests/lalo/test_report_html.py`

**Interfaces:** consumes `FindingRecord.reproduced: bool` (existing, already captured);
no new field.

- [ ] **Step 1: Write the failing test**

  Append to `tests/lalo/test_report_markdown.py`:

  ```python
  def test_render_finding_md_labels_exploitation_section_only_when_reproduced() -> None:
      reproduced = render_finding_md(_record(reproduced=True))
      not_reproduced = render_finding_md(_record(reproduced=False))
      assert "### Exploitation" in reproduced or "### Exploitation Steps" in reproduced
      assert "### Analysis" in not_reproduced
      assert "### Exploitation" not in not_reproduced
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_report_markdown.py -k labels_exploitation -v
  ```

  Expected: fails — today's `render_finding_md` renders identical section labels
  regardless of `reproduced`.

- [ ] **Step 3: Write minimal implementation**

  In `render_finding_md` (and the HTML equivalent), find the current unconditional
  section header used ahead of the Evidence/exploitation-steps block and branch it:

  ```python
      lines.append("### Exploitation Steps" if record.reproduced else "### Analysis")
      lines.append("")
  ```

  (Confirm the exact current heading text/position before changing it — this must not
  disturb Task 4's own `### Exploitation Steps` heading added just above the Evidence
  section; if Task 4 already landed, reconcile so there's exactly one such heading, not
  two competing ones — likely resolved by having Task 4's own steps-list heading double
  as this branch point, i.e. this task's real diff is renaming Task 4's always-present
  "### Exploitation Steps" heading to read "### Analysis" specifically when `not
  record.reproduced`, rather than adding a second, separate heading.)

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py -v
  ```

  ```
  uv run ruff check src/lalo/report/markdown.py src/lalo/report/html.py
  uv run ruff format src/lalo/report/markdown.py src/lalo/report/html.py
  uv run mypy src/lalo/report/markdown.py src/lalo/report/html.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/report/markdown.py src/lalo/report/html.py tests/lalo/test_report_markdown.py tests/lalo/test_report_html.py
  git commit -m "$(cat <<'EOF'
  feat(report): render section labels branch on reproduced

  A finding's own already-captured reproduced flag now changes its section
  label (Exploitation Steps vs. Analysis) - pure render-logic, the
  underlying data already existed.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 9: Browser session storage-state reuse + fingerprint hardening

**Files:**
- Modify: `src/lalo/browser/session.py` (`BrowserSession`)
- Test: `tests/lalo/test_browser_session.py` (or wherever `BrowserSession` is currently
  tested — grep first)

**Interfaces:**
- Produces: `BrowserSession.export_storage_state() -> dict[str, object]`,
  `BrowserSession.import_storage_state(state: dict[str, object]) -> None` (both thin
  wrappers over Playwright's own `context.storage_state()`/
  `browser.new_context(storage_state=...)`). `_ensure_started` gains a stronger stealth
  profile (UA/viewport/locale) — behavior change to an already-existing private method,
  no signature change.

- [ ] **Step 1: Write the failing test**

  First read `browser/session.py` in full to confirm exactly how `_page`/`_browser`
  are constructed today (already confirmed this session: `self._browser =
  self._playwright.chromium.launch(...)`, `self._page = self._browser.new_page()` — no
  intermediate `context` object is held today, since `new_page()` implicitly creates a
  default context). Storage-state export/import needs an explicit `BrowserContext`
  object to call `.storage_state()`/pass `storage_state=` into — this is a real,
  necessary internal restructuring (`self._browser.new_context(...)` +
  `context.new_page()` instead of `self._browser.new_page()` directly), not just two new
  methods bolted on.

  Check whichever test file already covers `BrowserSession` for its existing
  Playwright-mocking pattern (a fake `chromium`/`browser`/`page` object structure) and
  extend it with a fake `context` object exposing `.storage_state()` returning a fixed
  dict and accepting `new_page()`.

  ```python
  def test_export_then_import_storage_state_reuses_the_same_context_shape(monkeypatch) -> None:
      # Use this file's own existing Playwright-mocking fixture/pattern -
      # confirm its real name and shape before writing this test body.
      session = BrowserSession(_scope())
      session.navigate("https://example.com/")  # starts the session
      state = session.export_storage_state()
      assert isinstance(state, dict)

      session2 = BrowserSession(_scope())
      session2.import_storage_state(state)
      session2.navigate("https://example.com/")  # must not raise
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_browser_session.py -k storage_state -v
  ```

  Expected: `AttributeError: 'BrowserSession' object has no attribute 'export_storage_state'`.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/browser/session.py`:

  ```python
  class BrowserSession:
      def __init__(self, scope: ScopeGuard) -> None:
          self._scope = scope
          self._playwright: Playwright | None = None
          self._browser: object | None = None
          self._context: object | None = None
          self._page: object | None = None
          self._pending_storage_state: dict[str, object] | None = None

      def import_storage_state(self, state: dict[str, object]) -> None:
          """Reuse a previously-exported authenticated session (cookies +
          localStorage) - must be called BEFORE the first navigate()/
          _ensure_started(), since Playwright only accepts storage_state at
          context-creation time. Lets one browser-driven login be captured
          once (a preflight step, or a prior BrowserSession) and reused
          across every agent that needs the same authenticated session,
          mirroring SessionRegistry's existing reuse-across-agents shape for
          HTTP/JSON logins."""
          if self._context is not None:
              raise RuntimeError(
                  "import_storage_state() must be called before the session starts"
              )
          self._pending_storage_state = state

      def export_storage_state(self) -> dict[str, object]:
          page = self._ensure_started()
          return self._context.storage_state()  # type: ignore[attr-defined,union-attr]

      def _ensure_started(self) -> object:
          if self._page is None:
              self._playwright = sync_playwright().start()
              self._browser = self._playwright.chromium.launch(
                  headless=True,
                  args=["--disable-blink-features=AutomationControlled"],
                  ignore_default_args=["--enable-automation"],
              )
              context_kwargs: dict[str, object] = {
                  "viewport": {"width": 1920, "height": 1080},
                  "locale": "en-US",
                  "user_agent": (
                      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
                  ),
                  "extra_http_headers": {"Accept-Language": "en-US,en;q=0.9"},
              }
              if self._pending_storage_state is not None:
                  context_kwargs["storage_state"] = self._pending_storage_state
              self._context = self._browser.new_context(**context_kwargs)  # type: ignore[attr-defined]
              self._page = self._context.new_page()  # type: ignore[attr-defined]
              self._page.add_init_script(_STEALTH_INIT_SCRIPT)
          return self._page
  ```

  Strengthen `_STEALTH_INIT_SCRIPT`'s existing plugin spoof (find the current
  `plugins` override — confirmed this session it's a bare `[1,2,3,4,5]` numeric array)
  to realistic named plugin objects, e.g.:

  ```javascript
  Object.defineProperty(navigator, 'plugins', {
    get: () => [
      { name: 'PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
      { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
      { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
    ],
  });
  ```

  (Read the exact current `_STEALTH_INIT_SCRIPT` string in full first and replace only
  the plugins block, preserving the existing `navigator.webdriver`/`chrome.runtime`
  overrides unchanged.)

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_browser_session.py -v
  ```

  ```
  uv run ruff check src/lalo/browser/session.py tests/lalo/test_browser_session.py
  uv run ruff format src/lalo/browser/session.py tests/lalo/test_browser_session.py
  uv run mypy src/lalo/browser/session.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/browser/session.py tests/lalo/test_browser_session.py
  git commit -m "$(cat <<'EOF'
  feat(browser): storage-state export/import for cross-agent session reuse

  BrowserSession now creates an explicit context (needed for storage_state
  access) instead of relying on new_page()'s implicit default context, and
  gains export_storage_state()/import_storage_state() so a captured
  authenticated session can be reused across agents - the browser-driven
  analog of SessionRegistry's existing HTTP/JSON login reuse. Also
  hardened the existing stealth init script's plugin spoof (real named
  plugin objects instead of bare numbers) and added a fixed desktop
  UA/viewport/locale, matching a studied reference agent's own stealth
  profile.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 10: Browser-driven login preflight

**Files:**
- Modify: `src/lalo/identity/login.py` (`LoginScheme` — a new opt-in browser-driven
  variant), `src/lalo/scan.py` (`_preflight_logins` or wherever preflight login checks
  run)
- Test: `tests/lalo/test_identity_login.py`, `tests/lalo/test_scan.py`

**Interfaces:**
- Consumes: `BrowserSession.export_storage_state()`/`.navigate()` (Task 9).
- Produces: `LoginScheme` gains optional fields for a browser-driven flow: `browser_url:
  str | None = None` (the login page to navigate to), `success_url_contains: str | None
  = None` (a real, checkable success condition — a URL substring the page must reach
  post-login, never "the agent said so"). A `LoginScheme` with `browser_url` set is
  treated as browser-driven; one without it behaves exactly as every existing HTTP/JSON
  scheme does today, zero change to that path.

- [ ] **Step 1: Write the failing test**

  First read `identity/login.py`'s `LoginScheme`/`login()`/`SessionRegistry` in full
  (already confirmed this session: `LoginScheme` has `login_url`, `method`,
  `body_encoding`, `username_field`, `password_field`, `session_source`,
  `session_field`, `totp_secret`, `totp_field` — no browser-related field exists yet)
  and `scan.py`'s `_preflight_logins` (grep for it) to see its exact current per-scheme
  dispatch loop.

  Append to `tests/lalo/test_identity_login.py`:

  ```python
  def test_login_scheme_with_no_browser_url_is_unaffected() -> None:
      scheme = LoginScheme(login_url="https://x.example.com/login")
      assert scheme.browser_url is None
      assert scheme.success_url_contains is None
  ```

  Append a preflight-level test to `tests/lalo/test_scan.py` (or wherever
  `_preflight_logins` already has coverage — grep first) exercising a scheme with
  `browser_url` set, asserting the preflight step navigates via `BrowserSession` and
  fails the preflight (raising `LoginFailedError`, matching the existing
  `fail_on_broken_login` semantics) when the resulting page's URL never contains
  `success_url_contains`.

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_identity_login.py -k browser_url -v
  ```

  Expected: `TypeError: LoginScheme.__init__() got an unexpected keyword argument
  'browser_url'`.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/identity/login.py`'s `LoginScheme`:

  ```python
      totp_field: str = "otp"
      # Opt-in browser-driven login, for SSO/SPA flows the mechanical
      # form/JSON model above can't express. A scheme with browser_url set
      # is driven through BrowserSession instead of a direct HTTP POST;
      # success_url_contains is a REAL, checkable condition (never "the
      # agent said so") - the preflight step below refuses to trust a
      # browser-driven login without one.
      browser_url: str | None = None
      success_url_contains: str | None = None
  ```

  In `scan.py`'s preflight-login step (the exact function/loop identified in Step 1),
  add a branch: for a scheme with `browser_url` set, drive `self._browser` (the same
  shared `BrowserSession` every other browser tool call already uses) through
  `navigate(scheme.browser_url)`, then whatever minimal form-fill/submit is needed
  (confirm from the live `BrowserSession`/`browser/tool.py` API what interaction
  primitives already exist — `click`/`fill`, if present — rather than inventing new
  ones), then verify the resulting page URL contains `success_url_contains` before
  calling `browser.export_storage_state()` and importing it into the shared session for
  reuse by every subsequent agent. On a failed verification, raise `LoginFailedError`
  exactly like the existing HTTP-login preflight failure path does, so
  `fail_on_broken_login`'s existing advisory-vs-hard-stop semantics apply identically.

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_identity_login.py tests/lalo/test_scan.py -v
  ```

  ```
  uv run ruff check src/lalo/identity/login.py src/lalo/scan.py tests/lalo/test_identity_login.py
  uv run ruff format src/lalo/identity/login.py src/lalo/scan.py tests/lalo/test_identity_login.py
  uv run mypy src/lalo/identity/login.py src/lalo/scan.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/identity/login.py src/lalo/scan.py tests/lalo/test_identity_login.py tests/lalo/test_scan.py
  git commit -m "$(cat <<'EOF'
  feat(identity): opt-in browser-driven login preflight for SSO/SPA flows

  LoginScheme.browser_url/success_url_contains let a scheme that can't be
  expressed as a direct HTTP POST (SSO, SPA logins) get the same
  preflight-verify-before-mission-budget treatment the mechanical
  form/JSON model already has - driven through the shared BrowserSession,
  verified via a real URL-substring condition (never "the agent said so"),
  then exported for reuse across every subsequent agent via Task 9's
  storage-state plumbing. A scheme without browser_util set is completely
  unaffected.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 11: Schema-check structured LLM output in adversarial review

**Files:**
- Modify: `src/lalo/findings/review.py` (`_parse_review_response`)
- Test: `tests/lalo/test_findings_review.py`

**Interfaces:** no signature change — `_parse_review_response(text: str) -> tuple[dict |
None, str]` already returns `(None, reason)` for anything unparseable; this task widens
what counts as "unparseable" to include a wrong-shaped-but-valid-JSON response.

- [ ] **Step 1: Write the failing test**

  Read `_parse_review_response` in full first (already confirmed this session: it calls
  `extract_json_object(text)`, checks `raw_verdict in {v.value for v in ReviewVerdict}`
  — so verdict-membership IS already checked; the actual gap is narrower than the
  research first suggested — confirm precisely what's still unchecked, e.g.
  `reasoning`/`proof_level` being present with the wrong TYPE (not just an unrecognized
  string value), by reading `_compute_review`'s own downstream `str(parsed.get(...))`
  coercions, which already tolerate a missing/wrong-typed field via `str()` coercion —
  meaning the genuinely narrow remaining gap is likely already this small: nothing
  checks that `parsed` is a `dict[str, object]` specifically rather than some other JSON
  type `extract_json_object` might return, e.g. a JSON array or a bare string that
  happens to parse.

  Append to `tests/lalo/test_findings_review.py` a test proving whatever the real,
  confirmed gap is once Step 1's reading is done (e.g., a response whose top-level JSON
  is a list, not an object, currently reaching `parsed.get("verdict", "")` and crashing
  with `AttributeError` instead of degrading to the fallback):

  ```python
  def test_a_non_dict_json_response_degrades_to_open_proof_gap_not_a_crash() -> None:
      # e.g. router scripted to return "[1, 2, 3]" for the review call
      ...
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_findings_review.py -k non_dict_json -v
  ```

- [ ] **Step 3: Write minimal implementation**

  In `_parse_review_response`, add an `isinstance(parsed, dict)` guard immediately after
  `extract_json_object` returns, before any `.get()` call:

  ```python
      parsed = extract_json_object(text)
      if not isinstance(parsed, dict):
          return None, "review response was not a JSON object"
  ```

  (If `extract_json_object`'s own return type is already annotated `dict[str, object] |
  None`, this task may already be fully closed by the type system and the real fix is
  confirming `extract_json_object` itself never returns a non-dict — read
  `core/json_response.py` in full to settle this before writing any code; if it's
  already guaranteed, this task closes as "verified already correct, no code change
  needed" and Step 3 becomes documenting that finding instead of a fix.)

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_findings_review.py -v
  ```

  ```
  uv run ruff check src/lalo/findings/review.py tests/lalo/test_findings_review.py
  uv run ruff format src/lalo/findings/review.py tests/lalo/test_findings_review.py
  uv run mypy src/lalo/findings/review.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/findings/review.py tests/lalo/test_findings_review.py
  git commit -m "$(cat <<'EOF'
  fix(findings): adversarial review degrades on a non-dict JSON response

  extract_json_object's result was trusted as a dict without checking -
  a syntactically-valid JSON response that isn't a top-level object (an
  array, a bare string) would crash _parse_review_response's own .get()
  calls instead of degrading to open_proof_gap like every other malformed-
  response case already does.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 12: Confined-child tool-allowlist self-check

**Files:**
- Modify: `src/lalo/scan.py` (the `role="source_reviewer"` child-dispatch path)
- Test: `tests/lalo/test_scan.py`

**Interfaces:** no new public function — a defensive `assert` added at an existing
child-dispatch call site.

- [ ] **Step 1: Write the failing test**

  Read the exact current child-dispatch code around `_ROLE_TOOL_NAMES`/
  `_build_registry(child_graph, child_id, tool_names=...)` (already confirmed this
  session: `_ROLE_TOOL_NAMES: dict[str, frozenset[str] | None] = {"full": None,
  "source_reviewer": _SOURCE_REVIEWER_TOOL_NAMES}`).

  This is a self-check against a wiring bug, not a behavior a black-box test can force
  without deliberately breaking `_build_registry` — write the test as a direct
  unit-level assertion that `_build_registry`'s own output, for `role="source_reviewer"`,
  exactly equals `_SOURCE_REVIEWER_TOOL_NAMES` (proving the assertion this task adds
  would never fire on correct code, and would catch a real future drift):

  ```python
  def test_source_reviewer_registry_exactly_matches_its_declared_tool_allowlist() -> None:
      graph = ReachabilityGraph()
      registry = scan_module._build_registry(graph, "child-1", tool_names=scan_module._ROLE_TOOL_NAMES["source_reviewer"])
      assert {tool.name for tool in registry.tools} == set(scan_module._ROLE_TOOL_NAMES["source_reviewer"])
  ```

  (Confirm `ToolRegistry`'s real way of listing its own tools — `.tools`/`.names()`/
  iterating — before finalizing this assertion's exact shape.)

- [ ] **Step 2: Run test to verify it fails**

  This test should already PASS against current code (it's proving a property that's
  already true) — its purpose is regression protection, not closing an active bug. Run
  it once to confirm it passes today, establishing the baseline this task's real
  addition (the runtime assertion below) then protects going forward.

  ```
  uv run pytest tests/lalo/test_scan.py -k exactly_matches_its_declared -v
  ```

- [ ] **Step 3: Write minimal implementation**

  At the actual child-dispatch call site (where `_build_registry(child_graph, child_id,
  tool_names=_ROLE_TOOL_NAMES[role])` is called and the resulting registry is about to
  be handed to a confined child's `AgentLoop`), add:

  ```python
  expected_tools = _ROLE_TOOL_NAMES[role]
  if expected_tools is not None:
      actual_tools = {tool.name for tool in child_registry.tools}
      assert actual_tools == set(expected_tools), (
          f"role {role!r}'s registry drifted from its declared allowlist: "
          f"got {actual_tools}, expected {set(expected_tools)}"
      )
  ```

  (A correctness self-check on L4L0's *own* already-decided confinement — this can
  never fire against correct code, only against a future wiring bug that accidentally
  adds/removes a tool from a confined role without updating `_ROLE_TOOL_NAMES` to
  match.)

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_scan.py -v
  ```

  ```
  uv run ruff check src/lalo/scan.py tests/lalo/test_scan.py
  uv run ruff format src/lalo/scan.py tests/lalo/test_scan.py
  uv run mypy src/lalo/scan.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/scan.py tests/lalo/test_scan.py
  git commit -m "$(cat <<'EOF'
  fix(L4L0): self-check a confined child's registry against its declared allowlist

  A defensive assertion, not a new authorization boundary: catches a future
  wiring bug (an accidental extra/missing tool on a confined role like
  source_reviewer) before it ever reaches the model, rather than silently
  running with the wrong toolset.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 13: Per-child scratch-directory namespace

**Files:**
- Modify: `src/lalo/scan.py` (child-dispatch: the task/prompt text a spawned child
  receives)
- Test: `tests/lalo/test_scan.py`

**Interfaces:** no new tool or graph node — a documentation/prompt-text convention
threaded into a child's own task string, so `run_command` calls the child itself makes
naturally scope scratch files under it.

- [ ] **Step 1: Write the failing test**

  First find exactly where a spawned child's `task` string is assembled (grep
  `spawn_agent`/`_run_child`'s task-construction in `scan.py`/`agent/spawn.py`) — this
  task's real diff is prepending a short, deterministic scratch-directory hint to that
  string, keyed on the already-unique, system-generated `child_id` (never the
  agent-chosen `name`/`task` free text).

  ```python
  def test_a_spawned_childs_task_names_its_own_scratch_directory() -> None:
      # dispatch a spawn_agent call and inspect the resulting child's own
      # task string (via whichever existing test hook already lets tests
      # observe a spawned child's task, e.g. a scripted provider's own
      # captured prompt) for the literal scratch-dir hint.
      ...
      assert "/work/scratch/child-" in captured_child_task
  ```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Write minimal implementation**

  At the child task-assembly call site, prepend:

  ```python
  scratch_hint = (
      f"(Your own scratch working directory inside the container is "
      f"/work/scratch/{child_id}/ - use it for any scratch files, cloned "
      f"repos, or staged payloads so concurrent sibling agents never "
      f"collide on filenames. Create it yourself with mkdir -p if you need "
      f"it; nothing pre-creates it for you.)\n\n"
  )
  task = scratch_hint + task
  ```

  (This is a convention, not an enforced filesystem jail — matching CLAUDE.md's
  no-restrictions posture exactly: a child is free to write anywhere in the container
  regardless, this only gives it a natural, collision-free default via prompt guidance,
  the filesystem analogue of `isolate_for_child`'s existing graph-snapshot isolation for
  a genuinely different kind of state.)

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_scan.py -v
  ```

  ```
  uv run ruff check src/lalo/scan.py tests/lalo/test_scan.py
  uv run ruff format src/lalo/scan.py tests/lalo/test_scan.py
  uv run mypy src/lalo/scan.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/scan.py tests/lalo/test_scan.py
  git commit -m "$(cat <<'EOF'
  feat(L4L0): give each spawned child a named, collision-free scratch directory

  A prompt-text convention, not an enforced jail (matching the no-
  restrictions design posture) - each spawned child's task now names its
  own /work/scratch/<child_id>/ directory, keyed on the already-unique
  system-generated agent_id, so concurrent spawn_agents siblings sharing
  one container filesystem have a natural default that avoids scratch-
  filename collisions without restricting where any agent may actually
  write.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 14: Non-retryable provider-failure classification

**Files:**
- Modify: `src/lalo/core/errors.py` (`ProviderUnavailableError` — add a `retryable: bool`
  attribute), `src/lalo/core/providers.py` (the 401/403 raise sites set `retryable=False`),
  `src/lalo/core/model_router.py` (`AllProvidersFailedError`'s `failures` carries the
  flag through), `src/lalo/agent/loop.py` (`_retry_through_provider_outage` checks it)
- Test: `tests/lalo/test_providers.py`, `tests/lalo/test_agent_loop.py`

**Interfaces:**
- Produces: `ProviderUnavailableError.retryable: bool = True` (default preserves every
  existing raise site's current behavior — only the specific 401/403 sites set it
  `False`). `ModelRouter.complete`'s `failures: list[tuple[str, str]]` stays unchanged in
  shape (still `(provider_name, code)` pairs) — `AllProvidersFailedError` gains a new
  `all_non_retryable: bool` computed property instead of widening the tuple shape,
  keeping every existing `failures`-consuming call site (the GUI's error response)
  unaffected.

  **Verified exact current shape first** (read this session): `ModelRouter.complete`
  catches `(ProviderRefusalError, ProviderUnavailableError) as exc` and appends
  `(name, exc.code)` to `failures` — `exc.code` is currently always one of the two fixed
  class-level strings `"provider_refusal"`/`"provider_unavailable"`, never a
  finer-grained per-failure reason; the actual HTTP status only lives in the exception's
  *message* (e.g. `f"http {resp.status_code}"`, `providers.py` lines confirmed this
  session), which is discarded once only `.code` is kept. This task threads a NEW
  boolean through instead of trying to parse the discarded message.

- [ ] **Step 1: Write the failing test**

  Append to `tests/lalo/test_providers.py`:

  ```python
  def test_a_401_response_raises_a_non_retryable_provider_unavailable_error() -> None:
      # scripted transport returning HTTP 401 for AnthropicProvider.complete()
      # (or OpenAICompatibleProvider, whichever this file's existing fixtures
      # already build most easily)
      ...
      with pytest.raises(ProviderUnavailableError) as exc_info:
          provider.complete(CompletionRequest(prompt="x"))
      assert exc_info.value.retryable is False


  def test_a_503_response_still_raises_a_retryable_provider_unavailable_error() -> None:
      ...
      with pytest.raises(ProviderUnavailableError) as exc_info:
          provider.complete(CompletionRequest(prompt="x"))
      assert exc_info.value.retryable is True
  ```

  Append to `tests/lalo/test_agent_loop.py`:

  ```python
  def test_retry_through_provider_outage_skips_the_wait_when_every_failure_is_non_retryable() -> None:
      # a router whose only provider always raises a non-retryable
      # ProviderUnavailableError (401-shaped) - _retry_through_provider_outage
      # must return None immediately, with zero _interruptible_sleep calls,
      # rather than burning the full backoff schedule on a failure no amount
      # of retrying can fix.
      ...
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_providers.py -k retryable -v
  uv run pytest tests/lalo/test_agent_loop.py -k skips_the_wait -v
  ```

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/core/errors.py`:

  ```python
  class ProviderUnavailableError(ProviderError):
      """The provider is unreachable / transiently failing (transport, 5xx, rate limit).

      Failover-eligible, like :class:`ProviderRefusalError`. ``retryable``
      (default True) is False for a failure no amount of waiting can fix -
      currently just an authentication/authorization failure (401/403): a
      revoked or invalid credential stays invalid no matter how long
      :meth:`~lalo.agent.loop.AgentLoop._retry_through_provider_outage` waits.
      """

      code = "provider_unavailable"

      def __init__(
          self, message: str = "", *, provider: str = "", retryable: bool = True
      ) -> None:
          super().__init__(message, provider=provider)
          self.retryable = retryable
  ```

  In `src/lalo/core/providers.py`, at the two confirmed `f"http {resp.status_code}"`
  raise sites (lines ~133, ~207 — re-confirm exact line numbers live), add the
  classification:

  ```python
          if resp.status_code in _RETRYABLE_STATUS or resp.status_code >= 400:
              raise ProviderUnavailableError(
                  f"http {resp.status_code}",
                  provider=self.name,
                  retryable=resp.status_code not in (401, 403),
              )
  ```

  (Confirm the exact existing conditional this raise sits inside — this session's own
  earlier reading of `AnthropicProvider.complete()` showed `if resp.status_code in
  _RETRYABLE_STATUS or resp.status_code >= 400:` as the guard; adapt the `retryable=`
  expression to that real condition rather than assuming.)

  In `src/lalo/core/errors.py`, extend `AllProvidersFailedError` with a computed
  helper — confirm its exact current `__init__`/`failures` storage shape first, then
  add:

  ```python
      @property
      def all_non_retryable(self) -> bool:
          """True only if every single failure this run collected was
          non-retryable - used to skip the outer outage-retry wait entirely,
          never to suppress or hide any failure detail."""
          return bool(self.failures) and all(
              code != "provider_unavailable_retryable" for _name, code in self.failures
          )
  ```

  This requires `failures`' own `code` element to actually carry the `retryable` bit,
  which the current `(name, exc.code)` tuple in `model_router.py` does NOT — `exc.code`
  is the fixed class attribute, never the instance's `retryable` flag. Fix
  `ModelRouter.complete`'s append to carry both:

  ```python
          except (ProviderRefusalError, ProviderUnavailableError) as exc:
              retryable = getattr(exc, "retryable", True)
              failures.append((name, exc.code if retryable else f"{exc.code}_non_retryable"))
  ```

  (A pragmatic encoding that keeps `failures`' shape as `list[tuple[str, str]]`
  unchanged for every existing consumer, rather than widening the tuple to 3 elements
  and touching every call site that destructures it — confirm no existing test asserts
  an exact `failures` value that this string suffix would break, via grep, before
  finalizing this exact encoding; if it does, revisit toward a 3-tuple instead.)

  Rewrite `all_non_retryable` to match:

  ```python
      @property
      def all_non_retryable(self) -> bool:
          return bool(self.failures) and all(
              code.endswith("_non_retryable") for _name, code in self.failures
          )
  ```

  In `src/lalo/agent/loop.py`'s `_complete`, the current `except AllProvidersFailedError:
  return None` needs to preserve the exception's own `all_non_retryable` verdict for
  `_retry_through_provider_outage` to check — thread it via a small instance attribute
  set right before returning `None` (confirm `_complete`'s exact current signature/body
  first, already read this session), then in `_retry_through_provider_outage`, check
  that flag before the very first sleep and return `None` immediately if it's set,
  skipping the entire backoff loop.

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_providers.py tests/lalo/test_agent_loop.py -v
  ```

  ```
  uv run ruff check src/lalo/core/errors.py src/lalo/core/providers.py src/lalo/core/model_router.py src/lalo/agent/loop.py
  uv run ruff format src/lalo/core/errors.py src/lalo/core/providers.py src/lalo/core/model_router.py src/lalo/agent/loop.py
  uv run mypy src/lalo/core/errors.py src/lalo/core/providers.py src/lalo/core/model_router.py src/lalo/agent/loop.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/core/errors.py src/lalo/core/providers.py src/lalo/core/model_router.py src/lalo/agent/loop.py tests/lalo/test_providers.py tests/lalo/test_agent_loop.py
  git commit -m "$(cat <<'EOF'
  feat(core): skip the outer retry wait when every provider failure is non-retryable

  A 401/403 provider response now raises ProviderUnavailableError(retryable=
  False) - a revoked/invalid credential stays invalid no matter how long
  the outer outage-retry backoff waits. AllProvidersFailedError.
  all_non_retryable lets _retry_through_provider_outage skip its entire
  wait-and-retry schedule when nothing about it could possibly succeed,
  surfacing the real failure immediately instead.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 15: Bounded retry on transient journal/atomic-write I/O

**Files:**
- Modify: `src/lalo/core/atomic_io.py` (`atomic_write_verified`, `append_owner_only_line`)
- Test: `tests/lalo/test_atomic_io.py`

**Interfaces:** no signature change — both functions gain internal retry on `OSError`.

- [ ] **Step 1: Write the failing test**

  Read both functions in full first (already partially confirmed this session).

  ```python
  def test_atomic_write_verified_retries_a_transient_oserror(tmp_path, monkeypatch) -> None:
      path = tmp_path / "x.json"
      calls = {"n": 0}
      real_replace = os.replace

      def flaky_replace(src, dst):
          calls["n"] += 1
          if calls["n"] < 2:
              raise OSError("simulated transient disk error")
          return real_replace(src, dst)

      monkeypatch.setattr(os, "replace", flaky_replace)
      atomic_write_verified(path, b"hello")
      assert path.read_bytes() == b"hello"
      assert calls["n"] == 2


  def test_atomic_write_verified_gives_up_after_bounded_retries(tmp_path, monkeypatch) -> None:
      def always_fails(src, dst):
          raise OSError("permanently broken")

      monkeypatch.setattr(os, "replace", always_fails)
      with pytest.raises(OSError):
          atomic_write_verified(tmp_path / "x.json", b"hello")
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_atomic_io.py -v
  ```

  Expected: the retry test fails on the first (unretried) `OSError`.

- [ ] **Step 3: Write minimal implementation**

  Wrap the specific `os.replace`/file-write call inside `atomic_write_verified` (and the
  equivalent write call in `append_owner_only_line`) in a small bounded retry:

  ```python
  _IO_RETRY_ATTEMPTS = 3
  _IO_RETRY_DELAY_S = 0.1


  def _retry_on_oserror(fn: Callable[[], None]) -> None:
      """Deterministic, local I/O is cheap and safe to retry - a momentarily-
      full disk or a brief filesystem hiccup shouldn't abort a whole scan.
      Mirrors the deterministic-vs-model retry-profile distinction a studied
      reference agent's own durability layer draws (cheap IO gets more,
      cheaper retries than a model call would)."""
      last_exc: OSError | None = None
      for attempt in range(_IO_RETRY_ATTEMPTS):
          try:
              fn()
              return
          except OSError as exc:
              last_exc = exc
              if attempt < _IO_RETRY_ATTEMPTS - 1:
                  time.sleep(_IO_RETRY_DELAY_S)
      assert last_exc is not None
      raise last_exc
  ```

  (Wrap only the specific `os.replace(...)` call inside `atomic_write_verified` — not
  the whole function, since the temp-file write + fsync + read-back-verify steps before
  it are not what this task is about and re-running them on every retry would be
  wasteful; confirm the exact current function body's structure first to scope the
  wrapped closure correctly.)

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_atomic_io.py -v
  uv run pytest tests/lalo/test_scan.py tests/lalo/test_orchestrator_journal.py -q
  ```

  ```
  uv run ruff check src/lalo/core/atomic_io.py tests/lalo/test_atomic_io.py
  uv run ruff format src/lalo/core/atomic_io.py tests/lalo/test_atomic_io.py
  uv run mypy src/lalo/core/atomic_io.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/core/atomic_io.py tests/lalo/test_atomic_io.py
  git commit -m "$(cat <<'EOF'
  fix(core): bounded retry on transient I/O in atomic_write_verified

  A momentarily-full disk or a brief filesystem hiccup previously aborted
  the whole scan on the very next journal/report/graph write - deterministic
  local I/O is cheap and safe to retry a few times before giving up for
  real.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 16: `usage_accounting_complete` signal

**Files:**
- Modify: `src/lalo/core/usage.py` (`UsageStats`, `record_usage`)
- Modify: `src/lalo/gui/app.py` or wherever usage is surfaced to the operator (grep
  `total_cost_usd`/usage-display call sites)
- Test: `tests/lalo/test_usage.py`

**Interfaces:** `UsageStats.accounting_complete: bool = True` (new field, flips `False`
the first time a `record_usage` call itself fails after Task 15's own retries are
exhausted, or the lock in bugfix-plan Task 1 is somehow bypassed by a future change).

- [ ] **Step 1: Write the failing test**

  ```python
  def test_usage_stats_defaults_to_accounting_complete(tmp_path) -> None:
      stats = load_usage(tmp_path / "usage.json")
      assert stats.accounting_complete is True


  def test_a_failed_record_usage_call_flips_accounting_complete_false(tmp_path, monkeypatch) -> None:
      path = tmp_path / "usage.json"
      # first call succeeds and establishes the file
      record_usage(_response(), path=path)
      # force the SECOND call's write to fail permanently
      monkeypatch.setattr(
          "lalo.core.usage.atomic_write_verified",
          lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")),
      )
      with pytest.raises(OSError):
          record_usage(_response(), path=path)
      # re-read without the monkeypatch to see the durable state - since the
      # write itself failed, this must reflect the LAST successfully
      # persisted state, with accounting_complete now False (best-effort:
      # the failure itself is recorded on next successful write, or via a
      # sidecar marker if a completely failed write leaves nothing to
      # update - confirm the real mechanism during implementation).
  ```

  (This test's exact final shape depends on the real implementation strategy chosen in
  Step 3 — a totally-failed write genuinely cannot update the very file it failed to
  write, so `accounting_complete` most likely needs an in-memory/process-level flag
  surfaced via a separate mechanism, e.g. a module-level flag checked by whatever
  renders the usage summary, rather than a field inside the JSON file that a failed
  write can't persist. Resolve this design question by reading `record_usage`'s real
  call sites and the GUI's usage-display code before finalizing the test.)

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Write minimal implementation**

  Given the chicken-and-egg problem above (a failed write can't record its own
  failure in the file it failed to write), the practical implementation is a
  process-level flag, not a JSON field: a module-level `_accounting_complete =
  True` in `core/usage.py`, flipped to `False` inside `record_usage`'s own
  `except OSError` handling (after Task 15's retries are exhausted) rather than
  re-raising silently-swallowed, plus a small `usage_accounting_status() -> bool`
  reader function. Surface it in the GUI's usage summary (wherever `total_cost_usd`
  is currently rendered) as a warning line when `False`. This is a narrower, more
  honest scope than the spec's own JSON-field framing — document the reason for the
  design change in the module docstring rather than silently deviating.

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_usage.py -v
  ```

  ```
  uv run ruff check src/lalo/core/usage.py src/lalo/gui/app.py tests/lalo/test_usage.py
  uv run ruff format src/lalo/core/usage.py src/lalo/gui/app.py tests/lalo/test_usage.py
  uv run mypy src/lalo/core/usage.py src/lalo/gui/app.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/core/usage.py src/lalo/gui/app.py tests/lalo/test_usage.py
  git commit -m "$(cat <<'EOF'
  feat(core): surface when usage accounting might be an undercount

  A process-level flag (not a JSON field - a failed write can't record its
  own failure in the file it failed to write) flips when record_usage
  itself fails after its own retries are exhausted, surfaced as a warning
  in the GUI's usage summary instead of silently presenting a possibly-
  partial cost total as final.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 17: Centralized run-artifact filenames module

**Files:**
- Create: `src/lalo/paths.py`
- Modify: `src/lalo/scan.py`, `src/lalo/orchestrator/narrative.py`, `src/lalo/gui/app.py`,
  `src/lalo/core/usage.py` (replace each literal filename string with the new constant)
- Test: `tests/lalo/test_paths.py`

**Interfaces:** `EVENTS_FILENAME = "events.jsonl"`, `RESUME_MANIFEST_FILENAME =
"resume_manifest.json"`, `NARRATIVE_LOG_FILENAME = "narrative.log"`, `USAGE_FILENAME =
"usage.json"` — plain string constants, no functions needed (every call site already
does its own `run_dir / filename` join).

- [ ] **Step 1: Write the failing test**

  ```python
  def test_paths_module_exports_every_run_artifact_filename() -> None:
      from lalo.paths import (
          EVENTS_FILENAME,
          NARRATIVE_LOG_FILENAME,
          RESUME_MANIFEST_FILENAME,
          USAGE_FILENAME,
      )
      assert EVENTS_FILENAME == "events.jsonl"
      assert RESUME_MANIFEST_FILENAME == "resume_manifest.json"
      assert NARRATIVE_LOG_FILENAME == "narrative.log"
      assert USAGE_FILENAME == "usage.json"
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_paths.py -v
  ```

  Expected: `ModuleNotFoundError: No module named 'lalo.paths'`.

- [ ] **Step 3: Write minimal implementation**

  ```python
  """Centralized run-artifact filenames — every module that reads or writes
  one of these joins it onto a run_dir itself; this module only owns the
  literal string, closing the rename/drift risk of having the same filename
  duplicated across 2-4 separate files with no single source of truth."""

  from __future__ import annotations

  EVENTS_FILENAME = "events.jsonl"
  RESUME_MANIFEST_FILENAME = "resume_manifest.json"
  NARRATIVE_LOG_FILENAME = "narrative.log"
  USAGE_FILENAME = "usage.json"
  ```

  Grep every literal occurrence of `"events.jsonl"`, `"resume_manifest.json"`,
  `"narrative.log"`, `"usage.json"` across `src/lalo/` (confirmed this session: at least
  `scan.py`, `orchestrator/narrative.py`, `gui/app.py`, `core/usage.py`) and replace each
  with `from .paths import ...` + the constant, preserving every existing `run_dir /
  <constant>` join pattern exactly.

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_paths.py -v
  uv run pytest tests/lalo -q -m "not live and not integration"
  ```

  (The full-suite run here is the real regression check — this touches 4+ files'
  filename references, and a missed or wrong replacement would break a real run
  directory's file layout.)

  ```
  uv run ruff check src/lalo/paths.py src/lalo/scan.py src/lalo/orchestrator/narrative.py src/lalo/gui/app.py src/lalo/core/usage.py tests/lalo/test_paths.py
  uv run ruff format src/lalo/paths.py src/lalo/scan.py src/lalo/orchestrator/narrative.py src/lalo/gui/app.py src/lalo/core/usage.py tests/lalo/test_paths.py
  uv run mypy src/lalo/paths.py src/lalo/scan.py src/lalo/orchestrator/narrative.py src/lalo/gui/app.py src/lalo/core/usage.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/paths.py src/lalo/scan.py src/lalo/orchestrator/narrative.py src/lalo/gui/app.py src/lalo/core/usage.py tests/lalo/test_paths.py
  git commit -m "$(cat <<'EOF'
  fix(L4L0): centralize run-artifact filenames into one module

  events.jsonl/resume_manifest.json/narrative.log/usage.json were each
  duplicated as literal strings across 2-4 separate files with no single
  source of truth - a real rename/drift risk. One new lalo.paths module
  owns each literal now; every call site imports the constant instead.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 18: Packaged CI/CD integration script

**Files:**
- Create: `scripts/ci-scan.py`
- Create: `docs/ci-cd-integration.md` (a GitHub Actions workflow YAML example + a GitLab
  CI component example, both driving the new script)
- Test: `tests/lalo/test_ci_scan.py` (or `tests/scripts/test_ci_scan.py`, matching
  whichever convention this project's own `scripts/` directory already uses for tests,
  if any exist — check first; if `scripts/` has no test precedent, place it under
  `tests/lalo/` for consistency with everything else)

**Interfaces:** a standalone script — deliberately outside `src/lalo/` (this is
automation glue for a *different* tool's pipeline, never L4L0's own interactive product
surface; the no-CLI/no-TUI design center is about L4L0's own product, not about whether
a non-interactive script may exist at all — `setup.py`'s already-accepted narrow
exception is the same category). Uses the existing GUI HTTP API (`POST /scan`, `GET
/runs/{id}`, `GET /runs/{id}/report/sarif`) — no new backend endpoint, no import of
`lalo` internals.

- [ ] **Step 1: Write the failing test**

  ```python
  def test_ci_scan_exits_zero_when_no_confirmed_finding_meets_the_threshold(monkeypatch) -> None:
      # mock the HTTP calls this script makes (POST /scan, polling GET
      # /runs/{id}, GET /runs/{id}/report/sarif) via whatever this project's
      # own test suite already uses for mocking httpx (core/providers.py's
      # own tests use httpx.MockTransport - reuse that pattern)
      ...
      exit_code = ci_scan.main(["--target", "https://x.example.com", "--fail-on-severity", "high"])
      assert exit_code == 0


  def test_ci_scan_exits_nonzero_only_on_a_confirmed_finding_at_or_above_threshold(monkeypatch) -> None:
      # SARIF response with one finding whose properties["lalo"]["review_verdict"]
      # is "open_proof_gap" at "critical" severity - must NOT fail the build
      ...
      # a second SARIF response with a "confirmed" verdict at "high" severity
      # WITH --fail-on-severity high - must fail the build
      ...
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_ci_scan.py -v
  ```

  Expected: `ModuleNotFoundError` — the script doesn't exist yet.

- [ ] **Step 3: Write minimal implementation**

  `scripts/ci-scan.py` (stdlib `argparse` + `httpx`, already a project dependency via
  `pyproject.toml`):

  ```python
  #!/usr/bin/env python3
  """Non-interactive CI/CD wrapper around L4L0's GUI HTTP API - launches a
  scan, waits for completion, copies the SARIF output to a caller-specified
  path, and exits non-zero only when the worst CONFIRMED finding meets or
  exceeds a caller-supplied severity threshold. Never gated on an
  unconfirmed/open-proof-gap finding - only a real, adversarially-reviewed
  confirmation fails a build.

  Deliberately outside src/lalo/: automation glue for a DIFFERENT tool's
  pipeline (a GitHub Action, a GitLab CI job) to invoke non-interactively,
  the same category as lalo-setup's own already-accepted narrow exception
  to this project's no-CLI/no-TUI design center - not a new interactive
  mode of L4L0 itself.
  """

  from __future__ import annotations

  import argparse
  import json
  import sys
  import time

  import httpx

  _SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


  def _worst_confirmed_severity(sarif_doc: dict[str, object]) -> str | None:
      worst: str | None = None
      run = sarif_doc["runs"][0]  # type: ignore[index]
      for result in run["results"]:  # type: ignore[index]
          props = result.get("properties", {}).get("lalo", {})
          if props.get("review_verdict") != "confirmed":
              continue
          severity = _severity_from_security_severity(result["properties"]["security-severity"])
          if worst is None or _SEVERITY_ORDER[severity] < _SEVERITY_ORDER[worst]:
              worst = severity
      return worst


  def _severity_from_security_severity(score_str: str) -> str:
      score = float(score_str)
      if score >= 9.0:
          return "critical"
      if score >= 7.0:
          return "high"
      if score >= 4.0:
          return "medium"
      return "low" if score > 0 else "info"


  def main(argv: list[str] | None = None) -> int:
      parser = argparse.ArgumentParser(description=__doc__)
      parser.add_argument("--base-url", default="http://127.0.0.1:8000")
      parser.add_argument("--target", required=True, action="append")
      parser.add_argument("--mission", default="find and prove any exploitable vulnerability")
      parser.add_argument("--fail-on-severity", choices=sorted(_SEVERITY_ORDER), default=None)
      parser.add_argument("--sarif-out", default="l4l0-results.sarif")
      parser.add_argument("--poll-interval-s", type=float, default=5.0)
      parser.add_argument("--timeout-s", type=float, default=3600.0)
      args = parser.parse_args(argv)

      client = httpx.Client(base_url=args.base_url, timeout=30.0)
      response = client.post("/scan", json={"mission": args.mission, "targets": args.target})
      response.raise_for_status()
      run_id = response.json()["run_id"]

      deadline = time.monotonic() + args.timeout_s
      while time.monotonic() < deadline:
          runs = client.get("/runs").json()["runs"]
          run = next((r for r in runs if r["run_id"] == run_id), None)
          if run is not None and not run["running"]:
              break
          time.sleep(args.poll_interval_s)
      else:
          print(f"error: scan {run_id} did not finish within {args.timeout_s}s", file=sys.stderr)
          return 2

      sarif_response = client.get(f"/runs/{run_id}/report/sarif")
      sarif_response.raise_for_status()
      with open(args.sarif_out, "wb") as f:
          f.write(sarif_response.content)

      if args.fail_on_severity is None:
          return 0
      worst = _worst_confirmed_severity(json.loads(sarif_response.content))
      if worst is not None and _SEVERITY_ORDER[worst] <= _SEVERITY_ORDER[args.fail_on_severity]:
          print(f"L4L0 found a confirmed {worst} finding (threshold: {args.fail_on_severity})", file=sys.stderr)
          return 1
      return 0


  if __name__ == "__main__":
      raise SystemExit(main())
  ```

  (Confirm the real `/runs` list response shape and `security-severity`'s exact numeric
  convention against `report/sarif.py`'s own `_security_severity` function before
  finalizing `_severity_from_security_severity`'s thresholds — this sketch assumes the
  same CVSS-score-derived-security-severity mapping `sarif.py` itself uses; read it and
  match exactly rather than inventing independent thresholds.)

  `docs/ci-cd-integration.md`: a short doc with a GitHub Actions workflow YAML block
  (checkout, start `lalo-gui` in the background, run `python scripts/ci-scan.py
  --target ... --fail-on-severity high`, upload `l4l0-results.sarif` via
  `github/codeql-action/upload-sarif`) and the GitLab CI equivalent (a job template
  doing the same three steps).

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_ci_scan.py -v
  ```

  ```
  uv run ruff check scripts/ci-scan.py tests/lalo/test_ci_scan.py
  uv run ruff format scripts/ci-scan.py tests/lalo/test_ci_scan.py
  uv run mypy scripts/ci-scan.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add scripts/ci-scan.py docs/ci-cd-integration.md tests/lalo/test_ci_scan.py
  git commit -m "$(cat <<'EOF'
  feat(L4L0): packaged CI/CD integration script + workflow examples

  scripts/ci-scan.py drives the existing GUI HTTP API non-interactively -
  launch, poll, fetch SARIF, exit non-zero only on a CONFIRMED finding at
  or above a caller-supplied severity threshold (never gated on an
  unconfirmed/open-proof-gap finding). Deliberately outside src/lalo/,
  the same automation-glue category as lalo-setup's own already-accepted
  narrow exception to the no-CLI/no-TUI design center - not a new
  interactive mode of L4L0 itself. Paired with GitHub Actions/GitLab CI
  example workflows in docs/ci-cd-integration.md.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 19: Per-agent narrative log splitting

**Files:**
- Modify: `src/lalo/orchestrator/narrative.py` (new `write_per_agent_narrative_logs`)
- Modify: `src/lalo/scan.py` (call site, alongside the existing `write_narrative_log`)
- Modify: `src/lalo/gui/app.py` (a per-agent download link once more than one agent
  participated)
- Test: `tests/lalo/test_orchestrator_narrative.py`, `tests/lalo/test_gui_app.py`

**Interfaces:** `write_per_agent_narrative_logs(run_dir: Path) -> dict[str, Path]` (new,
alongside the existing `write_narrative_log(run_dir: Path) -> Path`) — groups the same
already-parsed `(category, payload)` events by real `agent_id`, writing one
`narrative-<agent_id>.log` per agent. The existing combined `narrative.log` is
unchanged; this is additive. A single-agent run produces no per-agent files (identical
content to the combined file — skip generating the pointless duplicate).

- [ ] **Step 1: Write the failing test**

  Read `orchestrator/narrative.py` in full first (already confirmed this session:
  `render_narrative_line(category, payload) -> str`, `render_narrative(run_dir) -> str`,
  `write_narrative_log(run_dir) -> Path`, plus its own `_SYSTEM_CATEGORIES`/agent-id
  extraction logic already used by `render_narrative_line`).

  Append to `tests/lalo/test_orchestrator_narrative.py`:

  ```python
  def test_write_per_agent_narrative_logs_splits_by_real_agent_id(tmp_path: Path) -> None:
      run_dir = tmp_path / "run"
      run_dir.mkdir()
      (run_dir / "events.jsonl").write_text(
          '{"category": "log", "payload": {"agent_id": "agent-1", "event": "tool_call", "tool": "http", "args": {"method": "GET", "url": "https://x/"}}}\n'
          '{"category": "log", "payload": {"agent_id": "agent-2", "event": "tool_call", "tool": "http", "args": {"method": "GET", "url": "https://y/"}}}\n',
          encoding="utf-8",
      )
      paths = write_per_agent_narrative_logs(run_dir)
      assert set(paths) == {"agent-1", "agent-2"}
      assert "https://x/" in paths["agent-1"].read_text(encoding="utf-8")
      assert "https://y/" not in paths["agent-1"].read_text(encoding="utf-8")
      assert oct(paths["agent-1"].stat().st_mode)[-3:] == "600"


  def test_write_per_agent_narrative_logs_skips_a_single_agent_run(tmp_path: Path) -> None:
      run_dir = tmp_path / "run"
      run_dir.mkdir()
      (run_dir / "events.jsonl").write_text(
          '{"category": "log", "payload": {"agent_id": "agent-1", "event": "tool_call", "tool": "http", "args": {"method": "GET", "url": "https://x/"}}}\n',
          encoding="utf-8",
      )
      assert write_per_agent_narrative_logs(run_dir) == {}
  ```

- [ ] **Step 2: Run test to verify it fails**

  ```
  uv run pytest tests/lalo/test_orchestrator_narrative.py -k per_agent -v
  ```

  Expected: `ImportError: cannot import name 'write_per_agent_narrative_logs'`.

- [ ] **Step 3: Write minimal implementation**

  In `src/lalo/orchestrator/narrative.py`, add (reusing the module's own existing
  `_events_path`/`_narrative_path`-style helpers and the same JSON-line-by-line parse
  loop `render_narrative` already has — confirm exact parsing shape before duplicating
  it, and factor out a shared internal parse-events helper if that avoids literal
  duplication, matching this module's own existing style):

  ```python
  def _narrative_path_for_agent(run_dir: Path, agent_id: str) -> Path:
      return run_dir / f"narrative-{agent_id}.log"


  def write_per_agent_narrative_logs(run_dir: Path) -> dict[str, Path]:
      """Additive to write_narrative_log's combined file, never a replacement:
      one narrative-<agent_id>.log per agent that actually participated,
      filenamed only from the already-safe, system-generated agent_id
      (never the agent-chosen name/task free text). Skips generating any
      file at all for a single-agent run - identical content to the
      combined file, a pointless duplicate.
      """
      path = _events_path(run_dir)
      if not path.exists():
          return {}
      lines_by_agent: dict[str, list[str]] = {}
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
          if not (isinstance(category, str) and isinstance(payload, dict)):
              continue
          agent_id = payload.get("agent_id")
          if not isinstance(agent_id, str):
              continue  # system/operator-scoped events have no per-agent home
          lines_by_agent.setdefault(agent_id, []).append(render_narrative_line(category, payload))

      if len(lines_by_agent) < 2:
          return {}

      written: dict[str, Path] = {}
      for agent_id, lines in lines_by_agent.items():
          out_path = _narrative_path_for_agent(run_dir, agent_id)
          atomic_write_verified(out_path, ("\n".join(lines) + "\n").encode("utf-8"))
          written[agent_id] = out_path
      return written
  ```

  Call it in `scan.py` alongside the existing `write_narrative_log(self.config.run_dir)`
  call:

  ```python
  write_narrative_log(self.config.run_dir)
  write_per_agent_narrative_logs(self.config.run_dir)
  ```

  In `gui/app.py`'s `_REPORT_FORMATS`-adjacent run-listing logic (the same place
  `"narrative"` was added to `report_formats` — confirm exact call site), detect
  per-agent files on disk (`run_dir.glob("narrative-*.log")`) and include their agent
  ids in the `/runs` response so the frontend can render one link per participating
  agent when more than one exists. Serve each via the same `/runs/{run_id}/report/{fmt}`
  endpoint's existing allowlist pattern, or a small dedicated route — confirm which
  fits this codebase's existing routing conventions better before choosing.

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_orchestrator_narrative.py tests/lalo/test_scan.py tests/lalo/test_gui_app.py -v
  ```

  ```
  uv run ruff check src/lalo/orchestrator/narrative.py src/lalo/scan.py src/lalo/gui/app.py tests/lalo/test_orchestrator_narrative.py tests/lalo/test_gui_app.py
  uv run ruff format src/lalo/orchestrator/narrative.py src/lalo/scan.py src/lalo/gui/app.py tests/lalo/test_orchestrator_narrative.py tests/lalo/test_gui_app.py
  uv run mypy src/lalo/orchestrator/narrative.py src/lalo/scan.py src/lalo/gui/app.py
  ```

  Live-verify: a real multi-agent run (a mission that spawns at least one child) shows
  more than one narrative link in the GUI, each with only that agent's own lines.

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/orchestrator/narrative.py src/lalo/scan.py src/lalo/gui/app.py tests/lalo/test_orchestrator_narrative.py tests/lalo/test_gui_app.py
  git commit -m "$(cat <<'EOF'
  feat(L4L0): per-agent narrative log splitting for multi-agent runs

  write_per_agent_narrative_logs groups the same already-parsed events by
  real agent_id into one narrative-<agent_id>.log per participating agent,
  additive to the existing combined narrative.log (never a replacement).
  Filenames come only from the already-safe, system-generated agent_id,
  never agent-chosen free text. A single-agent run generates no per-agent
  files - identical to the combined one, a pointless duplicate.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 20: Cancellation for an in-flight LLM call

**Files:**
- Modify: `src/lalo/core/model_router.py` (`CompletionRequest`), `src/lalo/core/
  providers.py` (`_post_with_retry`, every `Provider.complete` implementation),
  `src/lalo/agent/loop.py` (thread a `threading.Event` down from `should_stop`)
- Test: `tests/lalo/test_providers.py`, `tests/lalo/test_agent_loop.py`

**Interfaces:** `CompletionRequest` gains an optional `cancel_event: threading.Event |
None = None` field. Every `Provider.complete` implementation checks it before/during its
`httpx` call; `AgentLoop` passes its own `should_stop`-driven event through.

- [ ] **Step 1: Write the failing test**

  First confirm `CompletionRequest`'s exact current field list (`core/model_router.py`)
  and `AgentLoop.__init__`'s `should_stop: Callable[[], bool] | None` parameter
  (confirmed this session) — this task's real design question is how `should_stop`
  (a poll-based callback) and a `cancel_event` (settable from another thread) relate:
  `ScanRunner`'s own cancellation today sets `self._cancelled = True`, read by
  `_should_stop()` — the natural fix is for `ScanRunner.cancel()` to also `.set()` a
  shared `threading.Event` that `AgentLoop` was constructed with, rather than inventing
  a second, parallel cancellation channel.

  ```python
  def test_provider_complete_aborts_promptly_when_cancel_event_is_set(monkeypatch) -> None:
      # a transport that would otherwise hang/sleep for several seconds;
      # set cancel_event before calling complete() and assert it returns
      # (raising a dedicated cancellation exception, or returning promptly)
      # well under the transport's own full duration.
      ...
  ```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Write minimal implementation**

  Add `cancel_event: threading.Event | None = None` to `CompletionRequest`. In
  `core/providers.py`'s `_post_with_retry` (the shared retry helper every provider's
  `complete()` already routes through — confirmed this session as the common `_post`
  path via `_OpenAIStyleProvider`/`AnthropicProvider`), check `request.cancel_event` in
  the same interruptible-sleep-chunk pattern `agent/loop.py`'s own
  `_INTERRUPTIBLE_SLEEP_CHUNK_S` already uses for its outer backoff waits — since
  `httpx` itself doesn't offer a clean "abort this in-flight request from another
  thread" primitive without lower-level connection manipulation, the pragmatic, honest
  scope for this task is: check `cancel_event` **between retry attempts** (closing the
  gap for the common case — a request that's already failed once and is about to retry
  — immediately) rather than truly aborting a single already-in-flight socket read,
  which would need a deeper `httpx` transport-level change disproportionate to this
  task's value. Document this scope precisely in the new code's own docstring so a
  future reader doesn't assume more than what's actually delivered.

  In `agent/loop.py`, construct one `threading.Event` per `AgentLoop` instance (or
  accept one via `__init__`, matching whichever fits the existing `should_stop`
  wiring better — confirm by reading `ScanRunner`'s own `AgentLoop(...)` construction
  call sites first), pass it into every `CompletionRequest` this loop builds, and have
  `ScanRunner.cancel()` (the same method that already sets `self._cancelled = True`)
  also call `.set()` on it.

- [ ] **Step 4: Run test to verify it passes**

  ```
  uv run pytest tests/lalo/test_providers.py tests/lalo/test_agent_loop.py -v
  ```

  ```
  uv run ruff check src/lalo/core/model_router.py src/lalo/core/providers.py src/lalo/agent/loop.py
  uv run ruff format src/lalo/core/model_router.py src/lalo/core/providers.py src/lalo/agent/loop.py
  uv run mypy src/lalo/core/model_router.py src/lalo/core/providers.py src/lalo/agent/loop.py
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/core/model_router.py src/lalo/core/providers.py src/lalo/agent/loop.py tests/lalo/test_providers.py tests/lalo/test_agent_loop.py
  git commit -m "$(cat <<'EOF'
  feat(core): cancellation support for the between-retries window of an LLM call

  CompletionRequest.cancel_event, checked between retry attempts in
  _post_with_retry and settable from ScanRunner.cancel() - an operator
  stop or a wall-clock/cost-ceiling kill now interrupts a retrying
  completion within about one retry interval instead of waiting for the
  full attempt schedule. Scoped honestly to the between-attempts window,
  not a true single-in-flight-socket-read abort, which httpx has no clean
  primitive for without a disproportionate transport-level change.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

### Task 21: Doc-only methodology refinements

**Files:**
- Modify: `src/lalo/skills/content/methodology/severity-calibration.md` (4 new rules)
- Modify: `src/lalo/skills/content/methodology/source-aware-review.md` (call-site sweep
  technique)
- Modify: `src/lalo/prompts/content/agent.txt` (adversarial-sweep planning discipline)
- Modify: `src/lalo/prompts/content/review.txt` or `agent.txt` (cross-agent
  report-dedup discipline — confirm which role this belongs under; the spec frames it
  as a report-assembly-time concern, so `review.txt` likely fits better than `agent.txt`)
- Modify: `src/lalo/skills/content/vulnerabilities/xss.md` (DOM Clobbering bullet)
- Test: none new — this is content-only; the existing `skills/loader.py`/
  `prompts/loader.py` test suites already smoke-test that every file parses (frontmatter
  loads, no duplicate names, required placeholders present) — run those to confirm the
  edits don't break parsing.

**Interfaces:** none — pure markdown/text content additions to already-loaded files.

- [ ] **Step 1: No new test** — confirm the existing parse/load tests already cover file
  structure:

  ```
  uv run pytest tests/lalo/test_skills_loader.py tests/lalo/test_prompts_loader.py -v
  ```

  Run this once BEFORE editing (baseline green), then again after each file edit below,
  to catch a frontmatter/placeholder mistake immediately.

- [ ] **Step 2: N/A** (no failing test to write for pure content — the "test" here is
  the parse-loader suite staying green after each edit, verified in Step 1's before/after
  runs).

- [ ] **Step 3: Write the content**

  In `severity-calibration.md`, add four new subsections (matching the file's own
  existing heading/bullet style — read it in full first to match exactly):

  1. **Trusted-controller-mediated interfaces**: an exploit reachable only from a
     component with designed-in authority over the target (orchestrator→worker,
     management-plane→node) that only lets that controller do what it could already do
     legitimately caps low — *unless* it bypasses a specific, documented safety/security
     control that controller was designed to respect, which stays high.
  2. **Multi-tenant resource-reuse exception**: the existing self-contained-blast-radius
     cap does NOT apply if the effect could survive into a *different* principal's later
     reuse of the same execution slot (state/credentials leaking through a warm
     serverless container/VM reused by another tenant).
  3. **Non-repudiation carve-out**: an effect confined to the attacker's own data still
     caps low unless it also breaks non-repudiation (enables fraud/blame-shifting).
  4. **Attacker position by trust barrier, not wire protocol**: classify exposure by the
     outermost boundary the ultimate untrusted attacker must cross, tracing through
     trusted intermediaries — a component bound to loopback/service-mesh-only is LOCAL
     exposure even if it happens to speak HTTP.

  In `source-aware-review.md`'s Step Two, add: when a shared function/helper carries an
  implicit safety contract (a buffer-size assumption, a sanitization precondition), grep
  every call site of that helper across the whole repo and check each individually —
  the offensive complement to `closure-discipline.md`'s existing defensive "safe
  sibling" trap.

  In `agent.txt`'s existing THOROUGHNESS/MULTI-AGENT-WORK section, add: periodically
  spawn a child specifically tasked with re-examining a surface already judged
  low-value/`ruled_out`, with no prior context, as a deliberate check against
  confirmation bias from over-trusting upstream recon.

  In `review.txt` (confirm this is the right role after reading both files' current
  scope), add a cross-agent report-deduplication discipline: when independent
  specialist children each confirm the same underlying defect via different
  symptoms/routes, clean every candidate title down to defect+location (never
  consequence/hedges/process-framing) before comparing, and bias toward under-merging
  (a visible duplicate is recoverable) over over-merging (which can hide a genuinely
  distinct finding).

  In `xss.md`'s existing client-side-sinks/techniques section, add one bullet: DOM
  Clobbering — injecting HTML elements whose `id`/`name` attributes shadow global
  JavaScript variables (e.g. `<input id=config>` clobbering `window.config`) to bypass a
  sanitizer or corrupt app logic without executing `<script>` at all.

- [ ] **Step 4: Run the parse/load tests again to confirm nothing broke**

  ```
  uv run pytest tests/lalo/test_skills_loader.py tests/lalo/test_prompts_loader.py -v
  ```

  Also run `prompts/loader.py`'s own `REQUIRED_PLACEHOLDERS` check implicitly via this
  suite — confirm no stray `$` character was introduced by any new prose (grep the
  diffed files for a bare `$` before committing, matching this project's own established
  discipline from the round-4 plan's own skill-content task).

  ```
  uv run ruff format --check src/lalo/skills/content/methodology/severity-calibration.md src/lalo/skills/content/methodology/source-aware-review.md src/lalo/skills/content/vulnerabilities/xss.md 2>&1 || true
  ```

  (Markdown files aren't ruff-formatted — this line is a no-op placeholder reminder that
  only the `.txt` prompt files and any `.py` test file this task might touch need the
  usual `ruff check`/`format`/`mypy` gates; skip them for the `.md` files themselves.)

- [ ] **Step 5: Commit**

  ```bash
  git add src/lalo/skills/content/methodology/severity-calibration.md src/lalo/skills/content/methodology/source-aware-review.md src/lalo/prompts/content/agent.txt src/lalo/prompts/content/review.txt src/lalo/skills/content/vulnerabilities/xss.md
  git commit -m "$(cat <<'EOF'
  docs(L4L0): methodology refinements from a studied reference agent's own techniques

  Four new severity-calibration rules (trusted-controller-mediated
  interfaces, multi-tenant resource-reuse, non-repudiation carve-out,
  attacker-position-by-trust-barrier), an exhaustive same-contract
  call-site sweep technique for source-aware review, an adversarial-sweep
  planning discipline against recon-driven tunnel vision, a cross-agent
  report-deduplication discipline for independent children confirming the
  same defect, and DOM Clobbering in xss.md. All optional methodology
  guidance the agent may apply - nothing here is a mandatory gate.

  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  EOF
  )"
  ```

---

## Final Check

- [ ] `uv run pytest -q -m "not integration and not live"` — full suite green.
- [ ] `uv run ruff check src/lalo tests/lalo scripts` — zero errors.
- [ ] `uv run ruff format --check src/lalo tests/lalo scripts` — no reformatting needed.
- [ ] `uv run mypy` — no errors.
- [ ] `git diff --name-only <base-commit>..HEAD | xargs grep -niE "shannon|pentestgpt|\bstrix\b|\bpentagi\b|\bcai\b" || echo clean` — expect clean.
- [ ] `git fsck --full` — zero errors.
- [ ] Confirm every new opt-in field/tool defaults non-restrictively: `record_safe` is
  never required, `browser_url`/`success_url_contains` default to `None` (no behavior
  change to any existing scheme), `retryable` defaults `True` (no behavior change to
  any existing failure classification), the scratch-directory convention is prompt
  guidance only, never an enforced jail.
- [ ] One live-eval run (an on-demand lab target) exercising: `record_safe` actually
  getting called by the agent for at least one clean surface, the new report sections
  rendering with real data, and — if a suitable SSO-shaped lab target is available —
  the browser-login preflight path.
