---
title: Phase 1 Decisions
tags: [reachagent, decision-log, phase1]
---

# Phase 1 — Decision Log

Decisions made during Phase 1 scaffolding. Scope is *decisions*, not full
implementation summaries. Plan references are to `docs/reachagent-final-plan.md`.

## Task 1 — Execution layer (scope · firer · audit)

- **Gate ordering is the safety contract.** Every request runs
  scope → read-only-first → send, in that fixed order. A failure at any gate
  raises *before* any network I/O, so a rejected request never emits a packet.
- **Deny-by-default scope.** `ScopeGuard` allows a URL only if some rule matches
  it in full (host + optional port/path/scheme). Path matching is per-segment
  (`/api` does not match `/apixyz`) to avoid accidental widening.
- **Read-only-first is stateful, per endpoint.** A state-changing request is
  refused until a successful read-only request has "cleared" that
  scheme://host/path. Callers can flag a nominally read-only method (e.g. a GET
  with side effects) as `state_changing` so it is gated too.
- **Time requests with our own monotonic clock**, not httpx's `.elapsed`, because
  timing is load-bearing for the §7 timing-statistical oracle and shouldn't
  depend on client internals.
- **Audit every attempt** — fired, refused, or errored — and build endpoint keys
  from scheme/host/path only, excluding query/userinfo so secrets never land in
  logs.

## Task 2 — Identity & session management

- **Isolation by construction, not discipline.** Each identity gets its own
  `TokenStore` instance with no shared backing state, making cross-identity
  token bleed impossible rather than merely discouraged.
- **Secrets never enter the graph.** The `Session` node carries only a stable
  `token_ref`; the token value lives solely in the owning identity's isolated
  store and resolves only within it.
- **Never hardcoded, fail loud.** Credentials load from env or a local YAML
  secrets file with no default fallback — a misconfigured run raises
  `IdentityConfigError` instead of silently using a baked-in secret.
- **Password kept out of `repr`** on both `Credential` and `TokenStore`, so it is
  never echoed in logs, tracebacks, or test output.
- **Auth state resolution:** explicit `auth_state` wins; otherwise it is derived
  from role (`admin` → ADMIN, else USER).
- **Derived identities are first-class.** Identities spawned via a
  `derived_credential` edge are registered like seeded ones so the Coordinator
  can weight them heaviest in the §4 scoring rule.

## Task 3 — Recon / surface mapper

- **Declarative surface, generic mapper.** The endpoint/parameter/object
  inventory lives in `config/vampi-surface.yaml`, not in mapper code. The
  `SurfaceMapper` has no per-endpoint logic — a live OpenAPI ingest or crawl
  would feed the same `SurfaceSpec`, so nothing about VAmPI is baked into the
  class. Keeps §6's "absorb new classes into the schema, don't grow it" intact.
- **`can_call` is empirical or absent — never assumed.** A status is only ever
  written from an actual `FireResult`; `classify_can_call` maps a real HTTP
  status (2xx → allowed, 401/403 → denied, else inconclusive). If a probe never
  fires — out of scope, read-only-first refusal, transport error — no edge is
  written at all, rather than defaulting to a verdict. This is the load-bearing
  Task 3 DoD invariant.
- **Structure vs. authorization are two passes.** `map_structure` materializes
  every endpoint/parameter/object (including state-changing ones); `probe_can_call`
  fires only read-only endpoints. So a DELETE or `GET /createdb` still appears as
  a node with its accepts/returns edges, but carries no fabricated `can_call`.
- **Read-only-first honored twice.** Recon filters to read-only verbs *before*
  handing anything to the firer, and the firer's own gate is the backstop — a
  state-changing endpoint can't leak a packet during recon even if the filter
  regressed. Tests assert zero packets for `/createdb` and DELETE.
- **Templated paths need a real sample value.** `/users/v1/{username}` is probed
  only when a `sample_path_values` (or default) fills the placeholder; an
  un-fillable template is materialized structurally but skipped for probing —
  we won't invent a URL just to manufacture a status. Counted as
  `can_call_skipped_untemplated` in the run summary.
- **Auth header from the identity's own isolated store.** Each probe pulls its
  bearer token from that identity's `TokenStore` only (Task 2 isolation); an
  identity with no session simply probes unauthenticated, which is itself a
  valid empirical signal (typically `confirmed_denied`).
- **Single `can_call` edge per (identity, endpoint).** `set_can_call` overwrites
  a prior verdict instead of stacking parallel edges, so a re-probe updates the
  fact rather than accumulating stale ones — recon stays idempotent alongside
  the deterministic node ids.
- **Deferred:** `owns` edges (intended ownership per app roles) and object
  `owner_identity_ref` are left for the phase that needs cross-user BOLA
  modelling; Task 3's DoD names only accepts/returns/can_call.

## Task 4 — Payload library (tagged, VAmPI-relevant slice)

- **`payload_ref` is a handle, not an inlined exploit string.** The system's
  value is the tagging + oracle wiring (§9), so each entry references a payload
  by a stable ref (e.g. `sqli/error-based/quote-break`) rather than embedding
  the string. Keeps the library a routing index, not a copy of
  PayloadsAllTheThings, and keeps raw exploit strings out of source.
- **Authz classes carry a null sink, deliberately.** BOLA/IDOR/mass-assignment
  are differential *authorization* classes with no injection sink — none of the
  nine `SinkType` values models an object identifier. So their
  `inferred_sink_type` is `null`, and `get_payloads(class, None)` selects them.
  `sink_type=None` means "the sink-less classes", **not** a wildcard — a sinked
  class queried with `None` returns empty, so `None` can never leak a SQL entry.
- **SQLi + one XSS entry included beyond the three gate classes.** The Phase 1
  gate scores BOLA/IDOR/mass-assignment, but those are all sink-less, which would
  make the §9 sink-isolation invariant vacuous to test. VAmPI is genuinely
  SQLi-vulnerable, so a `sql` entry is on-target and gives the sink dimension
  real content; one `html_reflection` (XSS) entry makes "an html_reflection param
  never receives a SQL entry, and vice versa" a real, bidirectional test.
- **Oracle-confidence order is an explicit rank, definitive-before-statistical.**
  `get_payloads` sorts by a fixed ranking of the six §7 families
  (structural → execution → OOB → differential → business-rule → timing). The
  plan's one hard constraint is "OOB before pure timing" (timing's blind-only
  ceiling matches the published 0% naive-detection baseline, §5); the rest
  follows definitive-mechanism-first. `payload_ref` is the tie-breaker so
  ordering is deterministic run to run.
- **Malformed tags fail loudly at load.** An unknown `inferred_sink_type` or
  `oracle_type` raises `PayloadLibraryError` rather than silently never matching
  (or misrouting to the wrong oracle) — a typo surfaces as an error, not a
  quietly empty result.
- **Business-logic/race classes are absent by design.** They are
  request-sequencing / timing-delivery tests that skip `get_payloads` entirely
  (§9), so the library does not represent them.


## Task 5 — Explorer tool pipeline

- **Records/context/errors live outside `explorer.py`.** The role-boundary test
  (`test_tool_boundaries.py`) asserts the module exposes *exactly* four callables
  among non-underscore names. Any dataclass (`Candidate`, `FingerprintReport`) or
  exception defined in `explorer.py` — and even an enum *imported* by name
  (`SinkType`, `OracleMechanism` are callable) — would leak into that surface and
  break it. So records sit in `tools/candidate.py`, runtime state in
  `tools/explorer_context.py`, and enums are reached via module import
  (`_nodes.SinkType`) with the bare names annotation-only under `TYPE_CHECKING`.
- **The four tools take an `ExplorerContext` first.** The §13 manifest signatures
  (`fingerprint_parameter(endpoint, param)`, …) are what the MCP layer (Task 8)
  exposes once it binds a context; threading collaborators explicitly keeps the
  functions pure and testable, and the human/Coordinator-facing contract is
  unchanged.
- **Fingerprint gates the pipeline via an explicit `_fingerprinted` set, not via
  `inferred_sink_type`.** A legitimate fingerprint can resolve to *no* sink
  (`None`) — the authz classes have no injection sink — so "unknown sink" and
  "not yet probed" are different states. Only the latter blocks `fire_request`
  (raises `FingerprintRequiredError` before any I/O). Keying the gate on the sink
  value would wedge authz params forever.
- **Sink inference is a conservative positive-evidence heuristic.** A canary that
  provokes a SQL error string → `sql`; a canary reflected into an HTML
  content-type → `html_reflection`; otherwise `None`. Deeper probes
  (nosql/shell/ldap/template) are a later-phase concern — this Phase 1 heuristic
  only covers the sinks the shipped payload slice actually tags.
- **`classify_response` returns an inert `Candidate` by omission.** The type has
  no `status`/`confirm`/`write_finding` member, the module imports no validator
  symbol, and the candidate only *names* which oracle should judge it. The
  one-way candidate → oracle → finding gate is enforced structurally (asserted by
  a test), not by convention.
- **`_fire_with_value` passes httpx kwargs by explicit name.** Unpacking an
  untyped `**dict[str, object]` into the firer let mypy see `state_changing` as
  shadowable by a caller key; naming `params`/`headers`/`json` explicitly fixes
  the type and dedupes the identical location-branching in fingerprint and
  fire_request.


## Task 6 — Differential-diff oracle & verification engine

- **The decision table keys on `DiffExpectation`, not `DiffAxis`.** The three §7
  axes (cross-identity / cross-request / cross-condition) collapse to two
  invariant kinds — access-control (`PROBE_UNAUTHORIZED` / `PROBE_AUTHORIZED`)
  and injection (`RESPONSES_INVARIANT`). The axis is provenance only; the
  expectation drives the verdict. This is the concrete mechanism behind §7's "one
  generic mechanism, not per-class checkers" — one table serves BOLA/BFLA/
  mass-assignment/boolean-blind without branching per class.
- **`OracleVerdict` carries a four-value `FindingStatus`, not a bool, and the four
  statuses split into confirmed-fact vs. finding.** `confirmed_allowed` /
  `confirmed_denied` are confirmed *facts about a `can_call` edge* (§6), not bugs;
  only `confirmed_violation` is a finding. So `OracleVerdict.is_violation` — not
  `.confirmed` — is what gates `write_finding` (Task 7). A `confirmed_allowed`
  verdict has `confirmed=True` but `is_violation=False`.
- **`decide()` is a pure, total free function.** Extracted from the oracle so the
  four-status table is exhaustively testable without verdict/registry plumbing,
  and so "zero LLM input in the decision path" is literally inspectable: it's
  status-code normalization + whitespace-only body comparison, nothing else.
- **Body comparison is whitespace-normalization only — deliberately non-fuzzy.**
  Semantic normalization (stripping volatile timestamps/nonces/CSRF tokens) is
  the caller's responsibility, kept out of the oracle so the comparison stays
  exact and auditable. No fuzzy/semantic/model-based matching, which would
  compromise determinism.
- **Missing/errored baseline → `inconclusive`, never a guess.** An access-control
  diff with no valid owner/authorized reference to diff against yields no verdict.
  Absence of a clean signal is never reported as "safe" — this is what keeps the
  toggle-off run at zero confirmed findings (the Phase 1 gate).
- **The "only path to confirmed" proof is an AST walk, not an import check.**
  `test_only_the_oracle_family_constructs_a_verdict` parses every production
  `.py` and asserts `OracleVerdict` (the sole type carrying `.confirmed`) is
  constructed in exactly one file (`oracles/differential.py`). Since `run_oracle`
  is the only tool invoking `Oracle.run`, that proves no other code path can mint
  a confirmed result — the same spirit as Task 5's `classify_response` proof,
  strengthened to a whole-tree check.
- **`OracleVerdict` is frozen; unknown mechanism and wrong evidence type both
  raise.** A verdict can't be mutated into a different outcome after the fact; an
  unregistered mechanism raises `UnknownOracleError` (explicit "not built yet")
  and mis-typed evidence raises `TypeError` — neither degrades to a silent
  `inconclusive`, since both are wiring bugs, not weak signals. `validator.py`
  reaches oracles/mechanisms via module aliases so its tool surface stays exactly
  `{run_oracle, write_finding, mark_inconclusive}` (same boundary discipline as
  the Explorer).


## Task 7 — Validator tools (write_finding / mark_inconclusive)

- **The finding gate is on `verdict.is_violation`, not `verdict.confirmed`.** A
  `confirmed_allowed`/`confirmed_denied` verdict is a confirmed *fact* about a
  `can_call` edge (§6), not a finding — so `write_finding` refuses it exactly as
  it refuses `inconclusive` or a raw `Candidate`. Only `confirmed_violation`
  passes. This is the Task 6 decision cashed out at the commit boundary.
- **A raw candidate is rejected before the violation check.** `write_finding`
  first checks the argument *is* an `OracleVerdict` (via a runtime type handle
  from `validator_support`, not a name-bound class — see below), then checks
  `.is_violation`. So an Explorer `Candidate`, which carries no verdict at all,
  can never be written; the type check fails first.
- **Defense in depth: the store independently refuses non-violation findings.**
  `ReachabilityGraph.add_finding` raises unless `finding.status is
  CONFIRMED_VIOLATION`. Combined with Task 6's AST-checked invariant (only an
  oracle constructs an `OracleVerdict`) and the run_oracle-only dispatch, a
  finding physically cannot enter the graph without a real confirmed violation —
  the CLAUDE.md non-negotiable has two independent guards, not one.
- **`write_finding` stamps provenance from the verdict.** The persisted `Finding`
  takes its `status` (confirmed_violation), and — when the caller left them blank
  — its `oracle_used` and `evidence_ref`, from the verdict itself, so the node
  reflects what was actually confirmed rather than whatever a caller defaulted.
- **`mark_inconclusive` reuses the single `can_call` edge slot.** It writes an
  `inconclusive` status back onto the edge (overwriting any provisional status,
  never stacking a parallel edge), so the Coordinator's scoring won't re-select
  it. Verified by re-query: `can_call_status` returns `inconclusive` afterward.
- **`validator.py` keeps its exact three-callable surface.** The gate error
  (`UnconfirmedFindingError`) and the `OracleVerdict` type handle live in
  `tools/validator_support.py` and are reached via a module alias — a name-bound
  exception or class is callable and would leak into the role-bounded tool
  surface that `test_tool_boundaries.py` pins. Same discipline as Explorer (Task
  5) and the run_oracle wiring (Task 6). Findings persist idempotently by
  `finding_id(vuln_class, evidence_ref)`.

## Task 8 — MCP server (`reachagent-mcp`)

- **The bare §13 contract is achieved by binding, not re-signaturing.** Each MCP
  tool is a thin wrapper that closes over one server-side `ExplorerContext`/graph
  and exposes only the domain arguments (`fingerprint_parameter(identity,
  endpoint_node, param_node)`, …). The `ctx`/`graph` first-args that the Task 5/7
  functions take are bound at registration, so the signature a human calls today
  is identical to what the Phase 5 Coordinator will call — no handoff change, as
  the DoD requires.
- **In-flight objects pass by server-side handle, never over the JSON wire.**
  `FireResult` (carries `httpx.Headers` + raw `bytes`) and `OracleVerdict`
  (frozen, oracle-minted) have no JSON schema. So `fire_request` returns a
  `fire_ref` that `classify_response` consumes, and `run_oracle` returns a
  `verdict_ref` that `write_finding` consumes. This isn't a workaround — it's how
  the Coordinator (also a JSON tool-caller exchanging refs, not Python objects)
  will chain them, which is *why* the contract survives the handoff.
- **The handle indirection preserves the Task 6 AST invariant across the wire.**
  `OracleVerdict` may be constructed only in `oracles/differential.py`
  (AST-checked over all of `src/`, `server.py` included). If the MCP layer rebuilt
  a verdict from JSON, a human could hand `write_finding` a fabricated "confirmed"
  verdict and bypass deterministic verification. Keeping the real verdict
  server-side behind an opaque `verdict_ref` means `write_finding` is reachable
  *only* by a verdict a genuine `run_oracle` minted — the gate stays exactly where
  the tests put it.
- **Only evidence is reconstructed from JSON, never a verdict.**
  `DifferentialEvidenceInput` is a flat DTO the oracle's own
  `DifferentialEvidence`/`Observation` dataclasses are rebuilt from; FastMCP
  delivers the nested arg as a dict, so the wrapper coerces dict→DTO defensively.
  Evidence is oracle *input*; the verdict is still minted solely inside the oracle.
- **Role boundary is re-checked after registration, not just at module level.**
  `test_mcp_server.py` asserts the registered set is exactly the four Explorer +
  three Validator tools and disjoint from the Coordinator tools — so MCP wiring
  can't leak a confirming tool onto the Explorer side even though the structural
  `test_tool_boundaries.py` already pins the module surfaces.
- **Scope allowlist is deny-by-default at startup.** `_build_context` reads
  `REACHAGENT_SCOPE_HOSTS` (comma-separated); if unset it defaults the allowlist
  to *only* the target host, never wider. A misconfigured server fires nothing
  rather than somewhere unintended (§10).
- **`FastMCP`/`mcp` imported lazily inside `build_server`.** Importing this module
  to introspect the tool set stays cheap and side-effect-free; the SDK is only
  touched when a server is actually built.
- **Verified hand-callable for real**: a subprocess launch of `reachagent-mcp`
  over stdio answered a real `ListToolsRequest` (7 tools) and `CallToolRequest`
  (`get_payloads` → structured result, `isError: False`) — exactly the path
  Claude Code drives.


## Task 9 — VAmPI evaluation harness (Phase 1 numeric gate)

- **Measured result: gate PASSED.** Toggle ON — precision 100% (3/3), recall
  100% (3/3) on bola/mass_assignment/idor; toggle OFF — 0 confirmed findings.
  Thresholds were ≥90% precision, ≥80% recall, exactly zero off. Both runs
  driven end to end through the Task 8 MCP tools via `mcp.call_tool`.
- **Detection runs through MCP; setup does not.** `/createdb`, login, the
  malicious register, and the IDOR password-write happen directly over HTTP —
  they are target manipulation, not ReachAgent's detection. Every
  fingerprint/fire/oracle/finding call goes through `mcp.call_tool` (the real
  dispatch boundary a Claude Code client or the Phase 5 Coordinator hits). This
  mirrors the Task 3 recon/detection split. It is also forced: `fire_request`
  injects a single parameter and is not a general HTTP client that can build
  VAmPI's multi-field register/login bodies.
- **Confirmation is always a read-only re-read, never the mutating response.**
  A naive diff of the password-PUT response *false-positives on the secure
  toggle* (secure VAmPI still returns 204; it just changes the caller's own
  password). So IDOR/mass-assignment confirm via an independent read-only
  `/users/v1/_debug` re-read fed to the differential oracle — exactly §5's
  "re-read confirming the effect." This is what keeps the toggle-off run at zero.
- **`run_oracle` gained fire_ref body-diff + JSON projection + record select.**
  The Task 8 handle design keeps response bodies server-side; to diff them the
  oracle wrapper resolves `baseline_fire_ref`/`probe_fire_ref` server-side (a
  secret body never crosses the wire to be echoed back — §10), optionally
  projecting one JSON field (`secret`/`admin`/`password`) and optionally
  selecting one record from a list body (`username:name2`) so a single `_debug`
  dump confirms a change to *one* user without positional indexing. Evidence
  only — never a verdict (the Task 6 AST invariant still holds; `_project`/
  `_select_record` construct no `OracleVerdict`).
- **Cross-identity fires share one handle registry + graph.** BOLA diffs two
  GETs made under *different* identities; each identity fires through its own
  token-authenticated firer (the §10 isolated-session model), but all sessions
  share one `_SharedState` (fires, verdicts, counters, graph) so `run_oracle`
  can resolve both refs and findings aggregate in one graph. Each scored class
  gets a fresh `_SharedState` so the IDOR write can't perturb another class's
  baseline.
- **Two containers, one per toggle.** ON = the running `erev0s/vampi` on :5000
  (`vulnerable=1`); OFF = a second container on :5002 (`vulnerable=0`). The
  identical tool sequence runs against both, so the only variable is the
  target's behaviour — which is what makes the toggle-off zero a real control.
- **Reproducibility.** Each run re-seeds via `/createdb` and rediscovers the
  per-seed randomised book titles live, so titles are never hardcoded. VAmPI's
  threaded dev server can 500 on `/createdb` while still repopulating, so the
  harness does not assert that status — the subsequent logins are the readiness
  check. The gate is a pytest (`test_live_vampi_phase1_gate`) that skips cleanly
  when VAmPI isn't reachable, plus pure metric unit tests that need no target.
- **Scope: bola/idor/mass_assignment only.** JWT is deferred past Phase 1 with
  the structural oracle family (docs/phase1-tasks.md scope note); VAmPI's other
  toggled behaviours (SQLi, user/password enumeration, RegexDoS) are outside the
  Phase 1 differential-oracle scope and are not scored.

- **`docker-compose.yml` at repo root replaces the manual `docker start
  vampi-secure` step.** Task 9 left the eval environment as two hand-started
  containers (the vulnerable one on `:5000`, a manually-started secure one on
  `:5002`). That is now codified: `docker compose up -d` brings up both
  instances — `reachagent-vampi-vulnerable` (`vulnerable=1`) on `:5000` and
  `reachagent-vampi-secure` (`vulnerable=0`) on `:5002` — matching exactly the
  URLs the harness (`reachagent.eval`) and the live gate test default to. Both
  use `tokentimetolive=3600` so tokens don't expire mid-run. No more manual
  `docker start`; the eval environment is one reproducible command.
