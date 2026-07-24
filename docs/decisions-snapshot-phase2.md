---
title: Phase 2 Decisions
tags: [reachagent, decision-log, phase2]
---

# Phase 2 — Decision Log

Decisions made during Phase 2 implementation. Scope is *decisions*, not full
implementation summaries. Plan references are to `docs/reachagent-final-plan.md`;
task references are to `docs/phase2-tasks.md`.

## Task 1 — Finding-relationship + ownership graph layer at the store

- **`set_owns` mirrors the fact to both an edge and the object attribute.** The
  `owns(Identity → Object)` edge and `Object.owner_identity_ref` carry the same
  fact by two access paths: a graph walk (`owns_edges`) and a direct read off the
  object node (`owner_of`). Both are written in one method so they can't drift
  apart. A BOLA diff needs "who owns O" cheaply while holding only the object, so
  the attribute is not redundant — it's the ergonomic read path; the edge is the
  traversable one.
- **Ownership is declared, never inferred — mirroring `can_call`'s
  empirical-or-absent rule.** `set_owns` takes an explicit owner and stamps it;
  it has no code path that guesses. An object with no declared owner keeps
  `owner_identity_ref = None`, and `owner_of` returns `None` to mean *undeclared*,
  not *public*. Phase 1's Task 3 established this for `can_call` ("empirical or
  absent, never assumed"); the same discipline is why the store-level writer here
  refuses to default an owner. (Who supplies the owner — recon reading the app's
  own response — is Task 2's problem, deliberately kept out of the store.)
- **The finding-relationship edges are gated on real `Finding` nodes at the
  store, `_require_finding`.** `add_enables` requires *both* endpoints to be
  committed `Finding` nodes; `add_derived_credential` requires the source to be a
  `Finding` and the spawned target to already exist. This extends the CLAUDE.md
  non-negotiable ("a finding only exists via a confirmed oracle verdict") into the
  chain layer: an `enables` edge can only ever connect two confirmations, so a raw
  candidate can't be smuggled into an attack path by drawing an edge to it. The
  guard is at the store because the store is the last line — same rationale as
  `add_finding` refusing a non-`confirmed_violation` status independently of
  `write_finding`.
- **A derived credential is a first-class node via the *normal* query, not a
  parallel "derived" store.** `add_session`/`add_identity` are the single writers
  for both seeded and spawned nodes, and `sessions()`/`identities()` return both
  kinds undifferentiated. The §8 requirement that the Coordinator "treats a
  derived credential as first-class" then falls out for free: there is no second
  code path to keep in sync, and provenance (seeded vs. derived) lives on the node
  dataclass (`Provenance`) plus the incoming `derived_credential` edge, not in
  which collection holds it.
- **`add_session` writes the `authenticates_as` edge in the same call.** A
  `Session` is meaningless without the `Identity` it acts as, so the node and its
  `authenticates_as(Session → Identity)` edge are written together rather than
  leaving a caller to add the edge separately and risk an orphan session. Keyed by
  `token_ref` (`session_id`), so re-adding is idempotent like every other node.
- **Secrets stay out of the graph, unchanged from Phase 1.** The `Session` node
  still carries only `token_ref` (a handle), never the token value — Phase 2 adds
  session *nodes* to the store but does not change what a session node may hold
  (§10). A store-level test asserts no `Session` field carries a secret.
- **No new node/edge types — the additions are all already in §6.** `enables`,
  `derived_credential`, `owns`, and `Session`/`authenticates_as` were defined in
  the Phase 1 enums/dataclasses but had no store writers; Task 1 is writers +
  queries only. This keeps the CLAUDE.md "new node/edge types need explicit
  justification" bar untouched — nothing new to justify.
- **Tests live in `tests/phase2/`, not `tests/phase1/`.** New package mirroring
  the `tests/phase1/` convention, so the Phase 2 gate (§14/§15) can be run as its
  own selection (`uv run pytest tests/phase2/`) exactly as Phase 1's gate is. The
  file was initially created under `phase1/` and moved; the move was a plain `mv`
  (the file was still untracked, so `git mv` refused it) — noted only because the
  first attempt looked like it should have been `git mv`.

## Task 2 — SurfaceMapper ownership extension (recon populates `owns`)

- **Ownership is a discovery *recipe*, not a static owner field.** The load-bearing
  Task 2 decision: on a stateful target the vehicle/report→user association is
  created at runtime during signup/onboarding — there is no owner to write into
  YAML in advance. So `ObjectSpec.ownership` carries an `OwnershipDiscovery`
  (`reveal_path`, `reveal_method`, `owner_field`, `requires_session`) declaring
  *how to read* ownership off the app's own response, never *who* owns it. This is
  what keeps "declarative surface" honest for a target where ownership isn't
  declarable ahead of time.
- **Ownership discovery is a third empirical pass, parallel to `probe_can_call` —
  not part of `map_structure`.** Phase 1's "structure vs. authorization are two
  passes" invariant is preserved: `map_structure` stays pure node/edge
  materialization with zero I/O, and `discover_ownership` fires reveals and writes
  `owns` from observed responses. `run` is now structure → `can_call` → `owns`.
- **The reveal must be read-only, enforced at construction.** `OwnershipDiscovery.
  __post_init__` rejects a non-read-only `reveal_method`, so a state-changing
  "reveal" can't violate read-only-first the moment discovery runs (§10). The
  reveal still goes through Task 1's firer, so scope + read-only-first gate it
  regardless — the constructor check just fails louder and earlier.
- **`requires_session` models the "after which workflow step" clause as
  empirical-or-absent.** A session-gated reveal for an identity with no session
  yet is *skipped* (counted `owns_skipped_no_session`), writing no edge — the same
  discipline as `can_call` (an unfired probe writes nothing). Onboarding (Task 6)
  establishes the session; before it runs there is simply no association to read.
  So the mapper consumes the authenticated session onboarding produces but does
  not itself perform login/register — that setup is authorized target manipulation
  (the Phase 1 eval-harness split), not detection.
- **Two ownership modes, both reading the response.** Caller-scoped
  (`owner_field is None`): a 2xx reveal means the authenticated caller owns what
  was returned to them, so the owner is the caller. Named-owner (`owner_field`
  set): the field's value in the JSON body is matched to a *seeded identity's
  username* (translated via the credential, since the graph keys identities by
  seed name); an absent field or an unrecognized value writes no edge
  (`owns_skipped_unresolved`) rather than guessing an owner.
- **The mapper names no target — in code *or* comments.** Task 2's DoD calls for a
  grep of `mapper.py` for target-specific identifiers to stay clean, and a Task 2
  test enforces it literally (whole file, not just code). Honoring that meant
  genericizing docstrings too, including two pre-existing VAmPI mentions
  (`/createdb` example, a `config/vampi-surface.yaml` pointer) that predated this
  task — so the guarantee is "the generic mapper mentions no target anywhere,"
  which is stronger and easier to keep true than "no target-specific *logic*."
- **`_object_spec` coerces `sensitivity_tier` through `str` before `int`.**
  Extracting the object parser gave its input a precise `Mapping[str, object]`
  type (the old inline loop var was untyped `Any`), so `int(object)` no longer
  type-checks. `int(str(...))` matches how a YAML scalar actually arrives and is
  mypy-clean — chosen over an `Any`-cast that would have hidden the coercion.

## Task 6 — crAPI recon (consume the ownership recipe against live crAPI)

- **Surface is driven from crAPI's own OpenAPI spec, not memory.** The two BOLA
  flows in `config/crapi-surface.yaml` (vehicle-location, mechanic-contact) were
  extracted from crAPI's shipped `openapi-spec/crapi-openapi-spec.json` and
  verified against the live API, so paths/params/response fields are ground truth,
  not recalled. The exact seed credentials (`adam007@example.com` / `adam007!123`,
  `pogba006@example.com` / `pogba006!123`, mechanic `jhon@example.com` / `Admin1@#`)
  came from crAPI's `TestUsers.java` / `apps.py`, not guessed defaults (the
  guessed ones — `Victim!123`, `Adam!123` — all 401'd).
- **The vehicle reveal is caller-scoped (`owner_field: null`), confirmed live.**
  crAPI's `GET /identity/api/v2/vehicle/vehicles` returns only the caller's own
  vehicles (the list-view `owner` is null), so a 2xx *with a vehicle in it* means
  the caller owns it. This is exactly the Task 2 caller-scoped mode; no owner is
  named in config.
- **Live-caught correctness bug: a caller-scoped 2xx is NOT ownership if the
  reveal body is empty.** The first live run wrote three `owns` edges — including
  one for the *mechanic*, whose `/vehicles` returns `[]` (200, no vehicles). The
  Task 2 caller-scoped path returned the caller on any 2xx. Fixed in
  `_resolve_owner` via a new `_reveal_has_resource`: an empty list/object/`null`/
  non-JSON body is *no association*, so it writes no edge and counts as
  `owns_skipped_unresolved`. A hermetic mock with a non-empty body never exercised
  this — only the live empty-reveal did. Regression test added to the Task 2 suite
  (`test_caller_scoped_empty_reveal_writes_no_edge`) plus the live assertion that
  the mechanic gets no edge.
- **Onboarding vs. recon split, reused from the Phase 1 eval harness (Task 9).**
  `crapi_recon._onboard` logs each identity in *directly over HTTP* and stores the
  bearer token in that identity's isolated `TokenStore` — authorized setup, the
  "after which workflow step" the ownership recipe's `requires_session` waits on.
  Everything the graph is built from (structure, `can_call`, `owns`) runs through
  the mapper's scope-guarded, read-only-first firer. This is what makes "zero
  destructive side effects" a real, auditable property, not a claim:
  `ReconResult.destructive_actions` filters the audit log for any fired non-GET
  and the Task 6 test asserts it is empty.
- **State-changing crAPI endpoints are materialized but never fired.** signup,
  login, and `contact_mechanic` appear as nodes (so the graph knows the surface)
  but recon skips probing them (`can_call_skipped_state_changing == 3`), and the
  firer's own gate is the backstop. The login/signup the *harness* performs are
  setup, done by `_onboard`, not by recon.
- **crAPI comes up from its own upstream compose via `include`, not a re-declared
  service.** crAPI is a 10-service stack, so `docker-compose.crapi.yml` `include`s
  the user's local crAPI compose through `${CRAPI_COMPOSE_PATH:?...}` — which
  fails *loud* if unset rather than silently coming up empty. The VAmPI
  `docker-compose.yml` is untouched and still validates independently. The path is
  machine-specific by nature, so it's an env var, never hardcoded into the repo.
- **The live test skips cleanly when crAPI is down.** `test_live_crapi_recon` is
  gated on a 2s reachability probe (same pattern as the VAmPI live gate), so the
  suite stays green on a machine without crAPI while remaining the reproducible
  recon check when it's up.
- **Known limitation handed to Task 7: `Object` nodes are keyed by type, so both
  owners' vehicles collapse to one `object:vehicle` node.** `owns_edges()`
  correctly carries *both* owner→vehicle edges, but `owner_of` (a single stamped
  attribute) reflects only the last writer. The per-instance object identity the
  vehicle-location BOLA needs (adam's vehicle vs. pogba's, by UUID) is a Task 7
  concern — flagged here rather than silently widened into Task 6.

## Task 7 — Per-instance object node identity at the store

- **`object_id(type, instance_key=None)` — additive keying, not a rewrite.**
  Absent key returns `object:{type}` (unchanged, so VAmPI and the structural pass
  are untouched); a set key returns `object:{type}:{instance_key}`. That is the
  whole store change — two instances of a type become two nodes, which is the
  anchor cross-user BOLA needs ("identity B reaches identity A's *instance*", §8).
- **`instance_key` is a new `Object` *attribute*, not a new node type.** §6
  discipline: the schema doesn't grow a node/edge kind. Justified because BOLA
  operates on object instances by definition (§5/§8), recorded here per the
  CLAUDE.md "new node/edge types need explicit justification" bar.
- **The instance key is read from the app's own response, never fabricated.** The
  recipe gains `instance_key_field` (e.g. `uuid`); discovery keys each resource in
  the reveal by that field's value. A resource missing the field is skipped, never
  keyed by position — same empirical-or-absent discipline as ownership itself. A
  reveal that yields no ownable instance is `UNRESOLVED`.
- **`owns_discovered` now counts edges, not identities.** A caller owning N
  instances contributes N. `_discover_one_owner` returns an `_OwnResult`
  (outcome + `edges_written`) rather than a bare enum, so the summary stays honest
  for the per-instance case without a second traversal.
- **Type-level and per-instance are one code path, split only by the recipe.**
  `instance_key_field is None` runs the pre–Task 7 type-level writer (one edge to
  the type node); set runs the per-instance writer. No per-object or per-target
  branch — the generic-mapper grep test still passes (the docstrings say
  "resource `uuid`", not "vehicle").
- **Live-confirmed against crAPI.** adam and pogba resolve to two distinct
  `object:vehicle:{uuid}` nodes, each with its own `owner_of`; the collapse Task 6
  flagged is gone. The Task 6 hermetic test that asserted the flat `object:vehicle`
  node was updated to the per-instance id — the only Task 6 test that changed.

## Task 5 — Business-logic 4-template invariant library + oracle

- **One generic oracle backs all four templates; the rule is provenance, not an
  input.** The four invariants (single-use reuse, quantity/limit, price/parameter
  tamper, step-order) reduce to one security invariant — *a secure app must refuse
  the rule-breaking action* — so `business_rule.decide` has **no per-rule branch**:
  it checks a legitimate baseline was accepted (2xx) and whether the rule-breaking
  action was then accepted (violation) or refused (denied). `BusinessRule` is
  recorded on the verdict/finding for provenance, exactly as `DiffAxis` is for the
  differential oracle ("the axis is provenance only; the expectation drives the
  decision"). This keeps the six-family §7 set honest: one new *mechanism*, not
  four.
- **The `OracleVerdict`-constructor AST test now allows the whole `oracles/`
  package, not one file.** Phase 1 asserted verdicts are minted only in
  `oracles/differential.py`. The real invariant is "only an oracle *family* mints
  a verdict"; Phase 2's business-rule family is a second legitimate minter, so the
  test asserts the constructor set is exactly the two family files *and* that every
  path is under `oracles/` — the guarantee that no tool/recon/graph module mints a
  confirmation is unchanged, just no longer pinned to a single family.
- **Templates are recognizers over the graph, not hand-written per-target checks.**
  Each template reads only resources recon materialized (parameters/objects/
  endpoints) and matches them with *generic commerce vocabulary* (`coupon`,
  `quantity`, `price`, an ordered flow), never a target name — a grep of the
  library for target identifiers is clean, mirroring the Task 2 mapper discipline.
  A surface with no consumable/limited/priced/ordered resource instantiates
  nothing (empirical-or-absent, like `owns`/`can_call`). Recognition emits a
  *plan*; it fires nothing.
- **Step-order is the runtime-dependent template (same pattern as ownership
  discovery).** It does not read an `order:` field: the recognizer only proposes
  the *candidate* flow — the ordered state-changing endpoints recon surfaced — and
  marks the final step `VIOLATING` (the out-of-order jump), leaving whether the
  jump is actually served for the app's own response + the oracle to decide. A
  surface with fewer than two ordered state-changing steps has no flow, so nothing
  instantiates.
- **Firing is a separate sequential runner, so the §10 safety story is auditable,
  not asserted.** `SequentialReplayRunner` fires a check's steps strictly one after
  another through the ordinary scope+read-only-first firer — no concurrent/single-
  packet delivery (that race escalation is the deferred Phase 6 module). Before any
  state-changing step it fires a read-only probe of the same endpoint, so the
  firer's read-only-first gate is satisfied by observation; the gate is the backstop
  that refuses an uncleared mutation before any packet leaves. The Task 5 tests
  assert both directly from the audit log (a read-only `fired:` precedes every
  mutating `fired:`; no `refused_read_only_first`; entries are discrete and ordered).
- **The runner produces evidence and stops; it never decides.** It hands
  `BusinessRuleEvidence` to `run_oracle` (the Validator's sole confirmation path)
  and returns the verdict; `write_finding` stays gated on `is_violation`. So a
  confirmed business-logic violation is reachable only via `run_oracle` →
  `write_finding`, with no LLM in the decision path — the same guarantee as the
  differential oracle.
- **New store query `objects()`, no schema growth.** Templates enumerate object
  nodes to spot priced/consumable resources; `objects()` mirrors the existing
  `identities()`/`sessions()` node-kind queries (read-only, returns type-level and
  per-instance nodes alike). No new node/edge type — the §6 bar is untouched.

## Task 3 — Neo4j store backend via the neo4j-cypher MCP tool

- **Neo4j I/O goes through the *same* MCP server the agent uses, driven by the
  `mcp` client SDK — there is no `import neo4j`.** The plan says the store
  "migrates to Neo4j via Neo4j MCP" (§13). MCP tools are agent-callable, not
  library-callable, but the neo4j-cypher server is a stdio process
  (`uvx mcp-neo4j-cypher`); Python drives it as a *client* (`stdio_client` +
  `ClientSession`), calling the server's `read_neo4j_cypher`/`write_neo4j_cypher`
  tools. So "all Neo4j I/O goes through the MCP tool, no direct bolt driver" is a
  structural property (an AST test scans `src/reachagent` for any `neo4j` import
  and asserts none), not a convention. Same server block as `~/.claude.json`.
- **The store depends on a `CypherExecutor` interface, not a transport.** The
  Neo4j store emits parameterized Cypher and hands it to an injected executor
  with two methods (`read`/`write`) mapping one-to-one to the two MCP tools. The
  only production executor is `MCPCypherExecutor`; a test could substitute an
  in-memory one without a live database. This is the seam that keeps "all I/O
  through the MCP tool" true without coupling the store to the SDK.
- **Sync-caller ↔ async-stdio bridge: one background loop thread, one warm
  session — and open/close must be the *same* task.** pytest and the future
  Coordinator are synchronous; the MCP client is async. `MCPCypherExecutor` owns
  a thread running one asyncio loop with a single long-lived `ClientSession`, so
  `uvx` is spawned once per executor, not per query. The load-bearing subtlety
  (found live via a teardown `RuntimeError: Attempted to exit cancel scope in a
  different task`): the MCP client's anyio scopes must be entered and exited by
  the *same* task. The fix is a single driver coroutine that opens the session,
  signals ready, `await`s a shutdown event, then closes — never a second
  `run_until_complete` for teardown. Calls are submitted with
  `run_coroutine_threadsafe` and block on the future.
- **Both backends share the `*_id` helpers, so node identity is backend-
  identical.** `Neo4jGraphStore` imports `endpoint_id`/`object_id`/… from
  `store` and stores them as the `id` property under a single `:Node` label with
  a `kind` discriminator (mirroring the NetworkX `_KIND` tag) — no label-per-type
  sprawl (§6). Typed edges are one `:REL` type carrying a `type` property, keyed
  by MERGE on `(src, dst, type)`, so re-adding is idempotent exactly like the
  NetworkX MultiDiGraph keyed on `(u, v, key)`. That shared keying is what lets
  the parity test assert `nx_ids == neo_ids` and equal query results.
- **Multi-hop traversal is one variable-length Cypher path query, not
  client-side hop reassembly.** `chain_paths` uses `-[rels:REL*1..]->` filtered
  to the two chain edge types, with an acyclic guard and a `NOT (leaf)-->()`
  maximal-path filter, returning `[n IN nodes(path) | n.id]` per leaf — the whole
  reason the finding-relationship layer moves to Cypher (§8/§12). A test asserts
  structurally that the method issues exactly one `read` and contains `*1..`. The
  NetworkX side keeps a client-side DFS as the *reference*; a parity test asserts
  the two produce identical paths on the same graph.
- **Parity, not cutover — NetworkX stays the default.** The Neo4j backend is
  opt-in via an injected executor; nothing in recon/execution/oracles switches to
  it. The contract suite runs the *same* test bodies against both via a
  parametrized `backend` fixture; the Neo4j parametrization is gated on a live
  bolt endpoint *and* `NEO4J_PASSWORD` (the credential the MCP server needs),
  passed via env at run time, never hardcoded — same discipline as the live crAPI
  gate. Green both ways: skips cleanly with no Neo4j, runs when it is up.
- **Secrets stay out of the graph on both backends, verified symmetrically.** A
  `Session` node stores only `token_ref`/`identity_ref`/`live` — never a token
  value — and values are passed as Cypher *parameters*, never interpolated into
  the query string. The parity test reads the stored node's properties on each
  backend (`vars(session)` for NetworkX, `properties(n)` for Neo4j) and asserts
  the property set is a subset of the three secret-free fields.
- **Config refuses to guess a credential.** `MCPCypherExecutor` has no baked-in
  default password; an absent `NEO4J_PASSWORD` is a loud `CypherExecutionError`
  at `__enter__`, never a guessed default — the read-only-first "empirical or
  absent, never assumed" discipline applied to connection config. A tool error
  from the MCP server surfaces as `isError` and is raised, so a swallowed write
  failure can't let the store believe a node landed when it did not.

## Task 4 — Chain Solver (spawn-and-requery, §8)

- **One entry point, one branch — on structure, not vuln class.** `ChainSolver.advance`
  is the single spawn-and-requery mechanism §8 describes. Its only branch is on the
  `spawn` argument: `None` = self-escalation (mass-assignment — no new node, re-query
  the acting identity's own edges), `Session`/`Identity` = credential-yield (spawn the
  node + `derived_credential` edge, then re-query from the new identity). No
  per-class-pair `if xss then... elif ssrf then...` exists — the caller decides *whether*
  a credential was produced, which is a structural fact about the finding, not a label
  the solver switches on. Satisfies the DoD "class-agnostic, one entry point" clause and
  keeps the design goal of absorbing new classes without new code paths.
- **Solver is a graph-layer component; firing/oracle stay in Explorer/Validator.**
  `advance` never fires a request or calls an oracle — it mutates the store (spawn node,
  write edge) and *returns* the unexplored `(identity, endpoint)` candidates for the
  Coordinator to schedule. The role boundary (only Validator fires/oracles) is untouched.
  The Coordinator's own query/score stubs are Phase-5 and raise NotImplementedError, so
  Task 4 operates over the store's finding layer directly rather than through them.
- **Termination is empirical, not a fixed depth.** `_unexplored` skips any
  `(identity, endpoint)` pair that already carries a `can_call` verdict (written by the
  execution layer or a prior pass), so a re-query never re-opens a verdicted neighborhood
  — the graph's own write-back is the fixpoint signal. The §11 per-path budget is a
  second, independent halt: `advance` returns `[]` once `budget_remaining(path_id) <= 0`,
  and budgets are scoped per `path_id` so one exhausted chain never starves a sibling.
- **Chains persisted as connected `enables` edges, asserted by query not report.** `link`
  writes a Finding→Finding `enables` edge; a reconstructed chain is recovered via
  `graph.chain_paths(start)` / `enables_edges()`, never parsed from report text — the DoD
  "assert by querying the path" clause. The end-to-end test walks XSS → derived admin
  session → SSRF and asserts both the `derived_credential` hop and the `enables` hop show
  up in `chain_paths`.

## Task 8 — crAPI multi-step BOLA gate; Chain Solver adjacency bug caught here

The Phase 2 gate reconstructs **both** documented crAPI BOLA chains (vehicle-location,
mechanic-contact) end-to-end: recon → per-hop cross-identity differential → Chain Solver
linking. Standing it up against live crAPI surfaced a latent Chain Solver bug that Task 4's
own suite never exercised.

- **The bug: iteration-adjacency linking, not a precondition check.** The Task 4 linker
  wrote an `enables(A→B)` edge whenever B's finding was confirmed *after* A in iteration
  order — a proxy for "A enabled B" that happens to hold in the single credential-yielding
  case Task 4 tested, but is not a real data dependency. On crAPI it over-links: two
  independent vehicle-location BOLAs on distinct instances, each consuming only its own
  owner's key and leaking nothing to the other, got a spurious `enables` edge purely
  because they confirmed in sequence.
- **Why Task 4's tests passed it undetected.** Task 4 only exercised the *credential-
  yielding* branch (XSS → derived admin session → SSRF) against a false-positive case where
  a genuine dependency existed, so adjacency and real-precondition agreed. No test posed two
  *independent* findings that adjacency would wrongly link — the exact shape crAPI's two
  same-class vehicle instances produce. The gate's new
  `test_bola_enables_precondition.py::two independent instances get no edge` is the missing
  case; it fails on the old linker and passes on the fix.
- **The fix: link on a produced/consumed identifier match, order-independent.** The linker
  now writes `A→B` iff B *consumes* an identifier that A *produced* (`needed in produced[A]`),
  A≠B, and A did not itself consume that identifier (`consumed[A] != needed` — the direction
  guard that stops a co-consumer echoing its own input key from posing as a producer).
  Identifiers are extracted by *shape* (UUID / long opaque token / ≥4-digit numeric), never
  by target-specific field names, so it generalises. Iteration order is now irrelevant.
- **Chain 2's missing precondition — three options considered, two rejected.** With the
  linker fixed, chain 2 (mechanic-contact) had no producer to link: empirically, **no read-
  only crAPI endpoint discloses another principal's `report_id`**, and the report id is a
  short *sequential integer* (2, 3, 4) — so a cross-user read needs no disclosure at all.
  - *Rejected — option 1 (producer-seed node + edge):* model the out-of-band
    `contact_mechanic` setup as a new non-Finding "producer" node feeding an edge into the
    report BOLA. Rejected: it grows the §6 schema per-class (a new node kind), the exact
    thing the schema-absorption design goal forbids, to represent something that is attack
    *setup*, not a vulnerability.
  - *Rejected — option 3 (fire the setup POST out-of-band):* fire `contact_mechanic` once to
    obtain a real `report_id` producer. Rejected: `contact_mechanic` is state-changing, so
    firing it violates read-only-first (§10) — and it still would not be a
    `CONFIRMED_VIOLATION`, so it could never legitimately become a `Finding` anyway.
  - *Shipped — precondition classifier:* the detector classifies each confirmed hop by the
    *shape* of its consumed identifier — `direct` (none), `requires_disclosed_identifier`
    (unguessable UUID/opaque key → must be leaked upstream → a genuine two-finding chain), or
    `enumerable_identifier` (short/sequential → guessable, no producer needed). Chain 1's
    vehicle hops classify as disclosed and carry a real incoming `enables` edge from the
    community-feed leak; chain 2's report hops classify as enumerable and are recorded as a
    confirmed single-hop BOLA with that provenance stamped on the `Finding.metadata`
    (existing field — no schema growth), and **no** fabricated edge. Both chains are
    reconstructed truthfully within the existing schema; neither non-negotiable is touched.
- **The forbidden-edge assertion is what makes the regression test honest.** The gate
  asserts opposite requirements on the two chains: chain 1's vehicle findings *must* have an
  incoming `enables` edge (and a connected `chain_paths` through the producer); chain 2's
  report findings *must not* (`test_crapi_bola_gate.py:379`,
  `assert not any(dst == hop.finding_node for _, dst in enables)`). That negative assert is
  the specific mechanism preventing the test from being satisfied by a fabricated symmetric
  edge — if a future change re-introduces adjacency linking (or invents a chain-2 producer to
  make the two chains look alike), line 379 fails. A test that merely asserted "≥1 edge
  exists" would accept the over-linking bug; asserting a *specific absence* keyed on the
  shape-derived precondition does not.
- **`owns` is written uniformly for both vehicle and report objects — the
  disclosed-vs-enumerable distinction affects only whether an `enables` edge into the
  finding is warranted, not whether an `owns` edge exists.** The detector skips any object
  with no owner (`detector.py`, `owner_id is None → continue`), so *every* confirmed hop —
  vehicle and report alike — is anchored on an `owns` edge recon wrote from the app's own
  caller-scoped reveal (`mechanic owns object:service_report:2/3/4`, seen live). What
  differs between the chains is one layer up: the vehicle's unguessable UUID warrants an
  incoming `enables` edge (a producer disclosed it), the report's enumerable id does not.
