# Phase 2 — Graph + stateful chains: task list

Derived from `reachagent-final-plan.md` §6 (graph data model), §8 (chain
discovery), §7/§9 (business-logic templates), §12/§13 (Neo4j via MCP), and
§14/§15 (the gate). Each task's definition of done is a checkable invariant
from the plan, not "implement X." Ordered by dependency.

## Phase-level numeric gate

The single numeric gate for Phase 2 (§14, §15), verified verbatim by Task 8:

> 100% of crAPI's documented multi-step BOLA scenarios (vehicle-location and
> mechanic-contact chains) reconstructed end-to-end **via template match, not
> hand-coded per-scenario logic**; **zero** destructive side effects logged
> during the run.

Two halves, both load-bearing:
- **Reconstruction is generic.** A scenario counts as reconstructed only if it
  falls out of the graph + Chain Solver + template match — a `grep` for the
  scenario's crAPI-specific object ids / endpoint paths in Phase 2 detection
  code must come back clean. Per-scenario `if crapi_vehicle: …` branches fail
  the "not hand-coded" clause even if they produce the right finding.
- **Zero destructive side effects.** The full run's audit log (Phase 1 Task 1, §10)
  contains no `fired:` line for a state-changing request that was not first
  cleared by read-only-first and confirmed reversible — asserted against the
  log, not by inspection.

## Scope notes

- **crAPI's *documented* BOLA scenarios only.** The gate scores the two chains
  §14 names — vehicle-location and mechanic-contact. crAPI's other classes
  (SSRF, JWT, mass-assignment beyond BOLA) are Phase 3+/already-covered and are
  not scored here. The exact crAPI endpoint paths and object ids for the two
  chains are confirmed live during Task 6 recon, never hardcoded into detection.
- **Neo4j migration is trigger-based, not unconditional (§12, §15).** The plan
  migrates "once chain queries are the bottleneck." Task 3 makes the store
  swappable and stands up the Neo4j-MCP backend at parity; the NetworkX backend
  remains the default until the Chain Solver's `enables`/`derived_credential`
  traversal (Task 4) is the measured bottleneck. The migration DoD is *parity*,
  not *cutover*.
- **Business-logic templates are Partial support by design (§5).** The 4-template
  library covers the known pattern set (single-use reuse, quantity/limit, price
  tamper, step-order); novel business rules stay Weak/unsupported (§5) and are
  out of scope — a template only ever instantiates against a recon-discovered
  resource, never a hand-modeled per-target rule.

## Tasks

### 1. Finding-relationship + ownership graph layer at the store (§6, §8)
- `enables(Finding → Finding)` and `derived_credential(Finding → Session |
  Identity)` edges exist as typed store methods (Phase 1 defined the
  `FindingEdge` enum but the store wrote neither) — a test round-trips both and
  reads them back.
- The store can write an `owns(Identity → Object)` edge and set
  `Object.owner_identity_ref` (Phase 1 defined the `OWNS` enum member and the
  field but shipped no writer — `store.py` has no `add_owns`, confirmed by
  grep). This is the *store-level* writer only; populating it from recon is
  Task 2. With it, cross-user BOLA is posable as "identity A `owns` object O,
  identity B `can_call` the endpoint that `returns` O" without per-class logic.
- A `derived_credential` edge target is a real queryable node: writing one
  spawns a `Session`/`Identity` the graph returns from a normal query, so the
  Coordinator can treat it as first-class (§8).
- The Phase 1 non-negotiable still holds: the store refuses any `Finding` whose
  status is not `confirmed_violation`, and only `write_finding` writes finding
  nodes — a test re-asserts this after the schema grows.
- No new node/edge type beyond the §6 set is introduced (CLAUDE.md working
  conventions) — the additions are exactly `enables`/`derived_credential` plus
  the deferred `owns`/`owner_identity_ref`, all already in §6.

### 2. SurfaceMapper ownership extension — recon populates `owns` (§3, §6)
Phase 1's Task 3 decision log deferred `owns` edges and `owner_identity_ref` "for
the phase that needs cross-user BOLA modelling." Phase 2 is that phase, and the
crAPI gate's "generic, not hand-coded" clause forces ownership into the graph via
recon rather than a per-scenario constant — so the Phase 1 `SurfaceMapper` needs
a real change, tracked here with its own DoD instead of folded into Task 6.
- `ObjectSpec`/`SurfaceSpec` (recon's declarative input, `mapper.py`) can express
  an object's owning identity, and `map_structure` writes the `owns` edge +
  `owner_identity_ref` via Task 1's store writer — a test loads a surface with
  ownership and reads the `owns` edge back off the graph.
- Ownership stays declarative and generic: the mapper gains **no** per-endpoint
  or per-object branch (the Phase 1 Task 3 invariant — "declarative surface,
  generic mapper"), so the same code path serves VAmPI and crAPI. A grep of
  `mapper.py` for target-specific identifiers stays clean.
- Ownership is never fabricated: an object with no declared owner in the surface
  gets **no** `owns` edge and a `None` `owner_identity_ref` (mirrors Phase 1 Task 3's
  "empirical or absent, never assumed" rule for `can_call`) — a test asserts an
  un-owned object writes no edge.
- **Ownership is runtime-created on crAPI, so "declarative" means declaring _how
  to discover_ it, not a static owner field.** Unlike VAmPI's inventory — where an
  owner could in principle be a fixed YAML value — crAPI's vehicle-to-user
  association is created during signup/onboarding and does not pre-exist. So the
  surface declares a *discovery recipe* (which endpoint reveals ownership, and
  after which workflow step it becomes readable), not an asserted owner. The
  mapper runs the same onboarding flow the seeded identities need anyway (Task 6),
  then reads the resulting `owns` edge from the app's *own response* — never
  asserting the owner in advance. A test drives the onboarding flow and confirms
  the `owns` edge is written from the observed response, not from surface config.
  This keeps the empirical-or-absent rule intact: before the flow runs and the
  app confirms the association, there is no `owns` edge.
- The Phase 1 gate is unregressed: the VAmPI eval harness and every Phase 1 test
  still pass with the extended mapper (ownership is additive — VAmPI declares no
  owners, so its graph is unchanged).

### 3. Neo4j store backend via the neo4j-cypher MCP tool (§12, §13)
- The graph store is reachable through one interface; a single store-contract
  test suite runs unchanged against both the NetworkX backend and the
  Neo4j-MCP backend and returns identical results for every query (nodes,
  `can_call`, findings, `enables`/`derived_credential` traversal) — parity, not
  a one-way cutover.
- Every Neo4j read/write goes through the `neo4j-cypher` MCP tool
  (`read_neo4j_cypher` / `write_neo4j_cypher` / `get_neo4j_schema`), never a
  direct bolt driver import — mirroring the Phase 1 Task 8 discipline that detection
  runs through the tool boundary, and matching §13's "Neo4j MCP backs
  `query_graph`/`write_finding`/`mark_inconclusive`."
- `enables`/`derived_credential` traversal is expressed as a Cypher path query
  (§12: "Cypher fits `enables`/`derived_credential` traversal naturally"), and a
  test asserts a multi-hop path returns as one connected result, not N
  round-trips reassembled client-side.
- Node identity stays deterministic across backends: the same
  endpoint/param/object/finding maps to the same id under Neo4j as under
  NetworkX (re-seeding is idempotent on both), so a graph built on one backend
  reads back equivalently on the other.
- Secrets never enter the graph on either backend — the `Session` node still
  carries only a `token_ref` (§10), asserted by inspecting what Cypher actually
  writes.

### 4. Chain Solver — spawn-and-requery over the finding layer (§8)
- A confirmed finding that yields a new credential / elevated privilege /
  attacker-controlled-content triggers exactly one uniform action: spawn the
  `Session`/`Identity`/edge and re-run reachability from that node — verified by
  a test where a seeded confirmed finding causes a previously-unreachable
  `can_call` edge to be re-queried.
- The re-query mechanism is class-agnostic: the same code path handles a
  mass-assignment self-escalation (no new node, re-test the acting identity's
  own `can_call` edges) and a credential-yielding finding (new node, then
  query) — a test exercises both through one entry point, no per-class-pair
  branch (§8).
- A reconstructed chain is persisted as connected `enables` edges linking the
  contributing `Finding` nodes, so the output is one connected path, not two
  disconnected findings — asserted by querying the path, not by report text.
- The solver terminates: re-query does not re-open an already-explored
  `(identity, endpoint)` neighborhood (reuses Phase 1's inconclusive/verdict
  write-back so nothing is retested), and respects the §11 per-path budget cap.

### 5. Business-logic 4-template invariant library + oracle (§7, §9, §5)
- Exactly four templates exist — single-use reuse, quantity/limit, price/
  parameter tamper, step-order — and adding a fifth requires a plan change first
  (§7 names four; CLAUDE.md forbids growing the family set silently).
- Each template is *instantiated from a recon-discovered resource*, not
  hand-modeled: a template produces a concrete check only when the graph
  surfaces a matching consumable/limited resource (a coupon/token object, a
  quantity/limit parameter, a priced object, an ordered multi-step flow) — a
  test feeds a surface with no such resource and asserts the template
  instantiates nothing.
- The templates run as the `business_rule_invariant` §7 family through
  `run_oracle` (Phase 1's registry raised `UnknownOracleError` for it) — a
  confirmed business-logic violation is reachable only via `run_oracle` →
  `write_finding`, exactly like the differential oracle, with no LLM in the
  decision path (fixed-input/fixed-output test).
- Sequential-replay-first: a template fires as cheap sequential replay and never
  escalates to concurrent delivery in Phase 2 (that's the deferred Phase 6 race
  module, §7/§15) — asserted by the audit log showing sequential, not
  single-packet, delivery.
- The check is read-only-first-safe: any state-changing step a template needs
  (e.g. redeeming a single-use token twice) fires only after the read-only case
  is cleared and is logged as reversible/idempotent-aware (§10) — a test asserts
  no ungated mutating request.
- **Runtime-dependent surface (same pattern as Task 2's ownership discovery).**
  The step-order template especially does not read its ordered multi-step flow
  from a static YAML field: the flow — and the state each step leaves behind —
  only exists after the workflow runs. So "instantiated from a recon-discovered
  resource" here means the template discovers the ordered flow empirically (the
  sequence of endpoints, and what earlier steps make reachable) and reads the
  resulting state from the app's own responses, never asserting the expected
  order in advance. A test drives the flow and confirms the template instantiates
  from the observed sequence, not a pre-declared one.

### 6. crAPI target — recon surface, identities, and stateful-safety (§3, §14, §10)
- crAPI's surface is a declarative inventory (`config/crapi-surface.yaml`, same
  shape as `vampi-surface.yaml`) with no per-endpoint logic in the mapper — the
  two documented-BOLA flows' endpoints/params/objects materialize as
  `Endpoint`/`Parameter`/`Object` nodes with `accepts`/`returns` edges.
- ≥2 crAPI identities across its role hierarchy (two vehicle-owning users, plus
  the mechanic role the mechanic-contact chain needs) are seeded from env/secret
  store, never hardcoded (grep-clean), each with an isolated token store (Phase
  1 Task 2 invariants re-asserted against crAPI).
- `can_call` edges are empirical and `owns` edges reflect crAPI's ownership as
  the app itself reports it (which user owns which vehicle/report) — set from
  actual responses / app data, never assumed; an unprobed edge is absent, not
  defaulted.
- Ownership is discovered at runtime, not read from the YAML (the Task 2
  companion clause applied to the live target): crAPI associates a vehicle to a
  user *during* signup/onboarding, so no owner exists to declare in advance. The
  surface declares *how to discover* it — run the onboarding flow the seeded
  identities need anyway, then read the resulting `owns` edge off the app's own
  ownership-revealing response. A test asserts the `owns` edge is written only
  after that flow runs and matches what the app returned, never asserted ahead of
  it. This is the concrete precondition for the cross-identity BOLA diff in
  Task 8 — without a real owner on the graph, "identity B reads identity A's
  object" has no A to anchor to.
- Stateful safety holds on a mutating target: recon fires only read-only probes,
  every state-changing crAPI endpoint is materialized-but-unprobed, and the
  run's audit log shows zero destructive side effects (§10) — the precondition
  for the gate's "zero destructive side effects" clause.
- A `docker compose` service brings up crAPI reproducibly (mirroring Phase 1's
  VAmPI compose) so both gate halves run in one reproducible pass.

### 7. Per-instance object node identity at the store (§6, §8)
Phase 2 Task 6 surfaced this and it must be resolved before the gate, not inside
it. `Object` nodes are keyed by *type* — `object_id` returns `object:{type}` — so
every vehicle collapses into one `object:vehicle` node. `owns_edges()` still
carries both owners' edges, but `owner_of` (a single stamped attribute) reflects
only the last writer, and the vehicle-location BOLA ("identity B reaches the
object *instance* owned by identity A") has no per-instance anchor to diff
against. Fixing this is a store node-keying change — the Task 1 layer — so it is
tracked here with its own DoD instead of folded into the Task 8 gate, exactly as
the ownership-discovery gap became its own task (Task 2) rather than being folded
into recon. It extends the store Task 1 built, but Task 1 is already
complete/committed, so this is a new task, not a reopening.
- The store keys object nodes per instance when an instance identifier is known:
  `object_id(type, instance_key=None)` returns `object:{type}` when the key is
  absent (unchanged) and `object:{type}:{instance_key}` when present, and `Object`
  carries an optional `instance_key`. A test round-trips two instances of the same
  type (two vehicle UUIDs) as two distinct nodes.
- `owner_of`/`owns_edges` resolve per instance: two identities owning two distinct
  object instances of the same type produce two owned nodes with two owners — the
  collapse is gone. A test asserts owner_a's vehicle node ≠ owner_b's vehicle
  node, each with its own `owner_identity_ref` (the exact case Task 6 could not
  represent).
- The instance key is empirical, read from the app's own response: recon's
  ownership discovery creates one object node per instance the reveal returns,
  keyed by the identifier in that response (e.g. the vehicle `uuid`), never a
  positional index or a fabricated key (mirrors the empirical-or-absent rule).
- §6 discipline: no new node/edge *type* — `instance_key` is a new *attribute* on
  the existing `Object` node, justified because BOLA operates on object
  *instances* by definition (§5/§8: "identity B reaches identity A's object",
  "cross-flow object reuse") and recorded in the decision log.
- Phase 1 is unregressed: a type-keyed object with no instance key still keys to
  `object:{type}` (VAmPI and the structural pass declare none), so the VAmPI gate
  and every Phase 1 test are unchanged — per-instance keying is additive.

### 8. crAPI multi-step BOLA end-to-end reconstruction — THE phase gate (§8, §14, §15)
- **Precondition (Task 7): per-instance object identity.** The two chains are
  posed between object *instances* (owner_a's vehicle vs. owner_b's), so the gate
  cannot be met while objects collapse to one node per type — Task 7 is a hard
  blocker, not an optimization. The vehicle-location diff anchors on owner_b's
  vehicle *instance* node, which only exists once Task 7 lands.
- Both documented multi-step BOLA chains — **vehicle-location** and
  **mechanic-contact** — are reconstructed end-to-end: recon → cross-identity
  differential confirms each hop → Chain Solver links the hops into one
  connected `enables` path → the full chain is queryable from the graph. 100%
  (2/2) reconstructed.
- Reconstruction is generic, not hand-coded (the load-bearing clause): the
  scenarios fall out of template match + the Chain Solver, and a grep for
  crAPI-specific object ids / endpoint paths in Phase 2 detection code is clean
  — a per-scenario branch fails the gate even if the finding is correct.
- **Zero destructive side effects logged**: the entire run's audit log contains
  no `fired:` entry for a state-changing request that wasn't first cleared by
  read-only-first and confirmed reversible — asserted against the log.
- The whole run is driven through the MCP tool boundary (Phase 1 Task 8 contracts,
  extended with the Neo4j-backed store) in one reproducible pass against the
  Task 6 crAPI instance — no direct Python calls into detection tools, matching
  the Phase 1 gate's discipline.
