# Phase 1 — Foundation: task list

Derived from `reachagent-final-plan.md` §14/§15. Each task's definition of done
is a checkable invariant from the plan, not "implement X." Ordered by
dependency.

## Phase-level numeric gate

The single numeric gate for Phase 1 (§14, §15), verified verbatim by Task 9:

> ≥90% precision and ≥80% recall with VAmPI's toggle on; **zero** confirmed
> findings with the toggle off.

**Scope note — JWT deferred past Phase 1.** §14 lists VAmPI as validating
"BOLA/IDOR/mass assignment/JWT," but §15's Phase 1 scope names only the
*differential-diff* oracle. Per §7, JWT forgery is a **structural** oracle, not
a differential one, so it falls outside Phase 1's stated scope. Resolving the
apparent tension in favour of §15's explicit scope: **the Phase 1 numeric gate
is measured on BOLA / IDOR / mass-assignment only.** JWT moves to a later phase
alongside the structural oracle family.

## Tasks

### 1. Execution layer — scope guard + request firer (§10, §12)
- A request to any host/path not on the allowlist is rejected *before a packet
  leaves the process* — test asserts no socket call on an out-of-scope target.
- No state-changing request fires until the read-only case is confirmed safe
  (read-only-first) — verified by test.
- Every fired request is written to the audit log (action, identity, target,
  outcome).

### 2. Identity/session management (§10)
- ≥2 VAmPI identities across its role hierarchy seeded from env/local secret
  store, never hardcoded (grep-clean).
- Each identity has an isolated token store; a test asserts no cross-identity
  token bleed.

### 3. Recon / surface mapper (§3, §6)
- Every VAmPI endpoint, parameter, and object represented as
  `Endpoint`/`Parameter`/`Object` nodes with `accepts`/`returns` edges.
- `can_call` edges written per identity, carrying a
  `confirmed_allowed`/`confirmed_denied` status set *empirically* (from an
  actual request), not assumed.

### 4. Payload library — tagged, VAmPI-relevant slice (§9)
- Entries for the classes the VAmPI toggle covers, each with the full §9 schema
  (`vuln_class, context, inferred_sink_type, oracle_type, payload_ref,
  graph_edge_on_success`).
- `get_payloads(vuln_class, sink_type)` returns only sink-matched entries,
  ordered by oracle confidence; a test confirms an `html_reflection` param never
  receives a SQL entry and vice versa.

### 5. Explorer tool pipeline (§9, §13)
- `fingerprint_parameter` sends a benign canary first and sets
  `inferred_sink_type` on the `Parameter` node; nothing downstream fires before
  it completes.
- `classify_response` emits a *candidate* record only — test asserts it has no
  path to `write_finding`.
- All four Explorer tools (`fingerprint_parameter`, `get_payloads`,
  `fire_request`, `classify_response`) are real functions routing through Task
  1's firer.

### 6. Differential-diff oracle + verification engine (§7)
- The cross-identity/cross-request/cross-condition diff returns exactly one
  deterministic status — `confirmed_allowed` / `confirmed_denied` /
  `confirmed_violation` / `inconclusive` — with no LLM input, verified by
  fixed-input/fixed-output tests.
- `run_oracle` is the *only* code path that can yield a `confirmed` result
  (enforced, tested).

### 7. Validator tools (§13)
- `write_finding` rejects any input not backed by a `confirmed` `run_oracle`
  verdict — a test feeds it a raw candidate and asserts it refuses.
- `mark_inconclusive` writes the negative result back to the edge so it isn't
  retested (verified by re-query).
- Role-boundary test still passes: Validator is the only holder of
  `run_oracle`/`write_finding`.

### 8. MCP server — human-in-the-loop (§13)
- `reachagent-mcp` starts and exposes the Explorer + Validator tools; callable
  by hand from Claude Desktop/Code.
- Registration preserves role boundaries (Explorer subset has no
  `write_finding`), and contracts are identical to what the Phase 5 Coordinator
  will call — no signature changes anticipated at handoff.

### 9. VAmPI evaluation harness — THE phase gate (§14, §15)
- With VAmPI's vulnerable toggle **on**: **≥90% precision and ≥80% recall**
  against its built-in ground truth, measured on BOLA / IDOR / mass-assignment
  (JWT deferred, see scope note above).
- With the toggle **off**: **zero** confirmed findings.
- Both measured in a single reproducible run driven through the MCP tools from
  Task 8.
