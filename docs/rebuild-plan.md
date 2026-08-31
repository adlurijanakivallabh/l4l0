# ReachAgent — Cut-Forward Rebuild Plan (v2)

**Plan date:** 2026-08-30
**Supersedes:** `docs/build-plan.md` (v1, the "evidence-driven build plan").
**Scope:** authorized web/API assessment targets and intentionally-vulnerable
laboratories only (VAmPI, crAPI, Juice Shop, PortSwigger/DVGA labs).
**Nature of this plan:** NOT a from-scratch rebuild. The project is *over-built
and never pruned* (v1 explicitly said "No source files or project files are
deleted by this plan") on a payload methodology that is partly wrong. This plan
**corrects the methodology, fixes the correctness bugs the audit found, and cuts
the dead weight** — one capability slice at a time.

Everything below is grounded in a 15-agent, adversarially-verified audit of the
real tree (every claim carries a `file:line`) plus a 3-panel web-researched
methodology design. Findings marked **[confirmed]** were independently
reproduced by a second skeptical agent; **[refuted]** means a suspected problem
does not exist.

---

## 0. Non-negotiable invariants (unchanged, enforced every phase)

1. No `Finding` without a `confirmed_violation` from `run_oracle`. The LLM
   proposes/orchestrates; it never writes a finding. (Explorer/Coordinator
   physically cannot reach `write_finding`.)
2. Six deterministic oracle families, fixed. A seventh requires a written plan
   change first.
3. No external scanner (sqlmap/Nuclei/ZAP/Burp/Caido) as a *detection*
   dependency — only signal-gated adapters emitting inert candidates an oracle
   re-confirms.
4. Read-only-first; scope allowlist enforced at the execution layer.
5. **Honest coverage ratings (Full/Partial/Weak), never aspirational** — this
   invariant is currently *violated* (see §2) and this plan fixes it.
6. Reference projects are read per-phase, license recorded first, never named in
   project code/docs/commits.

## 0.1 The two-plane model (the spine of the whole system)

- **Reasoning plane (non-deterministic):** the LLM proposes recon steps,
  insertion points, payload choices, chain order. It narrows the search space.
- **Control plane (deterministic):** six oracle families + role-bounded tools +
  scope + read-only-first. It is the **sole release authority** — for a runtime
  finding *and* for accepting a rebuild phase (a phase is "done" only when its
  numeric/deterministic gate passes, never on vibes).

## 0.2 Corrected methodology — the funnel (replaces "map → fire all payloads")

The old mental model ("recon → identify insertion points → fire ALL payloads at
every point") is wrong on three axes: it wastes budget (payloads × points ×
encodings), it trips WAFs/lockouts and violates read-only-first, and it confuses
coverage with detection. The corrected core is a **funnel** (all three
methodology panels converged on this):

1. **Surface modeling + insertion-point *typing*.** Each insertion point carries
   a TYPE (identity/object-ref, structured-data field, reflected/rendered, path
   segment, header, upload, GraphQL arg). Type gates which classes are even
   plausible. Spec-first (OpenAPI/GraphQL) over blind crawling.
2. **Sink fingerprinting via paired probes — BEFORE any exploit.** Baseline vs.
   class-metacharacter probe; infer reachability only from a consistent
   *differential* on structured attributes (status, content-type, HTML
   structure, timing), repeated to denoise. **Most inputs terminate here at one
   request with no signal — that is the intended outcome, not a gap.**
3. **Sink-matched, confidence-ordered payload routing.** Fire a payload only if
   its tag set intersects the *detected* sink + backend fingerprint;
   template-first, cheapest-highest-signal first, **early-exit** the moment the
   class is ruled out.
4. **Fire-vs-skip gate** at the firer: skip if no sink signal (unless blind
   class), defer if state-changing before read-only clearance, skip if
   out-of-scope, back off on WAF/lockout, honor per-class + global budget.
5. **Propose/confirm** is the routing controller: LLM proposes, only the
   Validator runs the oracle, `write_finding` is reachable only from a confirmed
   result.
6. **Blind/OOB path** for silent-in-band sinks (blind SQLi, SSRF, blind XXE),
   keyed to a unique per-attempt nonce — reserved for points whose TYPE makes
   the blind class plausible, not sprayed.
7. **Feedback loop:** write fingerprints/ruled-out-classes/confirmed-engines back
   onto the graph so evidence compounds; one Postgres confirmation reorders SQLi
   payloads target-wide.

**Authorization classes (BOLA/IDOR/BFLA/mass-assignment) are NOT payload
classes** — they are identity-swap + object-reference enumeration across roles.
They leave the payload funnel entirely and are tested by cross-identity replay.

## 0.3 Recon economy (replaces "run every tool")

- Free facts first (spec-first — the OpenAPI spec often *is* the surface and
  cancels content discovery entirely).
- Calibration (HTTP catch-all + DNS wildcard) is **mandatory and cheap** and
  gates the expensive step. (Already built in `calibration.py` — this plan wires
  it as a hard gate.)
- **Exactly ONE content brute-forcer + fallback** per (target, surface) — `ffuf`
  primary (native `-ac`), `gobuster` for DNS/vhost, `feroxbuster` only for
  recursion, `dirb` last-resort. Fallback fires only if the primary returned
  zero useful paths AND budget remains.
- One purpose-matched wordlist (never a raft/dir list against a documented API).
- Adaptive "change ONE variable per step" so every escalation's yield is
  attributable, under a **hard recon budget the selector cannot exceed**.

## 0.4 Rebuild discipline — strangler-fig, cut-forward

Each phase strangles one capability slice behind a seam, and **deletion is a
first-class deliverable**: the superseded path is removed when the seam flips.
Bounded autonomy on purpose (2026 evidence: high-autonomy "refactor the module"
prompts produce tangled, cruft-*adding* diffs). Total system size must trend
**down**.

---

## 1. Reference-reading map (licenses recorded; never named in code)

| Ref | Project (dir) | License | Read for |
|---|---|---|---|
| R1 | `pentagi` | MIT | GUI IA/state, service lifecycle (Phase 5) |
| R2 | `cai` | **dual** (MIT + research-only core) | orchestration/handoffs, control loop (Phase 3) |
| R3 | `PentestGPT` | MIT | unified agent loop, event normalization (Phase 3) |
| R4 | `claude-bug-bounty` | MIT | ReAct loop, payload/brain, memory (Phases 1, 3) |
| R5 | `hexstrike-ai` | MIT | large tool catalog, recon economy, transports (Phase 2) |
| R6 | `strix` | Apache-2.0 | scan preflight, bounded coordination, viewer (Phases 2, 5) |
| R7 | corpora (`third_party/payloadsallthethings-snapshot`) | MIT | payload breadth (Phase 4) |
| R8 | wordlists (`/usr/share`, `third_party/seclists-snapshot`) | MIT | discovery wordlists (Phases 2, 4) |

**R2 (`cai`) caution:** dual-licensed with a research-only core — take
architecture/technique ideas only, write everything original in our own style.

---

## 2. Verified issue ledger (what this plan fixes/cuts)

Severity/verdict from the adversarial pass. `file:line` abbreviated.

### Correctness bugs (fix)
- **B1 [confirmed, HIGH]** Unreachable sinks. Fingerprint only ever emits
  `SQL/HTML_REFLECTION/FILE_PATH/TEMPLATE/None`; `get_payloads` requires an exact
  sink match, so **NoSQLi/LDAP = 0% reachable, command-injection (531 corpus
  rows) + SSRF (24 base rows) dead** — all rated "Full" in §5. `_sink_for_vuln_class`
  (the correct map) is used only in the dry-run block. (`explorer.py:243-319`,
  `payload_chain.py:572-604`, `library.py:253`, `entrypoint.py:202`.)
- **B2 [confirmed, HIGH]** `"recon selection exceeds the remaining tool budget"`
  aborts the scan: the prompt prints the full budget while the validator enforces
  `budget - completed`; the fixer never gets the real number; the exception
  propagates uncaught. (`planner.py:608/646-708`, `orchestrator.py:1106-1119`,
  `entrypoint.py:726/843`.)
- **B3 [confirmed, HIGH]** `httpx.Client` leaked per scan in **both** entry
  points (GUI leaks two per scan, accumulates fds on a real target).
  (`entrypoint.py:439`, `orchestrator.py:1352`.)
- **B4 [confirmed, MED]** Undefined CSS vars `--faint`/`--line-strong` silently
  drop styling; tool rows reuse `.ev` → misaligned connector; provider-test color
  set then cleared same tick. (`index.html:128-137/331-333`.)
- **B5 [confirmed, MED]** No degrade-to-deterministic fallback around the
  planner — any provider/validation failure aborts the whole scan mid-recon.
- **B6 [confirmed, MED]** Stale `driven_classes` set omits `xss_dom` (which *is*
  driven) → contradictory "not-applicable" event every all-class scan.

### Dead / unreachable code (cut)
- **C1 [confirmed, HIGH]** `surface_tuning` + `signal_tuning` + `transport_tuning`
  (~564 LOC) never activate — they read `os.environ` directly, bypassing the
  ContextVar the GUI's `override()` sets.
- **C2 [confirmed, HIGH]** 5 `Anthropic*Client` classes are dead **and a latent
  trap** (`anthropic` not in `pyproject`; config validation greenlights an
  anthropic scan that then crashes).
- **C3 [confirmed, HIGH]** `arjun`/`paramspider`/`x8` registered + plannable but
  **never dispatched** (also consume plan budget + prompt tokens every scan).
- **C4 [confirmed, LOW]** empty `tui/` package (stale bytecode); dead
  `_wordlist.py` `"api"`/`"parameter"` branches; dead aliases `RunConfig`,
  `VulnTuningChoice`; legacy `build_phase_summary`; `expand_encoding_variants`
  (dead dup of `expand_payload_mutations`).
- **C5 [confirmed, MED]** PortSwigger race "live gate" unconditionally skips;
  9 byte-identical copies of `test_six_oracle_families_unchanged`; brittle
  source-substring/`ast.parse`-only tests that assert comments.

### Over-engineering / waste (rebuild/collapse)
- **W1 [confirmed, HIGH]** Four content brute-forcers run on one site.
- **W2 [confirmed, HIGH]** The up-front execution plan is largely ceremony:
  per-phase `vuln_classes/payload_refs/profile` feed *display events only*; real
  targeting comes from separate downstream LLM calls. Two LLM decisions for one
  choice. Planner phase vocab (7) ≠ control loop (5) ≠ executed phases.
- **W3 [confirmed, MED]** 20 client classes across 7 modules reimplement
  prompt→JSON→validate; gobuster carries two overlapping tuning mechanisms;
  profile decision recomputed ~6×/scan (no cache) and the displayed pick
  *diverges* from what runs; `entrypoint` `propose_transport` computed then
  discarded; 5-round LLM retry/fixer fan-out (one wasted call).
- **W4 [confirmed, MED]** GUI polls the full payload + rebuilds the whole DOM
  every 1s; the purpose-built `/events` delta endpoint is unused; idle
  `/api/scans` poll never stops; 8 endpoints the GUI never calls
  (`/reasoning`,`/chains` have zero consumers at all).
- **W5 [confirmed, MED]** Signal-gated scanners run live every scan but the
  reconfirm seam is unwired → candidates go nowhere (pure cost).

### Honesty (correct the record)
- **H1 [confirmed]** §5 rates IDOR, Mass Assignment, XSS Stored **Full** but no
  driver exists in either entry point (driverless: `idor`, `mass_assignment`,
  `xss_stored`, `race`). Violates invariant #5.
- **H2 [refuted]** "PayloadsAllTheThings used as a directory wordlist" — does
  **not** happen; recon reads `/usr/share`, corpus reads `third_party/`, enforced
  at the execution layer. **Keep** the separation.

### Decisions folded into the go/no-go (§4)
- **D1** `arjun`/`paramspider`/`x8`: **cut** (default) or wire an insertion-points
  dispatch step?
- **D2** SecLists snapshot (~1200 reachable LFI/XSS/SQLi payloads, never loaded
  in prod): **wire in + cross-source dedup** or document as test-only?
- **D3** Signal-gated adapters (nuclei/nikto/sqlmap/dalfox/commix/jwt_tool):
  **wire the reconfirm seam** (candidates → oracle) or **cut the live invocation**?

---

## 3. Phase plan (cut-forward, strangler-fig)

Each phase runs the §5 per-phase contract. Reference reads are per-phase.

### Phase A — Safety net + honest inventory (no behavior change)
- Fix **B3** (client leak) in both entry points — prerequisite for any live run.
- Pin the current full-suite result as the regression baseline (record exact
  numbers; this is the deterministic gate every later phase must not regress).
- Rewrite the §5 coverage matrix to honest Full/Partial/Weak from audit truth
  (fixes **H1**); no ratings inflated. No cuts yet.
- Gate: full suite green at recorded baseline; matrix matches what the pipeline
  can actually confirm.

**Status (2026-08-30): in progress.** Baseline had **13 pre-existing hermetic
failures** (v1's "no deterministic failure" claim was false) collapsing to 4 root
causes, all fixed: (1) `mcp_call` normalizes FastMCP's sole-`{"result":…}` wrapper
so union-return tools like `fire_request` present flat fields — fixed the whole
BOLA suite (9 tests) + latent live-eval breakage; (2) `bola`/`juiceshop_live`
`fired["fire_ref"]` now resolve; (3) graphql complexity feeds non-negative shifted
residuals to the timing oracle (a Phase-6-hardening regression); (4) the
persistence redactor no longer over-redacts the stable `token:owner` session
handle (kept full secret-scrubbing on free text — verified). Plus **B3** (client
leak) fixed in `scan_target`. `test_store_backend_parity` allow-set updated for
the safe `auth_kind`/`expires_at` session fields. **Deferred:** the §5 honest
coverage-matrix rewrite moves to Phase G (truth-up), where ratings settle after
B/C/D fix reachability and drivers — rewriting it now then re-upgrading would be
churn.

### Phase B — Core methodology: reachable sinks + probe-before-payload
*(the highest-value change — read R4 payload/brain, R7 corpora; web: PortSwigger
backslash-powered scanning.)*
- Fix **B1**: unify the sink strategy — the live path falls back to the class's
  canonical sink (`_sink_for_vuln_class`) when the canary is silent, union with
  the null sink where a class spans sinks (command_injection). Restores
  NoSQLi/LDAP/command-injection/SSRF reachability.
- Implement the paired-probe reachability gate (funnel step 2) so exploit
  payloads are spent only on points showing a differential; keep template-first
  + early-exit (funnel step 3).
- Confirm BOLA/IDOR path stays out of the payload funnel (cross-identity replay).
- Gate: NoSQLi/LDAP/command-injection/SSRF each confirm ≥1 hermetic MockTransport
  case E2E; clean target = zero findings; six-family + role-boundary invariants
  hold.

**Status (2026-08-30):**
- **B1a — reachability (done).** Root cause (verified): all four classes were in
  `_GENERIC_CLASSES` → generic `payload_chain` → `get_payloads`, but the sink
  hint map + `_HINTABLE_SINKS` only covered file_path/template and `_CLASS_SINKS`
  lacked `ssrf`, so `get_payloads` returned nothing (0% reachable). Fix: added
  `nosqli→nosql`, `ldap_injection→ldap`, `command_injection→shell`, `ssrf→url`
  to the hint map + `_HINTABLE_SINKS`, and `ssrf→URL` to `_CLASS_SINKS`. Probe:
  all four now fingerprint the right sink and attempt payloads (27/40/40/15 vs.
  "no payloads matched"). **SSRF now confirms E2E** via the existing structural
  `ssrf_response` oracle; NoSQLi confirms for the 2xx-divergence pattern.
- **B1b — precise drivers (pending).** ldap/command-injection do NOT confirm the
  refused→granted auth-bypass / blind patterns through the generic chain (the
  methodology's exact point). Plan: wire dedicated `detect_nosqli`/`detect_ldapi`
  (auth-bypass-first + timing — already built & tested) and a command-injection
  OOB/timing driver into `scan_all_classes` (mirroring `run_sqli_blind`), and
  drop nosqli/ldap/command-injection from `_GENERIC_CLASSES` so auth classes are
  not imprecisely sprayed. Then a hermetic E2E per class.

### Phase C — Recon economy
*(read R5 recon, R6 preflight/runner, R8 wordlists.)*
- Fix **B2** (budget prompt/validator divergence) + **B5** (degrade-to-
  deterministic fallback — a planner failure never aborts the scan).
- **W1**: exactly one content brute-forcer + fallback; wire `ReconProfile.tools`
  to constrain the family (or collapse at execution) — this deletes the four-tool
  waste and the dead `.tools` field at once.
- Spec-first short-circuit (found spec cancels content discovery); calibration as
  a hard gate.
- Cut the discarded-plan-recon-list path (single recon authority); compute the
  profile once per scan (fixes the display-vs-execution divergence in **W3**).
- Gate: one content tool runs per surface; calibration suppresses catch-all;
  budget never exceeded; recon-tier still emits zero findings/candidates/can_call.

### Phase D — Cut the planning/tuning tier
*(read R2 orchestration, R3 unified loop.)*
- Cut **C1** (3 orphan tuning modules), **C2** (5 Anthropic clients + the
  config-validation trap), **C4** (tui/, dead aliases, `build_phase_summary`,
  `_wordlist` branches).
- **W2/W3**: collapse the plan schema to what execution consumes (budgets +
  signal-tool list) OR consume its per-phase picks and delete the downstream
  re-proposals — one LLM decision per choice; align planner phase vocab to the 5
  executed phases; cap the fixer loop at one corrective turn.
- Collapse the 20 client classes to one shared `propose_json(prompt, validator)`
  helper on `client.py`; delete gobuster's second freeform tuning mechanism.
- **D1** arjun/x8/paramspider and **D3** signal-gated reconfirm per go/no-go.
- Gate: full suite green (minus intentionally-deleted tests); net LOC down;
  invariants intact; a planner/provider failure degrades, never aborts.

### Phase E — Payload corpus hygiene
*(read R7 corpora, R8 wordlists.)*
- Cut `expand_encoding_variants`; memoize corpus load (measure first — near-YAGNI);
  collapse the double per-line validation; fix the stale reserved-token rationale.
- **D2** SecLists per go/no-go (wire + dedup, or document test-only).
- Gate: no dead handle / no orphan template; sink isolation holds; corpus census
  unchanged unless SecLists intentionally added.

### Phase F — GUI information-architecture rebuild (not from scratch)
*(read R1 frontend, R6 viewer. The CSS/tokens are competent — keep them; the IA
is the problem.)*
- Real view routing (toggle `hidden`, not anchor-scroll); note `#findings-panel`
  is nested inside `#surface-panel`. Data-first default (collapse the hero to a
  launch bar).
- **W4**: wire `/events` delta polling + append rows; stop the 1s full-DOM
  rebuild; stop the idle `/api/scans` poll; delete zero-consumer endpoints
  (`/reasoning`, `/chains`) and decide keep/wire for evidence/compare.
- Fix **B4** (CSS vars, tool-row classes, provider color) + empty-state copy +
  sub-10px labels + dead launch `<select>` options.
- Gate: GUI static markers + Playwright smoke (launch/live/surface/findings/
  report/export) pass; every displayed value sourced from real graph/audit state.

### Phase G — Test + correctness truth-up
- Add drivers OR downgrade ratings for `idor`/`mass_assignment`/`xss_stored`/
  `race`; fix **B6** (stale `driven_classes`, xss_dom).
- Add MockTransport E2E through `scan_target` for a differential class (BOLA) and
  a structural class (clickjacking/CORS), not just SQLi.
- Cut **C5** (no-op race gate, 9 duplicate invariant tests → one canonical,
  brittle source-string/parse-only tests); keep the legit AST invariant tests.
- Gate: E2E covers ≥3 families through a real entry point; no test asserts a
  comment or a stub's mere presence.

### Phase H — Full hardening + evaluation (final; no new capability)
- The one authorized fresh whole-tree run; provisioned live gates (VAmPI
  numeric, crAPI, Juice Shop clean-container, PortSwigger/DVGA where provisioned);
  fresh scope/audit/oracle-boundary review across the whole tree; honest
  documentation of every skip.
- Gate: all provisioned gates pass simultaneously; unprovisioned honestly
  skipped; net LOC down vs. v1; release report with exact command/results +
  commit hash.

---

## 4. Decisions (resolved 2026-08-30, before Phase A)

- **D1** arjun/paramspider/x8 → **CUT** (redundant with `api_discovery` +
  `SurfaceMapper` param discovery). Phase D.
- **D2** SecLists → **WIRE IN + cross-source dedup** (+~1200 reachable
  LFI/XSS/SQLi payloads). Phase E.
- **D3** signal-gated adapters (sqlmap/nikto/nuclei/dalfox/commix/jwt-tool) →
  **WIRE the reconfirm seam** so their candidates are oracle-reconfirmed (keeps
  invariant #3; makes the tools useful). Phase D.
- **Cadence** → **CONTINUOUS** (test each phase, then proceed; stop only for a
  destructive/ambiguous call).

---

## 5. Per-phase completion contract

1. Restate the invariants + authorization boundary.
2. Fully read the phase's reference subtree (record license) + every ReachAgent
   caller/helper the slice touches.
3. Record technique / current gap / smallest safe design in a decision doc.
4. Implement only that slice, behind a seam where risky; **name the code it
   deletes.**
5. Run only phase-relevant tests + the hermetic oracle/invariant checks + the
   phase's numeric gate.
6. Self-review with Ponytail; fix findings.
7. Reference-name leakage check on changed code/docs/commit text.
8. Flip the seam, **delete the superseded path** (a phase that leaves both alive
   has failed), commit (message records files read, technique, files
   changed/DELETED, tests, remaining weakness).
9. Update this plan's status + the decision doc.
10. Continue to the next phase (per chosen cadence).
