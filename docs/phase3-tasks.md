# Phase 3 — Full class coverage: task list

Derived from `reachagent-final-plan.md` §7 (oracle families), §9 (payload library),
§14/§15 (the gate). Each task's definition of done is a checkable invariant from the
plan, not "implement X." Ordered by dependency.

## Phase-level numeric gate

Historical target gate: ≥75% of Juice Shop's injection/XSS/file-upload/path-
traversal challenge-tracker items, false-positive rate ≤10%, and confirmed
blind-SQLi on PortSwigger vulnerable/non-vulnerable variants. Current API-only
Docker mode must not present that historical target as achievable: strict
runtime denominator is nine `VERIFIED_CHALLENGE_SCOPE` keys, with a current
class-correct deterministic ceiling of 4/9 (three SQLi auth-bypass keys plus the
null-byte input-validation key). The null-byte package-artifact result is now
labeled `file_upload`; `unionSqlInjectionChallenge` and `dbSchemaChallenge` remain
uncredited until exact extraction attribution replaces generic response
divergence. Upload challenges lack persistence/retrieval/execution evidence, and
DOM-XSS challenge attribution requires browser-rendered execution unavailable in
current API-only runner. Phase 3 remains incomplete until at least 7/9 is honestly
reachable, or scope is explicitly re-baselined.
Three load-bearing clauses remain for any browser-capable re-baselined run:

- **≥75% Juice Shop coverage.** Scored against built-in challenge tracker (ground truth), not self-reported. Current API-only mode is capped at 4/9 class-correct keys; 75% requires at least 7/9 matching typed claims.
- **≤10% false-positive rate.** Measured against confirmed challenge completions: a finding on a challenge the tracker has not confirmed is a false positive. The rate is `false_positives / (true_positives + false_positives)` over full run.
- **Blind-SQLi on PortSwigger, zero false positives on non-vulnerable variants.** Juice Shop does not cleanly isolate blind case; PortSwigger labs remain dedicated ground truth for OOB-first/paired-timing oracle. A confirmed finding on vulnerable lab plus zero findings on non-vulnerable variant is pass condition.

## Scope notes

- **Oracle families, not new vuln classes.** Phase 3 extends the §7 oracle set (OOB
  callback, timing/statistical) and the Playwright execution-confirmation family to
  cover classes the Phase 1/2 payload library already names but whose oracles were
  deferred. No seventh oracle family is introduced without updating the plan first
  (CLAUDE.md non-negotiable).
- **Playwright taint-tracking is bounded by a hand-maintained hook list (§5).** DOM XSS
  discovery is Partial support by design: the shim hooks the known sinks
  (innerHTML, document.write, eval, location.href assignment) and sources
  (location.hash, postMessage, document.referrer). Systematic discovery within that
  set, not exhaustive coverage of every possible sink/source.
- **Statistical oracle reuse is explicit.** The paired-trial harness built for blind
  SQLi (Task 2) is the same harness NoSQLi extraction (Task 3) and LDAP extraction
  (Task 4) reuse — no parallel implementation. A grep for the harness entry point in
  Tasks 3 and 4 must resolve to the Task 2 module, not a copy.
- **No external scanners as detection dependencies (CLAUDE.md).** OOB callbacks go
  through a self-hosted interact.sh instance (§13), not Burp Collaborator or an
  external service. Playwright is the browser oracle, not a headless scanner.

## Tasks

### 1. OOB callback infrastructure + blind SQLi OOB-first oracle (§7, §9)
- A self-hosted OOB collaborator (interact.sh, §13) is reachable from the test
  environment and the `out_of_band_callback` §7 oracle family is registered in the
  oracle registry — `run_oracle(OracleMechanism.OOB_CALLBACK, evidence)` no longer
  raises `UnknownOracleError`. A test fires a known-good DNS callback and asserts the
  oracle returns `confirmed_violation`.
- Blind SQLi detection uses OOB-first: the payload library's `sqli_blind` sink
  produces an OOB-capable payload (DNS/HTTP exfil via the collaborator subdomain)
  before falling back to timing. A test with a mock collaborator that receives the
  callback confirms a finding; a test with no callback received does not confirm one
  (the oracle is not timing-only by default).
- The OOB payload is tagged with a per-request nonce so two concurrent probes on
  different parameters do not cross-attribute callbacks — a test fires two probes and
  asserts each callback resolves to its own parameter, not the other's.
- Read-only-first (§10): the OOB probe is a GET/POST that reads a response; it does
  not mutate application state. A test asserts the audit log shows no state-changing
  request during the OOB probe phase.
- The collaborator subdomain and token are loaded from env/secret store, never
  hardcoded — grep of the OOB oracle module for literal collaborator hostnames is
  clean.

### 2. Paired-trial statistical oracle — timing with negative control (§7, §9)
- The `timing_statistical` §7 oracle family is registered and callable via
  `run_oracle`. It accepts a `PairedTrialEvidence` object: a baseline trial (benign
  payload, measured latency) and a probe trial (time-delay payload, measured latency),
  plus a configurable significance threshold. A fixed-input test with a synthetic
  5-second delay confirms a violation; a test with equal latencies does not.
- **Negative control is mandatory, not optional.** The oracle refuses to confirm a
  violation from a single timing measurement — it requires a paired baseline trial
  fired under identical conditions (same endpoint, same identity, same non-delay
  payload) in the same run. A test that supplies only a probe trial (no baseline)
  raises a validation error rather than confirming.
- The statistical decision is deterministic given the inputs: the oracle applies a
  fixed threshold (e.g. probe latency ≥ baseline + N×σ, where N and σ are
  configurable) and returns the same verdict for the same inputs every time — no
  random sampling, no LLM judgment. A fixed-input/fixed-output test asserts this.
- This oracle is the **fallback** for blind SQLi (Task 1 uses OOB-first); it is also
  the **primary** oracle for NoSQLi extraction (Task 3) and LDAP extraction (Task 4),
  which have no OOB channel. The module is imported by Tasks 3 and 4, not copied —
  a grep confirms one implementation.
- The oracle's support level stays Partial (§5): the plan's coverage matrix records
  "timing-only remains noisy — matches published 0% baseline for naive timing-only
  detection." The DoD does not require upgrading this to Full; it requires the
  negative-control pairing that moves it above naive.

### 3. NoSQL injection — blind/deep extraction (§7, §9)
- The `nosqli_extraction` vuln class is added to the coverage matrix (§5) with
  support level Partial and oracle `timing_statistical` (reused from Task 2). A test
  asserts `get_payloads("nosqli_extraction", sink_type=SinkType.NOSQL)` returns at
  least one payload from the library.
- Detection uses the Task 2 paired-trial harness: a baseline trial with a benign
  NoSQL operator and a probe trial with a time-delay operator (e.g. `$where` with a
  `sleep()` expression), both fired against the same parameter. The oracle is
  `run_oracle(OracleMechanism.TIMING_STATISTICAL, evidence)` — no new oracle family.
- A confirmed NoSQLi extraction finding is reachable only via `run_oracle` →
  `write_finding` (the CLAUDE.md non-negotiable). A test with a mock transport that
  returns a delayed response for the probe and a fast response for the baseline
  confirms a finding; a test with equal latencies does not.
- The NoSQLi auth-bypass class (operator-injection differential, already Full support
  from Phase 1) is unregressed — its oracle path is unchanged and its tests still
  pass.

### 4. LDAP injection — blind extraction (§7, §9)
- The `ldap_extraction` vuln class is added to the coverage matrix (§5) with support
  level Partial and oracle `timing_statistical`. The plan notes: "No OOB channel
  exists for this class — ceiling is lower than SQLi's." The DoD does not require
  OOB; it requires the paired-trial harness.
- Detection mirrors Task 3: baseline trial with a benign LDAP filter, probe trial
  with a time-delay filter (e.g. a filter that triggers a slow recursive search),
  both fired against the same parameter, evaluated by the Task 2 oracle.
- A confirmed LDAP extraction finding is reachable only via `run_oracle` →
  `write_finding`. A test with a mock delayed-probe transport confirms a finding; a
  test with equal latencies does not.
- The LDAP auth-bypass class (wildcard/filter differential, already Full support) is
  unregressed.

### 5. Playwright taint-tracking shim for DOM XSS discovery (§7, §9)
- A Playwright-based taint-tracking shim is injected into the browser context before
  any page load. It hooks the following sinks: `innerHTML` setter,
  `document.write`/`document.writeln`, `eval`, `Function` constructor,
  `location.href` assignment, `location.replace`, `location.assign`. It hooks the
  following sources: `location.hash`, `location.search`, `document.referrer`,
  `window.name`, `postMessage` event data. A test loads a synthetic page that routes
  `location.hash` into `innerHTML` and asserts the shim fires a taint event.
- The shim reports taint events as structured evidence (source name, sink name,
  tainted value, stack trace) to the `evaluation_execution` §7 oracle family — the
  same family Phase 1's reflected XSS oracle uses. No new oracle family is introduced.
  A test asserts `run_oracle(OracleMechanism.EXECUTION_CONFIRMATION, shim_evidence)`
  returns `confirmed_violation` when a taint event fired and `inconclusive` when none
  did.
- The shim is injected via Playwright's `addInitScript` (or equivalent), not via a
  proxy that rewrites responses — the injection is browser-side, not network-side, so
  it does not interfere with HTTPS or require a CA cert.
- **The browser is driven through a new MCP tool, `fire_browser`, not direct Playwright
  Python calls (§13 manifest change).** Phase 1's manifest has seven tools, none of
  which wraps a browser — `fire_request` is network-side (httpx). `fire_browser(identity,
  url, inject_shim=True)` is added to the §13 core manifest as an Explorer-owned tool:
  it navigates the URL, installs the shim via `addInitScript` before load, and returns a
  browser fire handle whose captured taint events feed `run_oracle`'s
  `EXECUTION_CONFIRMATION` family. A test asserts the DOM-XSS taint path reaches
  `run_oracle` through `mcp.call_tool` (the real dispatch boundary), not a direct call.
- **`fire_browser` is proven Explorer-only by an extended boundary test.**
  `tests/phase*/test_tool_boundaries.py` is extended to assert `fire_browser` is exposed
  on the Explorer tool subset and is **unreachable** from the Coordinator and Validator
  subsets — the same structural proof that already covers the original seven tools
  (Explorer never `write_finding`/`run_oracle`; Coordinator never `fire_request`/
  `run_oracle`). `fire_browser` joins the `fire_request` side of that assertion: a
  firing tool, Explorer-only, never a confirmation path.
- Scope is bounded by the hook list above (§5 Partial support). A sink or source not
  in the list is not detected; the DoD does not require exhaustive coverage. Adding a
  new hook requires updating this list in the surface config, not the shim code —
  the shim reads its hook list from config, not hardcoded strings.
- The Phase 1 reflected XSS oracle is unregressed: the shim is additive, not a
  replacement. A test asserts the reflected XSS path still confirms without the shim.

### 6. Stored and DOM XSS breadth — beyond Phase 1's reflected-only coverage (§7, §9)
- Phase 1 confirmed reflected XSS (payload injected and executed in the same
  response). Phase 3 extends to stored XSS (payload persisted, executed on a
  triggering second view) and DOM XSS (payload routed through a DOM source into a
  sink, confirmed by the Task 5 shim). All three variants use the
  `evaluation_execution` §7 oracle family — no new family.
- Stored XSS detection: the Explorer fires a write request (POST/PUT) with a tagged
  payload into a field the app persists, then fires a read request (GET) that
  triggers the stored payload in a browser context. The Playwright oracle confirms
  execution on the second view. A test with a mock transport that echoes the payload
  on the second GET confirms a finding; a test where the second GET does not echo it
  does not.
- The write request in stored XSS detection is state-changing. Read-only-first (§10)
  applies: the write fires only after the read-only probe (GET of the target field)
  confirms the field is injectable (reflected or error-based signal), and the write
  is logged as a state-changing action in the audit log. A test asserts the audit log
  records the write as state-changing and that no write fires without a prior
  read-only confirmation.
- DOM XSS detection uses the Task 5 shim: the Explorer navigates to a URL with a
  crafted fragment/query, the shim reports a taint event if the source reaches a
  sink, and the oracle confirms. A test with a synthetic DOM-XSS page confirms a
  finding; a test with a safe page does not.
- The `enables` edge from a stored XSS finding to a downstream SSRF finding (the
  §8 example chain) is expressible via the existing Chain Solver — a test seeds both
  findings and asserts `chain_paths` returns a connected path.

### 7. File upload — type/extension bypass detection (§7, §9)
- The `file_upload` vuln class is added to the coverage matrix (§5) with support
  level Full and oracle `structural_verification` (§7: "retrieval/execution
  confirmation"). A test asserts `get_payloads("file_upload", sink_type=None)`
  returns payloads covering at least: double extension (`.php.jpg`), null-byte
  truncation (`.php%00.jpg`), MIME-type mismatch (Content-Type: image/jpeg with a
  PHP body), and polyglot (valid JPEG header + PHP payload).
- Detection: the Explorer uploads each payload variant, then attempts to retrieve the
  uploaded file at its stored URL. The oracle confirms a violation when the retrieved
  response indicates server-side execution (e.g. PHP output, not raw file content) or
  when the file is retrievable at a path outside the intended upload directory. A test
  with a mock transport that returns PHP output on retrieval confirms a finding; a
  test that returns the raw file does not.
- The upload request is state-changing (§10): it fires only after a read-only probe
  confirms the upload endpoint exists and accepts multipart/form-data, and it is
  logged as state-changing in the audit log. A test asserts no upload fires without
  a prior read-only confirmation.
- Cleanup: after a confirmed finding, the audit log records the uploaded file's URL
  so a post-run cleanup pass can delete it. The DoD does not require automated
  cleanup, but the URL must be logged — a test asserts the audit entry exists.

### 8. Path traversal — retrieval of known out-of-scope file (§7, §9)
- The `path_traversal` vuln class is added to the coverage matrix (§5) with support
  level Full and oracle `structural_verification` (§7: "retrieval of known
  out-of-scope file, content-matched"). A test asserts `get_payloads("path_traversal",
  sink_type=SinkType.FILE_PATH)` returns payloads covering at least: `../` sequences
  (depth 3–8), URL-encoded variants (`%2e%2e%2f`), double-encoded variants
  (`%252e%252e%252f`), and null-byte termination.
- Detection: the Explorer fires each payload against a file-path parameter. The oracle
  confirms a violation when the response body contains a known content signature from
  an out-of-scope file (e.g. `/etc/passwd` root entry, `/etc/hosts` localhost line,
  Windows `win.ini` section header). Content-matching is deterministic — a fixed
  regex per target OS, not a heuristic. A test with a mock transport returning
  `/etc/passwd` content confirms a finding; a test returning a 404 does not.
- The probe is read-only (§10): path traversal reads a file, it does not write one.
  No state-changing request is needed; the audit log shows only GET/read probes.
- The oracle refuses to confirm on a response that merely echoes the payload string
  without the known file content — a test asserts a response containing `../etc/passwd`
  literally (not the file content) does not confirm.

### 9. Juice Shop + PortSwigger target setup and THE phase gate (§14, §15)
- **Precondition (Tasks 1–8):** all six oracle families used in Phase 3 are
  registered and callable; the Playwright shim is wired **and driven through the
  `fire_browser` MCP tool (Task 5), which is present in the §13 manifest and proven
  Explorer-only by `test_tool_boundaries.py`**; the payload library covers all Phase 3
  classes. The gate cannot be met while any Task 1–8 DoD item is open. The full-run
  MCP-boundary invariant below is unsatisfiable for the DOM/stored XSS classes unless
  `fire_browser` exists — the browser cannot otherwise be reached through
  `mcp.call_tool`.
- **Juice Shop** is brought up reproducibly via `docker compose` (mirroring the
  Phase 1 VAmPI and Phase 2 crAPI patterns). A `config/juiceshop-surface.yaml`
  declares the injection/XSS/file-upload/path-traversal surface; the SurfaceMapper
  populates the graph generically — no per-challenge logic in the mapper. A grep of
  Phase 3 detection code for Juice Shop-specific challenge names or endpoint paths
  is clean.
- **PortSwigger blind-SQLi labs** are accessed via the Burp Suite MCP Server or
  Caido MCP integration (§13: "capture/replay only") for the OOB-first oracle
  specifically. The lab URL and session token are loaded from env, never hardcoded.
- **Gate invariant 1 — historical ≥75% Juice Shop challenge coverage:** strict runtime scope is exactly the nine `VERIFIED_CHALLENGE_SCOPE` keys, not category-wide tracker rows. Current API-only Docker runner has class-correct ceiling 4/9: three SQLi auth-bypass keys plus the relabeled null-byte input-validation key. `unionSqlInjectionChallenge` and `dbSchemaChallenge` remain uncredited until exact extraction attribution; upload type/size lack persistence/retrieval/execution signal; DOM-XSS lacks browser attribution. Historical threshold requires ≥7/9 matching typed claims and is currently unattainable; gate must report measured failure, not imply unexplained target failure.
- **Gate invariant 2 — ≤10% false-positive rate:** `false_positives /
  (true_positives + false_positives) <= 0.10` over the full Juice Shop run, where a
  false positive is a confirmed finding on a challenge the tracker has not confirmed.
  Asserted against the run's finding list and the tracker state at run end.
- **Gate invariant 3 — PortSwigger blind-SQLi:** a confirmed `sqli_blind` finding
  exists in the graph for the vulnerable lab, and zero `sqli_blind` findings exist
  for the non-vulnerable variant of the same lab. Both are asserted by querying the
  graph, not by report text.
- **Zero destructive side effects outside logged state-changing actions:** the audit
  log contains no `fired:` entry for a state-changing request that was not first
  cleared by read-only-first and logged as state-changing (§10). Asserted against
  the log, not by inspection.
- The full run is driven through the MCP tool boundary — no direct Python calls into
  detection tools, matching the Phase 1 and Phase 2 gate discipline.
- **Clean-target requirement:** numeric runs use `REACHAGENT_JUICESHOP_EPHEMERAL=1`
  with `python -m reachagent.eval.juiceshop --fresh`. Runner starts pinned
  digest without volumes, waits for valid `/api/Challenges` data with known
  unsolved verified key, validates all nine verified keys clean, and always tears
  down container. Missing, malformed, wrong-category, pre-solved, or disappearing
  keys produce `NOT MEASURABLE`, never silent 0% result. Persistent URL mode
  remains useful for exploratory runs but is not clean numeric gate unless baseline
  classification reports `CLEAN`. Clean measurable run below 75% is an honest
  capability result under current API-only ceiling, not a setup failure.
