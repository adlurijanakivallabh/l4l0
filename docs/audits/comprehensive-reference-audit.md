# Comprehensive reference-project audit — full-surface, cross-ref (Phase 1, docs only)

Date: 2026-08-10 · Branch: feat/audit-ref-23 · Base: feat/audit-recon-22 (121a836)
Scope: entire ReachAgent codebase (not just recon/tools/) × 5 local references. No code in this commit.

## Reference licenses (stated before any deep reading)

| ref | license | reuse posture |
|-----|---------|---------------|
| pentestgpt | MIT (LICENSE.md, Grey_D) | technique-level inspiration + paraphrase safe |
| strix | Apache-2.0 | technique + limited-copy safe with attribution |
| cai | Dual: `src/cai/agents` MIT; `src/cai` core Alias Robotics research-use only (commercial forbidden) | MIT portion only for ideas; core read-for-ideas only, nothing adapted |
| hexstrike-ai | MIT (0x4m4) | technique + paraphrase safe |
| claude-bug-bounty | MIT | technique + paraphrase safe |

GPL/AGPL: none among the five → no GPL-blocked reuse decision needed this pass.

## Summary table

| dimension | a | b | c | d | headline items |
|-----------|---|---|---|---|----------------|
| 1 Detection/confirmation | 1 | 1 | 2 | 1 | multi-channel OOB (b); honest audit-attrs on fire (a); LLM-trust = c, never adopt |
| 2 Recon/enumeration | 1 | 2 | 0 | 2 | target-type dispatch (a); DNS wildcard pre-check (b); recovery-phase (b) |
| 3 Payload/technique breadth | 3 | 1 | 0 | 0 | JWT technique corpus (a); SSRF/XXE/Log4Shell OOB payloads (a); hexstrike class payload corpora (a) |
| 4 Reporting/output | 0 | 2 | 1 | 1 | Finding-node render tool (b); run-trace renderer (b) |
| 5 Error/retry/rate-limit/WAF | 3 | 2 | 1 | 1 | WAF calibration/classification helper (b); firer transient retry (a); per-tool timeout env (a); 403-bypass decision (b) |
| 6 Structural/other | 0 | 2 | 1 | 3 | durable-run/resume (b); sandbox policy (b); cai C2 non-compatible (c) |
| **total** | **8** | **10** | **5** | **8** | — |

Category key: (a) real improvement, fits as-is · (b) real improvement needing a human design checkpoint ·
(c) not compatible (state why) · (d) already handled differently but correctly.

---

## Dimension 1 — Detection/confirmation architecture

### (d) claude-bug-bounty `oob_listener.py` — already matches ReachAgent OOB_CALLBACK
Per-injection-point OOB payload with a unique nonce hostname, correlating DNS/HTTP/SMTP/LDAP
interactions back to the payload that triggered them (blind SSRF/XXE/SQLi/RCE/Log4Shell).
This is the same design as ReachAgent's `oob_callback` family (`probe_nonce in observed_nonces`)
and the PATT command-injection corpora. Already handled — ReachAgent does it deterministically.

### (b) OOB channel breadth — multi-channel correlation (DNS/HTTP/SMTP/LDAP)
CBB correlates across DNS + HTTP + SMTP + LDAP; ReachAgent's `oob_callback.py` observes one
channel shape. Broader channel coverage for the SAME family is a real improvement.
**Checkpoint needed:** extends which evidence shapes the OOB oracle accepts (new observation
channel inside existing family — not a 7th family). Same pattern as the TLS Option 1/2 call.

### (a) pentestgpt grounding receipts → honest fire-classification attrs
pentestgpt validates executor CLAIMS against observed trace receipts and records honest
outcome flags on a validated execution: `recovered_transport_failure`, `evidence_span_widened`,
`evidence_projected`. ReachAgent's `FireResult`/audit records fired/refused/errored but not the
transport-recovery nuance. Adopt: a small set of honest attrs on the firer result (transport
error recovered vs parse error vs refused) so a downstream reader never misreads a recovered
transport failure as a clean success. Fits existing audit vocabulary, no new family.

### (c) hexstrike — trusts external tool verdicts directly
hexstrike treats nuclei/sqlmap/etc output as the confirmation itself (priority table → tool run
→ card "VULNERABILITY DETECTED"). This is the exact opposite of ReachAgent's rule that no Finding
exists without `run_oracle`. **Not to be adopted** — finding rigorous, not popular.

### (c) strix / cai — LLM judgment is the confirmation
strix is an agent-runner framework (no vuln-confirmation primitive); cai delegates confirmation to
LLM + tool registry, with `tools/evidence/` aimed at C2 operational evidence (`capture_notice`,
`inventory_check`), not vuln confirmation. Nothing to adopt for confirmation. cai core is
research-only licensed — read for ideas only, nothing adapted.

### (d) pentestgpt `loop.py` — one-task-at-a-time + lease — already covered
Deterministic loop, Supervisor plans / Executor executes one lease at a time, memory kernels,
trace store. ReachAgent's Coordinator (query_graph → score_and_select → check_budget) + run_one
chain is the same discipline; grounding is done by `run_oracle` which is strictly stronger than
trace-receipt validation (it judges the *response*, not just that an action occurred).

## Dimension 2 — Recon/enumeration methodology beyond flags

### (a) claude-bug-bounty recon_engine.sh — target-type dispatch before recon
Dispatches the recon *shape* by target type: domain → subdomain enum; CIDR → nmap ping sweep;
single IP → skip subdomain enum entirely; host list file → load directly, no enum. ReachAgent's
cold-start scanner runs the same tool set regardless of target shape.
**Improvement:** select recon tools by target shape before ingest (host vs domain vs CIDR), so a
bare-IP scan doesn't waste budget on subdomain enumeration. Fits existing recon tier + scope layer.

### (b) DNS wildcard pre-check — the subdomain analog of the deferred calibration helper
recon_engine.sh probes 3 random labels under the apex; if 2+ resolve, the zone is a wildcard A
record — it persists `wildcard_dns.json` and filters brute-forced subs whose A record equals the
wildcard IP before httpx live-probe, saving dead-host probing. ReachAgent has no DNS wildcard
detection (subfinder/amass fixtures assumed clean). This is exactly the calibration-baseline idea
from the deferred FP item, applied at the DNS layer.
**Checkpoint needed:** where the helper lives (recon tier — passive dig is read-only-safe, §10),
and whether a wildcard-flagged subdomain becomes a Host fact with a note or is filtered before
graph write.

### (b) pentestgpt plan TaskKind — explicit RECOVER phase
pentestgpt's plan language separates DISCOVER / ENUMERATE / TEST / EXPLOIT / VERIFY / RECOVER.
ReachAgent covers discover/enumerate/test/verify (mapper, recon tier, run_oracle) but has no
explicit recovery of a partially-mutated probe state. Read-only-first (§10) avoids most of it, but
a state-changing request that does fire and errors mid-way has no modelled recovery.
**Checkpoint needed:** whether a RECOVER phase is worth adding given read-only-first already
minimizes the mutating case — or is documented as out-of-scope-by-design.

### (d) Coverage-completeness / "when is recon done" — already handled
hexstrike uses a static priority table; CBB is a fixed pipeline (no real "done" criterion beyond
finishing the script). ReachAgent's `check_budget` / ChainSolver budget is the "done enough" gate
and is stricter. No change.

### (d) dedup across multi-tool output — already handled
CBB dedups via `sort -u` into a canonical flat store (recon_adapter.py normalizes nested→flat).
ReachAgent's graph merges Host/Endpoint/Parameter by id (idempotent add_*), so multi-tool output
dedups at the node level — the graph IS the canonical store. No change.

### (a) hexstrike tech-aware selection — partially adopted already
hexstrike picks tools/wordlists/extensions by detected tech (php → `-x php,html,txt`, jsp for
Java, etc). Phase 2 already adopted the wordlist half (preferred_wordlist raft defaults). The
per-tech extension half is still open but classified (c) in the recon-tool audit (extension fuzzing
is probing judgment) — carried here as (d)/deferred, not a new a-row.

## Dimension 3 — Payload/technique breadth beyond vendored

### (a) claude-bug-bounty `jwt_scanner.py` — distinct JWT technique corpus
`alg:none` forging, RS256→HS256 algorithm confusion, weak-HMAC-secret crack, static `analyze`
(claims decode, missing exp, alg=none, sensitive claims, short-secret risk). ReachAgent has the
`jwt_forgery` STRUCTURAL oracle but thin PATT JWT payload coverage (JWT was RESERVED at Task 17).
**Improvement:** mine jwt_scanner's technique set into a tagged JWT payload corpus for the
existing structural jwt_forgery family. MIT → technique reuse safe. Payloads still route through
run_oracle; no new family.

### (a) claude-bug-bounty oob_listener blind-XXE / Log4Shell payload shapes
ReachAgent's OOB corpora cover command-injection and SSRF; CBB adds blind-XXE `SYSTEM
"http://<uid>.<oob>"` and Log4Shell `${jndi:ldap://<uid>.<oob>/a}` shapes. Distinct technique
breadth for classes ReachAgent has OOB_CALLBACK coverage for. Ingest as tagged payloads (MIT,
safe); oracle confirmation unchanged.

### (a) hexstrike class payload corpora (command_injection / sql_injection / ssrf / idor / xss / lfi / xxe / csrf)
hexstrike's workflow manager carries payload-set names per vuln class. Its distinct technique
patterns (esp. ssrf and lfi sets) are a source of additional tagged payloads for the same oracle
families. Mining these refs' OWN sets — not re-running PATT. Safe (MIT).

### (b) cbb `waf_encoder.py` / `multipart_mutator.py` — encoding-variant breadth
Multi-layer encoding (url/unicode/html-entity/sql-comment/case-mix/operator-substitute) and
multipart mutation produce payload VARIANTS. Variants are legitimately ingestable as tagged
payloads (tag decides the oracle), but unbounded variant expansion needs a corpus-growth posture
decision (matches the earlier "no unbounded corpus" discipline).
**Checkpoint needed:** accept encoding variants into the corpus (bounded, per class) or leave them
out until a specific class needs them.

### (d) strix skills / pentestgpt — methodology docs, no distinct per-class technique sets
strix `skills/*/SKILL.md` are runbooks; pentestgpt carries no payload libraries. Nothing new for
payload breadth. (cai core is research-only; its payload sets, if any, are not adapted.)

## Dimension 4 — Reporting / output quality

### (b) ReachAgent has no human-facing finding renderer
`Finding` nodes carry `vuln_class / severity / oracle_used / evidence_ref / status / metadata` but
there is no read-only tool that turns them into structured human output. hexstrike's
`format_vulnerability_card` (severity-colored name/severity/description card) and CBB's
`AgentTracer` (per-event log: tool_call/tool_result/loop_warn/finding/finish) are the references.
**Improvement:** a read-only report/summary tool that queries the graph and renders Finding nodes
(vuln_class + severity + oracle_used + evidence_ref) as structured output — keeping "graph is
system of record" (§2), never a free-text report generator.
**Checkpoint needed:** which role owns it (a Validator-adjacent read-only tool? a new read-only
report tool?) and the output contract. Must stay read-only and outside the write path.

### (b) run-trace renderer (tracer/dashboard)
CBB's AgentTracer + dashboard render the hunt session; hexstrike renders scan errors as recovery
cards. ReachAgent has the audit log and graph but no run-trace view. Same (b) bucket as the
renderer above — bundle into one reporting decision.

### (c) cai — no finding report (C2 operation focus) — not adopted.

### (d) pentestgpt RunSnapshot/resume — partially covered
RunSnapshot with transitions + `run_id` digest + `resume=True` is durable-run plumbing. ReachAgent
has `path_id/run_id` in ChainSolver budget identity but no durable resume to disk. Full durable
resume is dimension 6's (b), not a reporting gap per se.

## Dimension 5 — Error handling / retry / rate-limit / WAF-evasion

### (b) claude-bug-bounty `waf_response_analyzer.py` — WAF calibration + classification
This is the stand-out. `--calibrate` fires a baseline sample (status/size/time/body hash);
`ResponseFingerprint` captures vendor hits, log IDs (cf-ray / f5-support / akamai / aws / modsec),
business signals (csrf/api-key/token/form presence), block/challenge titles; `classify` decides
WAF block vs soft challenge vs genuine app response — including the "200 OK but block page" case.
ReachAgent has no WAF classification; responses flow through as facts regardless of block-vs-real.
**Checkpoint needed:** this IS the deferred calibration-baseline helper. Design decision: where it
lives (recon-tier fact emitter, firer-level response classifier, or a new read-only probe), and
whether a WAF-blocked probe becomes a Host/Endpoint fact with a `waf` attribute or is marked so
oracles skip it. Must not become a 7th oracle family.

### (b) claude-bug-bounty `bypass_403.sh` — 403-bypass matrix
Header/method/encoding 403-bypass techniques (wraps byp4xx + built-in matrix). ReachAgent's
recon-tool audit already classified 403 as ACL-surface fact, not bypass. Adopting 403-bypass needs
a decision: is a working bypass a recon FACT (which bypass header exposes /admin) or a FINDING
(structural oracle verdict)? **Checkpoint needed.** Do not auto-adopt as finding.

### (a) firer has no transient retry/backoff
ReachAgent's `RequestFirer` audits every attempt but never retries; a transient network error or
5xx ends the probe. strix has `_is_transient_model_error` + `_transient_model_retry_delay`
(backoff); pentestgpt flags `recovered_transport_failure`.
**Improvement:** bounded transient-retry with exponential backoff on the firer for
network-level errors and 5xx, each retry audited. Fits the existing audit discipline, no new
family.

### (a) per-tool timeout override env
Recon base uses a fixed `_LIVE_TIMEOUT = 300s`. hexstrike has per-tool timeouts (nmap 120s,
gobuster 300s, nuclei 180s, sqlmap 600s) and classifies timeout as a distinct error type with a
recovery action. **Improvement:** `REACHAGENT_*_TIMEOUT` per wrapper already added in Phase 2 for
several tools — extend the pattern to the base default or centralize (env count now >12 → the
"file config when env count >12" note in the prior task applies here: centralize into a small
config instead of one more env per tool).

### (a) audit transport-vs-parse classification
ReachAgent audits `ERRORED:TypeName` today. pentestgpt distinguishes transport recovery from
evidence span issues. **Improvement:** classify fire/recon errors as transport vs parse vs
refused in the audit entry so downstream logic can decide whether a retry is appropriate. Small,
fits audit schema.

### (c) cbb `waf_encoder.py` as active evasion — not adopted
Multi-layer encoding for EVADING a WAF during an active payload fire is detection-evasion-adjacent
and conflicts with the payload-tagging discipline. Tagged-variant ingest (dimension 3 b) is fine;
actively steering payloads around a WAF to land an unverified hit is not ReachAgent behavior.

### (d) rate-limit / threads — already handled
recon_engine.sh defaults 150 rps / 50 threads via env; hexstrike threads 10/40/50 by stealth.
Phase 2 already added per-tool rate/thread/timeout envs. No change.

## Dimension 6 — Anything else structurally notable

### (c) cai — C2 / post-exploitation / lateral-movement tooling — non-compatible with §1
cai ships `command_and_control/`, `lateral_movement/`, `data_exfiltration/`, `privilege_scalation/`.
ReachAgent explicitly has NO C2/post-exploitation capability (§1). Not adoptable. The tool
*categories* (evidence capture, inventory check) are useful contrast for what ReachAgent
deliberately excludes — noted, not adopted.

### (b) durable-run / resume
pentestgpt RunSnapshot + resume; CBB session_file JSON persistence surviving crashes. ReachAgent's
graph is in-memory (NetworkX; Neo4j migration planned §13). A durable run snapshot would let a
scan resume after a crash. **Checkpoint needed:** fits §13 Neo4j migration or a lightweight
snapshot export; don't add before the store decision.

### (b) sandbox policy for eval
pentestgpt carries `SandboxPolicy`; strix enforces image budgets and sandbox exec transport
errors. ReachAgent's eval is docker-compose (VAmPI/juice-shop) but has no explicit sandbox policy
enforcement primitive. **Checkpoint needed:** lightweight policy object or rely on ScopeGuard +
docker isolation as-is.

### (d) loop prevention — already handled
CBB `LoopDetector` records tool/args repetition and breaks. ReachAgent's `check_budget` +
`prior_attempts_in_neighborhood` in `score_and_select` already terminate repetitive selection. No
change.

### (d) scope enforcement — already handled, stricter
CBB `scope_checker.py` and hexstrike `in_scope/out_of_scope` are documented policy; ReachAgent's
ScopeGuard deny-by-default is enforced at the execution layer before spawn/fire. Strictly stronger.

### (d) LLM context management — N/A
strix compacts context and manages image budgets; CBB compresses working memory every 5 steps.
ReachAgent's loop is not an unbounded LLM ReAct loop (Coordinator is deterministic), so context
compaction is not needed in the same form. Not adopted.

### (d) testing discipline — already handled
pentestgpt (`test_loop`, `test_plan`, `test_executor`, `local_target` fixture) and CBB
(`test_recon_adapter`, `test_vuln_scanner_review_fixes`) unit-test non-network logic. ReachAgent's
hermetic fixtures + AST boundary tests + zero-findings assertions cover the same ground and are
strictly more safety-focused (role boundaries). No change.

---

## Cross-cutting notes

- **The single highest-value reference is claude-bug-bounty's `waf_response_analyzer.py`**: it is
  the concrete shape of the deferred calibration-baseline helper (dimension 5 b), and its
  business-signal / log-id fingerprinting is directly reusable as a fact-layer response
  attribute — pending the design checkpoint.
- **JWT is the cleanest quick (a) win** (dimension 3): an existing oracle (`jwt_forgery`
  STRUCTURAL) with thin payload coverage; CBB's MIT-licensed `jwt_scanner.py` provides a distinct
  technique corpus to mine, all still through `run_oracle`.
- **firer transient-retry (dimension 5 a)** is the most concrete "fits as-is" code improvement:
  bounded backoff + audited, no new family, no license concern.
- **No reference gives ReachAgent a reason to weaken confirmation.** hexstrike trusts tools, CBB
  and cai trust the LLM, pentestgpt grounds actions but not vulnerabilities. All five reinforce
  (not challenge) the run_oracle-before-finding invariant.
- **License posture holds**: only MIT/Apache-2.0 technique reuse proposed (JWT corpus, OOB shapes,
  retry/backoff, WAF fingerprints); cai core read-only; no GPL; no verbatim copies.

---
Phase 1 complete — docs only. (b) items need human decision before any Phase 2 code. STOP for review.
