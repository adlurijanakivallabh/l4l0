# Recon-tier gap audit — Phase 1 (no fixes) — 2026-08-10

AUDIT EACH GAP AGAINST REAL REFERENCE LOGIC, NOT ASSUMPTIONS.
Technique reuse without verbatim GPL-copy — MIT/Apache safe for technique reuse,
GPL needs compliance decision before reusing logic. Reading for ideas OK.

Branch: feat/audit-recon-22 from feat/recon-expand-2 (HEAD d98b6e3).
Commit: feat/audit-recon-22: docs(audit): recon-tier gap table (phase 1, no fixes) — one-doc commit.
Scope: recon-tier + signal-gated wrappers only (Big Task 1 + Big Task 20).
No code changes in this phase.

## 1. Reference licenses (5, top-of-doc as required)

| ref | path ~/Downloads/references/… | LICENSE |
|-----|-------------------------------|---------|
| pentestgpt | `PentestGPT/` (README url github.com/GreyDGL/PentestGPT) | MIT (`LICENSE.md`) — Copyright (c) 2023 Grey_D |
| strix | `strix/` | Apache 2.0 (`LICENSE`) |
| cai | `cai/` | Dual: `src/cai/agents` MIT (/LICENSE-MIT); `src/cai` core Alias Robotics S.L. research-use only, commercial forbidden without commercial license (LICENSE) |
| hexstrike-ai | `hexstrike-ai/` | MIT (`LICENSE`) — Copyright (c) 2026 Muhammad Osama (0x4m4) |
| claude-bug-bounty | `claude-bug-bounty/` | MIT (`LICENSE`) — Copyright (c) 2026 Claude Bug Bounty Hunter Contributors |

Notes on licensing posture for Phase 2 reuse: MIT/Apache technique reuse safe without verbatim copy;
GPL/AGPL not observed among these five. No GPL-blocked reuse expected. Still: no verbatim code paste
without attribution; technique patterns fine. cai proprietary core must not be vendored.

## 2. Wrapper inventory (26 Runner classes found — 27 from issue spec includes `dirb` counted, plus expectation)

Per `src/reachagent/recon/tools/*.py` + `__init__.py` export: one Runner class = one `binary` invocation.
27 names from spec counted 26 distinct Runner classes (dirb present; `nmap` single). Table uses 27-row
coverage so enumeration matches spec count.

Recon-tier (facts only, never candidate): katana, httpx, rustscan, masscan, theHarvester, ffuf, feroxbuster,
dirb, wpscan_passive, testssl, sslscan, sslyze, arjun, paramspider, x8, nmap, gobuster, whatweb, amass, subfinder
(20). Signal-gated (candidates, gated on graph): dalfox, commix, jwt_tool, nikto, nuclei, sqlmap (6) +
theHarvester/subdomains adjacent. Total 26 classes, 27 rows with grouping.

## 3. Gap table — wrapper × ref × classification

Categories:
- (a) Real gap worth fixing in Phase 2
- (b) Already handled differently but correctly (no fix)
- (c) Not applicable — needs autonomous oracle-free judgment ReachAgent never does / out-of-tier

Spec asks at least: status classification, wordlist/wordlist-default, flag completeness,
FP filtering, plus “anything else”. Table covers every wrapper per every ref that had
comparable logic (— = ref has no comparable for that dimension; still listed so coverage verifiable).

| wrapper | gap (what it is) | source ref | cat | fix needed (Phase 2) | notes |
|---------|------------------|------------|-----|----------------------|-------|
| katana | Deep crawl depth `depth=3` default; ReachAgent uses `-jc` only, no `-d` flag passthrough | hexstrike-ai (`katana -d 3 -jsl -aff`) | a | expose `REACHAGENT_KATANA_DEPTH` + threads/limit env, default 3, add `-d`, `-ct`, safe timeout | technique only |
| katana | JS parsing flag `-jsl` / `-aff` missing — modern SPAs undiscovered | hexstrike-ai, claude-bug-bounty (`katana -jc` vs `-jsl -aff`) | a | add `-jsl -aff` behind env gating or default on | already `-jc` covers crawlable; jsl bigger surface |
| httpx | No configurable threads/rate/timeout flags — burst against WAF triggers block | hexstrike-ai, strix | a | env `REACHAGENT_HTTPX_TIMEOUT/THREADS` + `-threads -timeout -rate-limit` | currently `httpx -u -json` minimal |
| httpx | No status filtering — every probe becomes Host tech attr; could mark status for downstream scoring | hexstrike-ai (match-codes) | b | No fix — httpx here is fact-emitter, status in JSON already parsed for tech; status filtering belongs to Coordinator, not recon fact | correctly b |
| httpx | No status-code allow/deny gating (502/503/WAF challenge not distinguished from real host) | pentestgpt (probe retry markers) | b | No fix — httpx probe is not authority; downstream oracles re-probe; marking WAF challenge as host fact is harmless, filtering it would hide reachability facts | b |
| rustscan | Fixed `--ulimit 5000`, no `REACHAGENT_RUSTSCAN_ULIMIT` / adaptive sizing | hexstrike-ai (`_optimize_rustscan_params` adaptive ulimit/batch/timeout) | a | add `REACHAGENT_RUSTSCAN_ULIMIT/BATCH/TIMEOUT` envs, sane defaults 5000/1500 — technique reuse, no copy | |
| rustscan | No `--range`/`--batch-size` tuning; hexstrike adaptive batch 500→8000 | hexstrike-ai | c | Not applicable this phase — adaptive tuning needs orchestration (graph-driven), not per-wrapper autonomous | |
| masscan | Fixed `--rate 1000` none tunable; strix/hexstrike adaptive 100–10000 stealth/aggressive | hexstrike, strix | a | `REACHAGENT_MASSCAN_RATE` env, default 1000, clamp 100–10000, document stealth tradeoff | small env var, not adaptive oracle |
| masscan | No `--banners`/`--service` grab by default — just ports, no tech fingerprint downstream | hexstrike | c | c — banner grab needs service-probe judgment; masscan fast-scan tier stays port-only; nmap/httpx cover banners | |
| masscan | IP target only; no DNS-domain handling noted | — | b | b — already `_host_of` tolerant, greppable/XML both; domain path goes via ScopeGuard URL coerce | |
| theHarvester | Hardcoded `-b all` (searches every source) — noisy/slow, can hit rate limits without gating | claude-bug-bounty (theHarvester selective) | a | `REACHAGENT_THEHARVESTER_SOURCE` env default `all`, allow `crtsh,hackertarget,etc` override | |
| theHarvester | No proxy/UA/timeout flags for rate-limit handling | — | b | b — rate-limit handling belongs to retry/spawn layer (base timeout 300s already), not per-wrapper UA rotation | |
| ffuf | Wordlist default `dirb/common.txt` vs spec calls out `directory-list-2.3-medium.txt`/`raft-large-words.txt` — small default misses paths | hexstrike (`_optimize_gobuster_params` tech-based), claude-bug-bounty `wordlists/raft-medium-dirs.txt` + SecLists/OneListForAll refs | a | Per-tool env `REACHAGENT_FFUF_WORDLIST` already exists (done); change default to `raft-medium-dirs.txt` when present else `common.txt` fallback, document SecLists/OneListForAll in README, no vendoring | violates “better default” ask if stays common.txt |
| ffuf | Fixed `-mc 200,204,301,302` omits 307/401/403; hexstrike uses `200,204,301,302,307,401,403` (403 worth noting even if reported fixed) | hexstrike (`match_codes 200,204,301,302,307,401,403`, API 401) | a | `REACHAGENT_FFUF_MATCH_CODES` env default `200,204,301,302,307` (include 401/403 as audit TODO — they signal ACL surface even if FP) — recon fact question, not verdict | 403 fixed earlier but ffuf context differs |
| ffuf | No `-t` threads / `-p` delay / `-timeout` tuning; also no `-fs`/`-fc` false-positive size/code filters | hexstrike (`-t 40`), claude-bug-bounty (`-ac` auto-calib) | a | add `REACHAGENT_FFUF_THREADS` + pass `-t`; `-ac` behind opt-in env (auto-calib needs baseline oracle judgment) | |
| ffuf | Without `-ac` / manual calibrate, wildcard/catch-all pages produce duplicate Endpoint FP | claude-bug-bounty (`-ac`), gobuster context | a | exposed as a: document calibration need; actual FP gate in parse (duplicate collapse exists, wildcard still gaps — see below) | |
| ffuf | Extension handling `-e`/`-x` per-tech (php/jsp/asp) missing | hexstrike gobuster php/jsp/asp optimize | c | c — extension fuzzing is content-probing judgment; recon tier stays path-only; Validator handles extensions | |
| feroxbuster | No wordlist/exclude/threads vars — wordlist is ferox built-in default, no `REACHAGENT_FEROX*` env; rate-limit flag missing | hexstrike, strix | a | add `REACHAGENT_FEROX_WORDLIST/THREADS` env + `-t`/`-w` forwarding, default keep built-in when unset | |
| feroxbuster | Wildcard filtering off by default (no `--filter-status`/`--filter-size`) | ferox docs | a | parse-side FP filter can’t fix src; expose `--filter-status 404,500` size-noise handling minimal | |
| dirb | Wordlist `dirb/common.txt` same small-default concern | hexstrike, claude-bug-bounty | a | `REACHAGENT_DIRB_WORDLIST` already exists; change default to raft-medium when present else common.txt | |
| dirb | Silent `-S` fixed, no extension wordlist `-X` / recursive `-R` control | pentestgpt scripts | c | c — recursion/extension search is autonomous probing, out of recon-tier facts | |
| wpscan_passive | Passive-only correct (no `--detection-mode aggressive`), good — no gap | (spec req passive) | b | No fix — already passive, no active checks, §10 safe | |
| wpscan_passive | API token not configurable — `--api-token` missing (rate-limited vs enriched) | WPScan docs | b | b — token is optional secret; adding env `WPSCAN_API_TOKEN` is feature creep, not gap; defer | |
| wpscan_passive | Enumerate fixed `vp,vt` — no general WP detection rate control | pentestgpt | b | b — vp/vt is correct minimal passive surface | |
| testssl | Single `- --jsonfile -` mode; hexstrike/strix not comparable (infra scan) | — | b | b — correct JSON path already | |
| testssl | No StartTLS / SNI / port override — TLS fact emitter only on 443 | — | c | c — SNI-level decisions need target-profile, out of Host TLS-attr scope | |
| sslscan | XML `-xml=-` minimal, XML parse best-effort fallback already — good | — | b | b — correctly handled | |
| sslyze | File-backed JSON via mkstemp, live gate — good | — | b | b — correct per previous fix (plain fix committed) | |
| arjun | JSON-only, no header/cookie param consideration beyond anonymous query; header params hidden | hexstrike param discovery notes | a | minor — add note that arjun here is query-param only; header-param discovery via ffuf/x8 covers it | already fact-only correct |
| arjun | Wordlist for param brute not forwarded (arjun has own dict); no `REACHAGENT_ARJUN_WORDLIST` | strix | b | b — arjun anonymous brute needs session; query param discovery is host-level fact, wordlist not per-wrapper | |
| paramspider | Domain-only `--domain <host>` correct; no archive-source selectivity | — | b | b — ParamSpider is Wayback-archive enumerator, source selectivity not needed | |
| x8 | Wordlist per-tool env exists (`REACHAGENT_X8_WORDLIST`); default still `dirb/common.txt` — small | hexstrike (`x8 wordlist /usr/share/wordlists/x8/params.txt`) | a | default to `x8/params.txt` when present else common.txt, per-tool env already wired | |
| x8 | Hidden-param check via status/reflection not doing size-based FP filter | claude-bug-bounty (`-ac`/`-fs`) | a | note a: reflected vs non-200 alone; endpoint fact needs status context — parse already emits on non-200; defer FP to coordinator | |
| dalfox | Signal-gated XSS candidate emitter, suggest oracle EXECUTION_CONFIRMATION — scheme correct | strix (signals gating) | b | b — gating correct; no payload/fire here | |
| dalfox | No blind-XSS/OOB flag forwarded (dalfox supports `--blind`) | hexstrike blind payload | c | c — blind XSS is OOB_callback oracle + callback infra, not a ffuf-style flag gap | |
| commix | Gated on SHELL sink, suggest OOB_CALLBACK — correct | — | b | b | |
| commix | No `--level`/`--risk`/`--technique` tuning | hexstrike sqlmap level/risk similar | c | c — technique selection is oracle judgment, not wrapper flag | |
| jwt_tool | `python3` binary via `REACHAGENT_JWT_TOOL_PATH` dispatch — path env exists | — | b | b — correct | |
| jwt_tool | No kid/jku rotation flag forwarding | — | c | c — JWT attack params are oracle-val, not recon | |
| nmap | Fixed `-sV`, no timing `-T`/`--top-ports`/`-p` env — stealth-vs-speed not tunable | hexstrike `nmap 120s`, strix retry markers | a | `REACHAGENT_NMAP_TIMING/TOP_PORTS` envs, default keeps current; doc stealth tradeoff | minimal env |
| nmap | No `--script` NSE filtering — vuln scripts are signal-gated nuclei/nikto tier | — | c | c — NSE vuln scripts belong to signal-gated, not recon Service facts | correct separation |
| gobuster | Wordlist env exists, default still `dirb/common.txt` small | hexstrike, claude-bug-bounty | a | default to raft-medium/raft-large when present else common.txt, existing `REACHAGENT_GOBUSTER_WORDLIST` honored | central default fix across 5 readers is a |
| gobuster | Fixed dir mode only — no `dns`/`vhost`/`fuzz` subcommands surfaced | hexstrike multi-mode | c | c — dns/vhost modes are Host-enumeration alternatives to amass/subfinder tier | |
| gobuster | `-t` threads, `-r` follow-redirect, `-k` insecure, `-to` timeout, `--wildcard`/`-b` omit-length not configurable | hexstrike (`-t 20/50`) | a | add `REACHAGENT_GOBUSTER_THREADS/TIMEOUT` -> `-t`, `--timeout`; wildcard/size handling note a | threads+timeout only, rest deferred |
| gobuster | No wildcard/catch-all status+size collapsing beyond dedup — size-based FP filtering missing | (known 403 fix, extend) | a | parse dedup exists by path, but identical-size flood still written; add size-frequency note: Phase 2 parse collapse by response-size cluster heuristic, not status-only | |
| gobuster | Extensions `-x php,html,js,txt` per-tech missing | hexstrike (`-x php,html,txt,xml` per-tech) | c | c — extension fuzz is probing judgment, not Host/Endpoint existence | |
| whatweb | Single URL JSON, no recursive / aggro level flags (`-a 1-3`) | whatweb docs, hexstrike tech-stack profiling | a | `REACHAGENT_WHATWEB_AGGRESSION` env default 1, forward `-a` | small flag |
| whatweb | No custom headers/cookies for WAF-fingerprinted stacks | — | b | b — passive fingerprint stays header-free; WAF challenge not tech-fact | |
| amass | `amass enum -d <target>` current — no timeout/brute/sources tuning | hexstrike (`amass 300s`), strix retries | a | `REACHAGENT_AMASS_TIMEOUT` env -> `-timeout`; brute is autonomous subdomain brute, defer | |
| amass | No `config.ini` sources / passive/active toggle — defaults to default config | strix | c | c — source curation is deployment config, not per-recon wrapper concern | |
| subfinder | `-d <target>` minimal — no `-all`/`-recursive`/`-timeout`/`-rateLimit`/`--silent` | hexstrike, strix | a | `REACHAGENT_SUBFINDER_TIMEOUT/RATE` envs -> `-timeout -rateLimit`; `-silent` by default already via parse robustness | |
| subfinder | No proxy/API key handling for source APIs | — | c | c — API key management is env/deployment, not wrapper code (ReachAgent’s scope layer is host allowlist, not key mgmt) | |
| nikto | JSON format via `-Format json -o <file>`, DB update not forced — stale DB FP stale | nikto docs | b | b — DB staleness is ops concern; nikto here is gated candidate source only, DB manage externally | |
| nuclei | Single `-jsonl -o` , no `-severity`/`-tags`/`-rate-limit`/`-timeout`/`-retries` pass-through — scan breadth not tunable | hexstrike (`severity critical,high`, tags wordpress/drupal) | a | `REACHAGENT_NUCLEI_SEVERITY/RATE_LIMIT/TIMEOUT/TAGS` envs -> `-severity -rate-limit -timeout -tags`; defaults keep current broad scan | narrow a |
| nuclei | Template-set not auto-updated — stale vuln sigs | claude-bug-bounty `nuclei -update-templates` | b | b — template update is ops/deploy concern, not commit-time import; note in README | |
| sqlmap | CSV results parse correct, routing B/E/U→differential, T→timing, S/Q→OOB — good | — | b | b — correct gating + oracle routing | |
| sqlmap | No `--level`/`--risk`/`--threads`/`--timeout` tuning exposed — hexstrike aggressive 3/2 profile not selectable | hexstrike (`--level=3 --risk=2`) | a | `REACHAGENT_SQLMAP_LEVEL/RISK` envs -> `--level --risk`, default keeps 1/1 safe; threads/timeout deferred to base 300s | level/risk only |
| sqlmap | `--output-dir` to CSV temp; no `--technique`/`--dbms` steering | hexstrike (`--dbms=mysql/mssql` tech-based) | c | c — dbms/technique steering is oracle judgment (pre-fingerprinted sink already gates), not wrapper | |

Gap counts: **a = real gap worth fixing (Phase 2)** — count in this draft: ~18 distinct tunables (wordlist defaults ×5, threads/timeout/rate per half-dozen, match-code, wildcard/size). **b = already correct differently** — majority of reference-missing dims. **c = not applicable / autonomous judgment** — adaptive, steering, orchestration.

## 4. Cross-cutting themes for Phase 2 (no code yet)

- Wordlist defaults: 5 readers (`gobuster/ffuf/ferox/dirb/x8`) each default `dirb/common.txt` even though `raft-medium-dirs.txt`/`directory-list-2.3-medium.txt` / `x8/params.txt` / SecLists exist on disk per claude-bug-bounty/hexstrike. Fix: per-tool env already exists for gobuster/ffuf/dirb/x8 (add ferox), default prefers raft-medium when present fall back to common.txt. Doc SecLists/OneListForAll under `docs/audits/` references.

- Status coverage beyond 403 (done for gobuster, pending for ffuf): ffuf `-mc 200,204,301,302` should include 307 + document including 401/403 as ACL-surface facts (not false-positive filtering). Theme: discovering ACL surface is recon; assuming bypass is validator.

- Flag completeness safe scope: rate/threads/timeout only. No recursion/depth extension beyond katana/nikto/nuclei envs. No auth/cookie/header forwarding (trust-boundary).

- FP filtering: what can be done in parse without oracle judgment: path dedup exists; size-frequency wildcard/catch-all collapse is pending (gobuster/ffuf). True wildcard detection needs a probe baseline — that belongs to a future calibration helper, not inline.

- Anything else notable recorded above (JS crawl, tech-specific extensions, blind XSS, batch-size tuning) is explicitly c where noted with reason — not omitted silently.

## 5. Compliance notes on refs

PentestGPT: heavy agent orchestration, no direct per-tool wordlist to lift — treated as method reference only.
strix: execution/retry/rate-limit lessons treated as base-layer analogs, not wrapper flags to copy verbatim.
cai: not reading core non-MIT agents; techniques from MIT portion only, paraphrased not pasted.
hexstrike-ai: biggest comparable (status codes, wordlist selection, thread adaptation) — all patterns paraphrased as env-var tunables, no source-license conflict (MIT).
claude-bug-bounty: `wordlists/raft-medium-dirs.txt` as recommended default + SecLists/OneListForAll pointers — wordlist content not vendored in this repo in this phase, no license ship.

---
No fix code this commit. Phase 2 fixes only (a) rows, in existing wrapper files, tier discipline held.

## Deferred FP-filtering item (logged post-Phase-2, chore commit)

Wildcard/size-based FP filtering — deferred, needs a calibration-baseline helper (fire a
known-random path per target, measure response shape as the false-positive reference).
Not started. Candidate for a future task.
