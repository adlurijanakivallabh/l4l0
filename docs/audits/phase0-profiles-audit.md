# Phase 0 — Expanded allowlist audit → named RECON_PROFILES (docs only)

**Branch:** `master` @ `bec199f` (three live-reasoning layers built: `live_tuning.py`, `vuln_tuning.py`, `payload_tuning.py`)
**Purpose:** Shape what Phase 1 builds — LLM picks ONE named profile (small, safe, well-tested) not dozens of freeform params. No code in this commit.

## 0. Licenses (stated before pulling any config)

| ref | path `~/Downloads/references/…` | LICENSE |
|-----|--------------------------------|---------|
| pentestgpt | `PentestGPT/` | MIT `Copyright (c) 2023 Grey_D` |
| strix | `strix/` | Apache-2.0 |
| cai | `cai/` | Dual: `src/cai/agents` MIT, `src/cai` core Alias Robotics research-use only |
| hexstrike-ai | `hexstrike-ai/` | MIT `Copyright (c) 2026 Muhammad Osama (0x4m4)` |
| claude-bug-bounty | `claude-bug-bounty/` | MIT `Copyright (c) 2026 Claude Bug Bounty Hunter Contributors` |

No GPL/AGPL among the five — technique paraphrase safe, no verbatim copy. cai core read-for-ideas only.

## 1. Tools — genuinely new vs 25 already built

**25 already built (Big Task 1 + 20):** `nmap`, `masscan`, `rustscan`, `subfinder`, `amass`, `theHarvester`, `whatweb`, `katana`, `gobuster`, `ffuf`, `feroxbuster`, `dirb`, `httpx`, `sslscan`, `sslyze`, `testssl`, `arjun`, `paramspider`, `x8`, `wpscan_passive`, `nuclei`, `nikto`, `sqlmap`, `dalfox`, `commix`, `jwt_tool` (26 with `jwt_tool` counted).

Cross-ref against 5 refs' actual invocations (from `comprehensive-reference-audit` + `recon-gap-audit`):

| tool | ref that uses it | already built? | verdict |
|------|------------------|----------------|---------|
| `httpx` | hexstrike, strix, CBB | yes | skip — gap is threads/timeout/rate, not binary |
| `nuclei -update-templates` | CBB | ops | skip — template update is deploy, not wrapper |
| `feroxbuster` built-in wordlist | hexstrike | yes | skip |
| `x8` | hexstrike | yes | skip |
| `OneListForAll` (OLA) as tool | CBB wordlist pointer | no | not a tool — wordlist file, see §2 |
| `byp4xx` (403 bypass) | CBB `bypass_403.sh` | no | **not added** — classified (b) in comprehensive audit: 403-bypass is validator/oracle judgment, not recon fact. Do not auto-adopt as recon. |
| `socialhunter` etc. | — | — | no new binary — refs add no new *binary* beyond the 25 that is worth wrapping; the gap is *how* they invoke (wordlist/status/flags), not *which* binary |

**Result:** 0 new binaries to wrap in Phase 1. The allowlist expansion is entirely about *profiles* over existing tools, not new Runner classes. This is intentional — `recon-gap-audit` already concluded the gap was tunables (~18), not missing binaries.

## 2. Wordlists — defaults each ref actually uses

| wordlist path (as ref names it) | ref | already vendored locally (`/usr/share/seclists`, `third_party/`) | worth vendoring? |
|--------------------------------|-----|---------------------------------------------------------------|------------------|
| `Discovery/Web-Content/raft-medium-directories.txt` | hexstrike `raft-medium-dirs.txt`, CBB | **yes** — `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt` present on Kali | no — already there |
| `directory-list-2.3-medium.txt` | hexstrike | **yes** | no |
| `Discovery/Web-Content/common.txt` | hexstrike | **yes** | no |
| `dirb/common.txt` | CBB default, hexstrike fallback | **yes** `/usr/share/wordlists/dirb/common.txt` | no — safe default already |
| `Discovery/Web-Content/CMS/wordpress.fuzz.txt` | hexstrike tech-aware | **yes** | no |
| `Discovery/Web-Content/api/api-seen-in-wild.txt` | hexstrike API | **yes** | no |
| `Discovery/Web-Content/x8/params.txt` / `burp-parameter-names.txt` | hexstrike x8 | **yes** | no |
| `raft-large-words.txt` / `raft-large-directories.txt` | hexstrike large | **no** on minimal Kali | **maybe** — but `raft-medium` already covers 90%; large is 10× slower for marginal gain. Defer — note as `RECON_LARGE` opt-in env, don't vendor in Phase 0. |
| `OneListForAll/onelistforallshort.txt` | CBB pointer | **no** | **worth noting, not vendoring** — 100k+ lines, heavy. Note as `OneListForAll` pointer in profile `aggressive_recon` but don't ship; user can mount `/usr/share/wordlists/onelistforall/...` if present. |
| `SecLists/Discovery/Web-Content/graphql.txt` | hexstrike graphql | **yes** if Seclists present | no — already in Seclists tree |
| `nuclei-templates` (not a wordlist, template set) | hexstrike, CBB | **yes** if `nuclei` templates installed | no — ops |

**Conclusion:** No new wordlist needs vendoring in Phase 0. All 7 `RECON_ALLOWLIST` wordlists already cover the refs' defaults; `raft-large`/`OneListForAll` are deferred opt-ins, not missing.

## 3. Status-code filtering profiles per target type

Refs differentiate little — most use a single set, but type-specific filtering is a real gap (current status filtering mostly fixed, 403 already fixed as `access_restricted` fact).

| target type | hexstrike (closest) | CBB | pentestgpt | strix | **proposed ReachAgent profile** |
|-------------|---------------------|-----|------------|-------|---------------------------------|
| **API** (`/api`, JSON, `swagger`/`openapi` in body) | `200,204,301,302` (API 401 is auth, not “found”) | — | — | — | `api_target`: `200,204,301,302` — 401/403 are ACL facts, not “found” for API |
| **CMS** (WordPress `wp-content`, etc.) | `200,204,301,302,307,401,403` | raft-medium + 403 note | — | — | `cms_target`: `200,204,301,302,307,401,403` — 401/403 signal ACL surface worth noting |
| **static site** (generic HTML, no tech hint) | `200,204,301,302,307` | — | — | — | `static_site` (safe default): `200,204,301,302,307` — no 401/403 noise |
| **SPA** (JS-heavy, `jsl`/`aff` crawl) | `200,204,301,302` + JS crawl | — | — | — | `spa_target`: `200,204,301,302` — JS routes often 200, filter 3xx aggressively |

All four are **allowlisted `status_codes` sets** — the LLM picks one set per target, not arbitrary codes. Reuses the 3 `RECON_ALLOWLIST["status_codes"]` already built, adds `200,204,301,302` as the 4th API/SPA set (already there). No freeform code list.

## 4. Flag/config presets → profiles

Beyond `rate/threads/timeout` (recon-gap-audit), refs ship **target-type modes**, not just per-flag tuning:

| mode | ref | what it does | maps to profile |
|------|-----|--------------|-----------------|
| **quiet** (stealth) | hexstrike low `rate 100`, `rustscan --ulimit 1000`, `subfinder --rateLimit 10` | low threads, longer timeout | `quiet_recon`: `flags=()`, low threads via env `REACHAGENT_*_THREADS=10`, timeout `10s` |
| **aggressive** | hexstrike `rustscan adaptive ulimit 5000→8000`, `masscan --rate 10000`, `gobuster -t 50` | high threads, short timeout | `aggressive_recon`: `flags=("-t","50")`, rate 10000, ulimit 8000 |
| **API-focused** | hexstrike `api-seen-in-wild` wordlist + `200,204` only | API wordlist + tight codes | `api_target`: wordlist `api-seen-in-wild.txt` + `flags=("-t","20")` + `200,204,301,302` |
| **CMS-focused** | hexstrike `wordpress.fuzz` + `403` include | WP wordlist + 401/403 | `cms_target`: `wordpress.fuzz.txt` + `flags=("-t","20")` + `200,204,301,302,307,401,403` |

These are exactly the `flag_presets` already in `RECON_ALLOWLIST` (`()`, `-t 20`, `-t 50`, `--timeout 10s`, `-t 20 --timeout 10s`) — no new flags needed.

## 5. Proposed RECON_PROFILES (bundled, small, well-tested)

```python
RECON_PROFILES: dict[str, ReconProfile] = {
    # wordlist, flag_preset, status_codes triple + tool set hint
    "api_target":       dict(wordlist="api-seen-in-wild.txt",       flags=("-t","20"), status="200,204,301,302",               tools=["gobuster","ffuf","httpx","whatweb","katana"]),
    "cms_target":       dict(wordlist="wordpress.fuzz.txt",         flags=("-t","20"), status="200,204,301,302,307,401,403",   tools=["gobuster","ffuf","whatweb","wpscan_passive"]),
    "static_site":      dict(wordlist="raft-medium-directories.txt",flags=(),         status="200,204,301,302,307",           tools=["gobuster","ffuf","katana","httpx"]),
    "spa_target":       dict(wordlist="raft-medium-directories.txt",flags=("-t","20"), status="200,204,301,302",               tools=["katana","gobuster","httpx","whatweb"]),  # katana -jsl -aff deferred, note
    "aggressive_recon": dict(wordlist="raft-medium-directories.txt",flags=("-t","50"), status="200,204,301,302,307,401,403",   tools=["gobuster","ffuf","feroxbuster","masscan","nmap","subfinder","amass"]),
    "quiet_recon":      dict(wordlist="dirb/common.txt",            flags=("--timeout","10s"), status="200,204,301,302,307",   tools=["gobuster","httpx","whatweb"]),
}
```

- Tool sets are **hints**, not hard allowlists — actual `scan/entrypoint` runner dispatch still respects `detect_target_type` (domain vs IP vs host:port) + scope; a profile that lists `masscan` on a domain target still won't run `masscan` on that target (IP-only dispatch). This is intentional — profile tunes *how* tools run, `detect_target_type` tunes *whether* they run.
- Each field is drawn from `RECON_ALLOWLIST` — profile choice is `profile_name in RECON_PROFILES`, validated before anything executes; invalid → safe default `static_site` (or `api_target` if `/api` in path), log why.
- `nuclei/sqlmap` etc. remain signal-gated tier, not recon — not in these profiles.
- No new wordlist vendored; `OneListForAll`/`raft-large` remain opt-in via `REACHAGENT_*_WORDLIST` env if present on disk.

## 6. What Phase 1 will build (and what it won't)

**Will:** `RECON_PROFILES` dict in `live_tuning.py` (or alongside `RECON_ALLOWLIST`), `propose_recon_profile(signals) -> str` with same `AnthropicTunerClient` shape + `_validate_choice` against `RECON_PROFILES` keys, wiring in `GobusterRunner` + `FfufRunner`/`FeroxbusterRunner`/`DirbRunner`/`X8Runner` to read profile's `wordlist/flags/status_codes` when `REACHAGENT_RECON_PROFILE=1` or `REACHAGENT_RECON_LIVE_TUNING=1` (default OFF), hermetic mocked tests.

**Won't:** New Runner classes, new wordlist vendoring, unbounded corpus, 403-bypass, recursion/extension fuzzing (all (c) per audit), new oracle, or payload generation.

**Gate:** `uv run ruff check --fix . && uv run ruff format . && uv run mypy src && uv run pytest -q` (fresh whole-tree), one commit per phase, Co-Authored-By.

---
No code in this commit. Phase 1 starts after review.
