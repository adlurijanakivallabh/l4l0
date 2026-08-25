# LLM-first ReachAgent execution plan

Status: implementation plan for the GUI-only scan path

## Stage 0 — repository and reference discovery

The existing engine already has the important safety and evidence boundaries:

- `src/reachagent/scan/orchestrator.py` owns the graph-backed scan loop and the
  23-class `ALL_CLASSES` coverage list.
- `src/reachagent/scan/entrypoint.py` dispatches the existing recon wrappers and
  performs API/parameter discovery.
- `src/reachagent/recon/tools/` contains the installed-tool adapters. Recon
  adapters emit graph facts; `sqlmap`, `dalfox`, `commix`, `nuclei`, `nikto`, and
  `jwt-tool` are signal-gated candidate sources, not finding authorities.
- `src/reachagent/tools/payload_chain.py` already resolves payloads from the
  payload library and requires an independent oracle before a finding is
  written.
- `src/reachagent/execution/firer.py` and `ScopeGuard` enforce target scope;
  tool runners use argument arrays, `shell=False`, audit rows, and skip absent
  binaries.
- `src/reachagent/llm/client.py` supports DeepSeek, OpenAI, and compatible
  chat-completions APIs. `src/reachagent/llm/runtime.py` scopes settings to a
  scan context and exposes strict GUI mode; library callers retain compatibility
  fallback behavior for fixtures.
- `src/reachagent/gui/app.py` is the only supported user entry point. It starts
  the real graph/audit scan and streams snapshots to the browser. GUI requests
  require a configured LLM and a validated execution plan.

Reference research was read from the local copies under
`~/Downloads/references/`:

- PentAGI (`frontend/`, MIT): React/Vite, Tailwind/Radix, Apollo GraphQL
  subscriptions, split flow/report views, reconnect/refetch behavior, and a
  report export surface. This is a visual and streaming reference only.
- CAI (Apache-2.0): FastAPI/SSE plus a Textual terminal UI; no browser product
  UI to copy. Its typed phase/tool event stream is the useful concept.
- HexStrike-AI (MIT), PentestGPT (MIT), and Claude Bug Bounty (MIT) do not ship
  a comparable browser GUI in the checked-out references.

Official tool/protocol references used for the adapter boundary:

- Nmap recommends XML (`-oX`) for programmatic consumers because it is stable
  and extensible: <https://nmap.org/book/output-formats-xml-output.html>
- Gobuster exposes directory, DNS, vhost, and fuzzing modes through its
  documented CLI: <https://github.com/OJ/gobuster>
- sqlmap documents both command-line and REST API control. ReachAgent keeps its
  own scope/oracle gate in front of the adapter:
  <https://github.com/sqlmapproject/sqlmap/wiki/usage>
- MCP standardizes model-discoverable tools but explicitly leaves authorization
  and user interaction to the host. ReachAgent therefore exposes only validated
  catalog entries, never raw shell or request capabilities:
  <https://modelcontextprotocol.io/specification/2024-11-05/index>

## Stage 1 — one validated LLM execution plan

Implemented in `src/reachagent/llm/planner.py`: one small planner module with three immutable concepts: a catalog entry, a
phase, and an execution plan. The catalog is built from the existing wrappers,
not duplicated command strings. Each plan contains:

1. ordered phases (recon, surface, insertion-points, payloads, verification,
   chains, report; the model may omit a phase only when its evidence says it is
   inapplicable);
2. validated tool names and optional profile/class/payload selections;
3. a short model rationale for the GUI audit stream;
4. a bounded request/tool budget.

The model receives target classification, current graph facts, operator prompt,
the catalog, and the complete allowlisted vulnerability-class names. It returns
JSON only. Validation rejects unknown phase/tool/class/payload names, duplicate
or over-budget actions, raw commands, arbitrary URLs outside scope, and
state-changing options. There is no fallback plan in the GUI path: a missing
provider, malformed response, or provider error fails before network execution.
Tests may inject a fake planner/client.

The catalog includes all existing recon adapters (nmap, masscan, rustscan,
subfinder, amass, theHarvester, whatweb, httpx, katana, gobuster, ffuf,
feroxbuster, dirb, arjun, paramspider, x8, TLS probes, wpscan passive) and the
signal-gated enrichment adapters (nuclei, nikto, sqlmap, dalfox, commix,
jwt-tool). Signal-gated tools remain conditional on graph evidence and their
output remains an inert candidate until a ReachAgent oracle reconfirms it.

## Stage 2 — connect the plan to the real scan

Implemented: `src/reachagent/llm/planner.py` now builds a 26-adapter catalog and
validates ordered phases, target compatibility, budgets, classes, profiles, and
payload handles. `scan_all_classes(require_llm=True)` sends its accepted recon
and insertion-point adapters to the existing scoped runner dispatch. Signal-gated
verification adapters are invoked after graph signals exist and their inert claim
counts are streamed as verification events.

Implemented: `scan_target()` accepts an optional validated tool-name selection. Preserve
the existing target-type dispatch for callers that do not provide a plan, while
the GUI passes the planner's list. Emit `plan`, `selected`, `skipped`, and
`failed` events with the tool name and reason. Then run the existing endpoint,
parameter, deterministic driver, payload-chain, and oracle code against the
same `ReachabilityGraph`, `AuditLog`, and `ScopeGuard`.

The LLM may choose ordering and compatible coverage; it never receives
`subprocess`, `RequestFirer`, `run_oracle`, or `write_finding` capabilities.
External scanner claims are advisory only. The deterministic oracle remains the
only path to `confirmed_violation` findings.

The GUI path enables the existing live-run gate per call (without mutating the
process environment), so installed compatible binaries are actually attempted;
missing binaries and signal refusals remain audited skips.

## Stage 3 — enforce LLM-only GUI operation

Implemented: the GUI scan endpoint rejects `use_llm=false`; the browser presents the
LLM provider as required configuration. A local preflight checks the selected
provider/key before creating a scan. `runtime.override()` gains a strict
`required` bit. In strict mode, profile, class, payload, planner, and report
errors propagate to the GUI instead of silently falling back. The library keeps
its compatibility mode for fixture/unit tests, but there is no manual or
deterministic GUI mode.

## Stage 4 — review and focused verification

Focused tests cover planner schema/allowlists, strict runtime behavior,
provider preflight, tool filtering, and GUI rejection of non-LLM requests. Run:

```text
uv run ruff check --fix .
uv run ruff format .
uv run mypy src
uv run pytest -q tests/recon/test_llm_runtime.py tests/recon/test_llm_client.py \
  tests/recon/test_llm_provider_integration.py tests/recon/test_api_discovery.py \
  tests/scan/test_orchestrator.py tests/gui/test_gui_slices.py
```

Do not run the full suite in this iteration. Verify the GUI against the existing
localhost fixture only after a provider/client is injected or configured. Report
missing external binaries as skipped audit events; do not silently install or
execute tools outside the target scope.

## Explicit non-goals

No Docker/container layer, CLI/TUI product surface, arbitrary shell execution,
blind “run every scanner” behavior, or claim of universal vulnerability
detection is added. “All tools” means every compatible allowlisted adapter the
LLM selects for the target and evidence, with safe skips; “all attacks” means
the existing class/oracle coverage is exercised, not that a scanner can prove
absence of unknown vulnerabilities.
