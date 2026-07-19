"""Role-bounded tool manifest (plan §13).

Tool calling is how the three agent roles (§4) are defined and bounded, not an
implementation detail underneath them. Each role's authority is enforced by
which tools it can call — implemented as separate tool subsets per role, so
"only a deterministic check can produce a finding" is enforceable in code, not
just stated as policy (§13, CLAUDE.md non-negotiables):

  * ``explorer``    — fingerprint_parameter, get_payloads, fire_request,
                      classify_response. Generates candidates, never confirms.
  * ``coordinator`` — query_graph, score_and_select, check_budget. Never fires
                      requests or runs oracles.
  * ``validator``   — run_oracle, write_finding, mark_inconclusive. The only
                      role that can produce a confirmed result or commit a
                      ``Finding`` node.

The same tool contracts are exposed as MCP tools (``reachagent.mcp``) so a human
can drive them by hand before the autonomous Coordinator exists, and nothing
changes when it takes over (§13).
"""
