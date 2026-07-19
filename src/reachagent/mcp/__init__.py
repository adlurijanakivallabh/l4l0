"""ReachAgent's own tools exposed as an MCP server (plan §13).

Built as actual MCP tools from Phase 1, not only as internal functions the
Coordinator calls once it exists. Before the §4 scoring rule is built, the same
tools are driven by hand from Claude Desktop or Claude Code — a faster debug
loop — and nothing changes when the autonomous Coordinator takes over in Phase 5,
since it calls the identical tool contracts (§13).

Distinct from the *supporting* MCP integrations ReachAgent consumes (Playwright
MCP, Burp/Caido MCP, Neo4j MCP, §13) — those back the tools; this server
publishes them.
"""
