"""MCP server entry point (plan §13).

Publishes the role-bounded tool manifest (``reachagent.tools``) as MCP tools so a
human can drive them by hand via Claude Desktop/Code during Phase 1, ahead of
the autonomous Coordinator (§13, §15). Role boundaries are preserved when
registering: the Explorer subset never exposes ``write_finding`` (CLAUDE.md
non-negotiable). Phase 1 scaffolding — tool registration not wired yet (§15).
"""

from __future__ import annotations


def main() -> None:
    """Console entry point (``reachagent-mcp``). Tool registration lands in Phase 1 (§15)."""
    raise NotImplementedError
