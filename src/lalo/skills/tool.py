"""The ``recall`` agent tool — retrieval over the skill library, wired into an agent's own toolset.

This is what makes the skill library the agent's *actual* methodology rather
than reference material nobody reads: every agent (root and spawned
children, per Phase 6) gets this tool, and calls it whenever it needs a
playbook — a vulnerability class to test, or a cross-cutting methodology
question (how to close a candidate, how to calibrate severity).
"""

from __future__ import annotations

from ..agent.tools import FunctionTool, ToolResult
from .loader import Skill
from .recall import recall

_MAX_OBSERVATION_CHARS = 6000


def build_recall_tool(skills: list[Skill]) -> FunctionTool:
    def _recall(args: dict[str, object]) -> ToolResult:
        query = str(args.get("query", "")).strip()
        if not query:
            return ToolResult(observation="error: 'query' is required", ok=False)
        results = recall(query, skills, top_k=3)
        if not results:
            return ToolResult(observation=f"no skill found matching {query!r}", ok=False)
        top = results[0]
        observation = f"# {top.skill.name}\n\n{top.skill.body}"
        others = [r.skill.name for r in results[1:]]
        if others:
            observation += f"\n\n(other related skills you can also recall: {', '.join(others)})"
        return ToolResult(observation=observation[:_MAX_OBSERVATION_CHARS])

    return FunctionTool(
        name="recall",
        description=(
            "Recall a methodology playbook by name or topic (e.g. 'sql injection', "
            '"closure discipline", "severity calibration"). args: {"query": str}'
        ),
        func=_recall,
    )
