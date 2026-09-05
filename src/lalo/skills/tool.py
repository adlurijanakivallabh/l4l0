"""The ``recall`` agent tool — retrieval over the skill library, wired into an agent's own toolset.

This is what makes the skill library the agent's *actual* methodology rather
than reference material nobody reads: every agent (root and spawned
children, per Phase 6) gets this tool, and calls it whenever it needs a
playbook — a vulnerability class to test, or a cross-cutting methodology
question (how to close a candidate, how to calibrate severity).
"""

from __future__ import annotations

from ..agent.tools import FunctionTool, ToolResult, str_arg
from .loader import Skill
from .recall import recall

# A defensive backstop, not an expected-to-trigger limit: skill bodies are
# fixed, curated, trusted content (never attacker-influenced, unlike e.g. a
# captured HTTP response), so there is no reason to truncate one that
# actually fits real methodology on one page. 6000 silently cut off 16 of
# the library's 17 real skills mid-sentence - including inside the
# Validation/False-Positive Discipline section every skill ends on - which
# defeated exactly the anti-false-positive discipline this tool exists to
# deliver. 12000 comfortably covers every skill shipped today (the longest
# is ~7600 chars) with headroom for new ones; a skill that ever needs more
# than that should be split, not silently cut.
_MAX_OBSERVATION_CHARS = 12_000


def build_recall_tool(skills: list[Skill]) -> FunctionTool:
    def _recall(args: dict[str, object]) -> ToolResult:
        query = str_arg(args, "query").strip()
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
