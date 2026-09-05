"""Multi-agent orchestration — spawn isolated specialists, merge by authority.

A coordinator spawns specialist sub-agents, each on its own deep-copied graph
snapshot, then merges their **authoritative findings** (from the sub-graph, by id)
back into the shared graph — never the child's prose summary. A completeness
critic turns coverage gaps into re-queue work; re-hunt spawns a focused specialist
on a confirmed lead.
"""

from .coordinator import (
    CompletionReport,
    MultiAgentCoordinator,
    SubAgentSpec,
    merge_findings,
    rehunt_spec,
)
from .critic import completeness_critic

__all__ = [
    "CompletionReport",
    "MultiAgentCoordinator",
    "SubAgentSpec",
    "completeness_critic",
    "merge_findings",
    "rehunt_spec",
]
