"""The ``record_coverage``/``list_coverage`` self-attestation ledger.

A third coverage signal alongside the two :mod:`~lalo.report.coverage`
already distinguishes (machine-observed: a filed finding, or a
``record_safe`` confirmed-clean assertion) - for a surface where neither
applies (the class genuinely doesn't exist on this target, or a check
ran out of time before reaching a verdict), this is where an agent leaves
an honest, explicit note instead of the surface silently reading as
"never looked at all." Purely informational: nothing reads this to gate
anything, matching CLAUDE.md's own no-restrictions posture exactly.
"""

from __future__ import annotations

import uuid

from ..agent.tools import FunctionTool, ToolResult, str_arg
from ..core.redaction import redact, safe_target_url
from .model import NodeKind, ReachabilityGraph

_VALID_OUTCOMES = frozenset(
    {
        "tested-and-reported",
        "tested-and-clean",
        "actively-ruled-out",
        "not-applicable",
        "needs-follow-up",
    }
)
_MAX_ENTRIES_LISTED = 100


def build_coverage_ledger_tool(graph: ReachabilityGraph) -> FunctionTool:
    def _run(args: dict[str, object]) -> ToolResult:
        action = str_arg(args, "action", "").strip()
        if action == "record":
            target = str_arg(args, "target", "").strip()
            vuln_class = str_arg(args, "vuln_class", "").strip()
            outcome = str_arg(args, "outcome", "").strip()
            if not target or not vuln_class or not outcome:
                return ToolResult(
                    observation="error: 'target', 'vuln_class', and 'outcome' are all required",
                    ok=False,
                )
            if outcome not in _VALID_OUTCOMES:
                return ToolResult(
                    observation=f"error: outcome must be one of {sorted(_VALID_OUTCOMES)}",
                    ok=False,
                )
            target_safe = safe_target_url(target)
            notes = redact(str_arg(args, "notes", ""))
            entry_id = f"coverage-{uuid.uuid4().hex[:12]}"
            graph.add_node(
                entry_id,
                NodeKind.COVERAGE_LEDGER,
                target=target_safe,
                vuln_class=vuln_class,
                outcome=outcome,
                notes=notes,
            )
            return ToolResult(
                observation=f"recorded {entry_id}: {vuln_class} on {target_safe} - {outcome}"
            )
        if action == "list":
            outcome_filter = str_arg(args, "outcome", "").strip()
            ids = graph.nodes_of_kind(NodeKind.COVERAGE_LEDGER)
            lines = []
            for entry_id in ids:
                node = graph.node(entry_id)
                if outcome_filter and node.get("outcome") != outcome_filter:
                    continue
                lines.append(
                    f"- {node.get('vuln_class')} on {node.get('target')}: {node.get('outcome')}"
                    + (f" ({node.get('notes')})" if node.get("notes") else "")
                )
            shown = lines[:_MAX_ENTRIES_LISTED]
            header = f"{len(lines)} coverage entr{'y' if len(lines) == 1 else 'ies'}:"
            observation = "\n".join([header, *shown]) if lines else "(no coverage entries)"
            return ToolResult(observation=observation)
        return ToolResult(
            observation=f"error: unknown action {action!r} - use record|list", ok=False
        )

    return FunctionTool(
        name="coverage_ledger",
        description=(
            "Self-report what you tested and what happened, for a surface none of "
            "record_finding/record_safe already cover (the class doesn't apply here, or "
            "you ran out of time before reaching a verdict). Never a gate on anything - "
            'purely informational. args: {"action": "record"|"list", ...}. record: '
            '{"target": str, "vuln_class": str (same hyphenated-slug convention as '
            'record_finding), "outcome": "tested-and-reported"|"tested-and-clean"|'
            '"actively-ruled-out"|"not-applicable"|"needs-follow-up", "notes": str '
            '(optional)}. list: {"outcome": str (optional filter)}.'
        ),
        func=_run,
    )
