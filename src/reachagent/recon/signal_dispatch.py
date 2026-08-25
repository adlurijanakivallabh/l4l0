"""Run model-selected signal-gated adapters without granting them findings."""

from __future__ import annotations

import tempfile
from collections.abc import Callable

from reachagent.execution.audit import AuditLog
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.tools import (
    CommixRunner,
    DalfoxRunner,
    JwtToolRunner,
    NiktoRunner,
    NucleiRunner,
    SqlmapRunner,
)


def run_signal_tools(
    *,
    tool_names: tuple[str, ...],
    graph: ReachabilityGraph,
    scope: ScopeGuard,
    audit: AuditLog,
    target: str,
    emit: Callable[..., None],
    live_recon: bool,
) -> None:
    """Invoke selected adapters and emit only inert candidate metadata.

    The adapters own signal, scope, live, and binary gates. Their output remains
    a candidate until a ReachAgent oracle independently reconfirms it; this
    dispatcher has no finding or oracle capability.
    """

    if not tool_names:
        return
    runner_types = {
        cls.name: cls
        for cls in (
            CommixRunner,
            DalfoxRunner,
            JwtToolRunner,
            NiktoRunner,
            NucleiRunner,
            SqlmapRunner,
        )
    }
    with tempfile.TemporaryDirectory(prefix="reachagent-signal-") as temp_dir:
        for tool_name in tool_names:
            runner_type = runner_types.get(tool_name)
            if runner_type is None:
                emit(
                    "verification",
                    "error",
                    f"planned signal tool is not registered: {tool_name}",
                    tool=tool_name,
                )
                continue
            output_path = f"{temp_dir}/{tool_name.replace('-', '_')}"
            try:
                result = runner_type(graph=graph, scope=scope, audit=audit).run(
                    target,
                    output_path,
                    environ={"REACHAGENT_RECON_LIVE": "1"} if live_recon else None,
                )
                emit(
                    "verification",
                    "step",
                    f"{tool_name} candidate pass: {result.outcome.value}",
                    tool=tool_name,
                    outcome=result.outcome.value,
                    candidates=len(result.candidates),
                    claims_are_unverified=True,
                )
            except Exception as exc:  # noqa: BLE001 — optional tools cannot abort coverage
                emit(
                    "verification",
                    "error",
                    f"{tool_name} candidate pass failed: {type(exc).__name__}",
                    tool=tool_name,
                )
