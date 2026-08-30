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
    SignalGatedResult,
    SqlmapRunner,
)
from reachagent.tools.candidate import Candidate


def run_signal_tools(
    *,
    tool_names: tuple[str, ...],
    graph: ReachabilityGraph,
    scope: ScopeGuard,
    audit: AuditLog,
    target: str,
    emit: Callable[..., None],
    live_recon: bool,
    reconfirm: Callable[[Candidate], object] | None = None,
) -> tuple[SignalGatedResult, ...]:
    """Invoke selected adapters and emit only inert candidate metadata.

    The adapters own signal, scope, live, and binary gates. Their output remains
    a candidate until a ReachAgent oracle independently reconfirms it; this
    dispatcher has no finding or oracle capability. If ``reconfirm`` is supplied,
    each normalized candidate is handed to that injected Validator-side callback;
    otherwise an explicit ``reconfirmation_required`` event is emitted.
    """

    if not tool_names:
        return ()
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
    results: list[SignalGatedResult] = []
    with tempfile.TemporaryDirectory(prefix="reachagent-signal-") as temp_dir:
        for tool_name in tool_names:
            if not isinstance(tool_name, str):
                emit("verification", "error", "planned signal tool name is invalid")
                continue
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
                    environ={"REACHAGENT_RECON_LIVE": "1"} if live_recon else {},
                )
                results.append(result)
                if result.candidates:
                    if reconfirm is None:
                        emit(
                            "verification",
                            "step",
                            f"{tool_name} claims require independent reconfirmation",
                            tool=tool_name,
                            reconfirmation_required=True,
                            candidate_count=len(result.candidates),
                        )
                    else:
                        for candidate in result.candidates:
                            try:
                                reconfirm(candidate)
                            except Exception as exc:  # noqa: BLE001 — one claim cannot abort others
                                emit(
                                    "verification",
                                    "error",
                                    f"{tool_name} candidate reconfirmation failed: "
                                    f"{type(exc).__name__}",
                                    tool=tool_name,
                                )
                candidate_preview = [
                    {
                        "endpoint": candidate.endpoint_node,
                        "parameter": candidate.param_node,
                        "vulnerability_class": candidate.vuln_class,
                        "oracle": candidate.suggested_oracle.value,
                        "notes": list(candidate.notes[:2]),
                    }
                    for candidate in result.candidates[:20]
                ]
                emit(
                    "verification",
                    "step",
                    f"{tool_name} candidate pass: {result.outcome.value}",
                    tool=tool_name,
                    outcome=result.outcome.value,
                    candidates=len(result.candidates),
                    candidate_preview=candidate_preview,
                    metadata=result.metadata.as_dict(),
                    claims_are_unverified=True,
                )
            except Exception as exc:  # noqa: BLE001 — optional tools cannot abort coverage
                emit(
                    "verification",
                    "error",
                    f"{tool_name} candidate pass failed: {type(exc).__name__}",
                    tool=tool_name,
                )
    return tuple(results)
