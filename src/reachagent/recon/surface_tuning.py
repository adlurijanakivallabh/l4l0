"""LLM-driven surface prioritization - which endpoints to attack first.

Fifth layer of the live-reasoning design: given the discovered surface
(Endpoint/Parameter/Host facts from recon), the LLM reasons about why certain
endpoints matter more than others and produces an ordered priority list.
The deterministic Coordinator still selects candidates using its existing
scoring formula - this layer only reorders the queue so high-value endpoints
are scored first when budget runs out before coverage does.

Blast radius: ordering only. No finding written, no oracle called,
no request fired by this module.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Protocol

_log = logging.getLogger(__name__)

# Maximum number of endpoint summaries sent to the LLM (context bound).
_MAX_ENDPOINTS = 40

# Maximum number of endpoint ids the proposal may return (bounded reorder).
_MAX_RANKED = 20


@dataclass(frozen=True)
class EndpointSummary:
    """One endpoint's surface facts for the LLM context."""

    node_id: str
    method: str
    path: str
    parameters: str = ""
    technology: str = ""
    access_restricted: str = ""
    content_type: str = ""
    insertion_points: str = ""
    state_changing: bool = False
    response_shape: str = ""


@dataclass(frozen=True)
class InsertionPointSummary:
    """One graph-known parameter the LLM may prioritize."""

    node_id: str
    endpoint_id: str
    name: str
    location: str
    serialization: str = ""
    required: bool = False
    example: str = ""
    sink: str = ""


@dataclass(frozen=True)
class SurfacePriorityResult:
    """Validated endpoint-priority ordering plus the LLM rationale."""

    ranked_ids: tuple[str, ...]
    rationale: str
    ranked_parameter_ids: tuple[str, ...] = ()


class SurfaceTunerClient(Protocol):
    """Thin swappable LLM boundary for surface prioritization."""

    def propose(
        self,
        summaries: tuple[EndpointSummary, ...],
        operator_prompt: str,
        target_type: str,
    ) -> dict[str, object]:
        """Return raw JSON with ranked_ids (list) and rationale (str)."""


def build_endpoint_summaries(graph: object) -> tuple[EndpointSummary, ...]:
    """Extract one summary per Endpoint node from the live graph.

    Bounded at _MAX_ENDPOINTS so a huge surface cannot flood the LLM context.
    """
    summaries: list[EndpointSummary] = []
    for ep_id, ep in graph.endpoints():  # type: ignore[attr-defined]
        if len(summaries) >= _MAX_ENDPOINTS:
            break
        params = ", ".join(
            f"{p.name}({p.location})"
            + (f"->{p.inferred_sink_type.value}" if p.inferred_sink_type else "")
            for _, p in graph.parameters_of(ep_id)  # type: ignore[attr-defined]
        )
        insertion_ids = "; ".join(
            f"{node}:{p.name}({p.location},{p.serialization or 'implicit'},required={p.required})"
            for node, p in graph.parameters_of(ep_id)  # type: ignore[attr-defined]
        )
        tech = ep.technology or ""
        if not tech:
            # Pull host-level tech when the endpoint has none.
            for _host_id, h in graph.hosts():  # type: ignore[attr-defined]
                if h.technology and not h.technology.startswith("wildcard"):
                    tech = h.technology
                    break
        summaries.append(
            EndpointSummary(
                node_id=ep_id,
                method=ep.method,
                path=ep.path[:120],
                parameters=params[:200],
                technology=tech[:80],
                access_restricted=ep.access_restricted or "",
                content_type=(ep.content_type or "")[:60],
                insertion_points=insertion_ids[:300],
                state_changing=bool(getattr(ep, "state_changing", False)),
                response_shape=(getattr(ep, "response_shape", "") or "")[:180],
            )
        )
    return tuple(summaries)


def build_insertion_summaries(graph: object) -> tuple[InsertionPointSummary, ...]:
    """Extract bounded, graph-backed insertion points for LLM ranking."""
    out: list[InsertionPointSummary] = []
    for endpoint_id, _endpoint in graph.endpoints():  # type: ignore[attr-defined]
        for param_id, param in graph.parameters_of(endpoint_id):  # type: ignore[attr-defined]
            if len(out) >= _MAX_ENDPOINTS * 5:
                return tuple(out)
            out.append(
                InsertionPointSummary(
                    node_id=param_id,
                    endpoint_id=endpoint_id,
                    name=param.name[:80],
                    location=param.location,
                    serialization=(param.serialization or "")[:80],
                    required=param.required,
                    example=(param.example or "")[:120],
                    sink=(param.inferred_sink_type.value if param.inferred_sink_type else ""),
                )
            )
    return tuple(out)


class OpenAISurfaceClient:
    """OpenAI-compatible implementation of the surface-tuner protocol."""

    def propose(
        self,
        summaries: tuple[EndpointSummary, ...],
        operator_prompt: str,
        target_type: str,
    ) -> dict[str, object]:
        from reachagent.llm.client import build_openai_compatible_client

        client = build_openai_compatible_client(tier="grunt")
        if client is None:
            raise RuntimeError("no LLM provider configured")
        lines = [
            f"- [{s.method} {s.path}]"
            + (f" params={{{s.parameters}}}" if s.parameters else "")
            + (f" tech={s.technology}" if s.technology else "")
            + (f" restricted={s.access_restricted}" if s.access_restricted else "")
            + (" state-changing" if s.state_changing else "")
            + (f" response={s.response_shape}" if s.response_shape else "")
            + (f" insertion_ids={s.insertion_points}" if s.insertion_points else "")
            + f" id={s.node_id}"
            for s in summaries
        ]
        insertion_text = "\n".join(
            f"- endpoint={s.node_id} parameter_ids={s.insertion_points} params={s.parameters}"
            for s in summaries
            if s.insertion_points
        )
        surface_text = "\n".join(lines)
        goal = operator_prompt[:2000] if operator_prompt else "general vulnerability coverage"
        prompt = (
            "You are an authorized-security-assessment surface analyst."
            " Rank which endpoints are MOST worth testing first."
            " Consider: auth/session paths (login/token/user/admin),"
            " file/upload operations, API routes with parameters"
            " (injection points), admin/config/debug surfaces, and anything"
            " the operator objective emphasizes. Return JSON:"
            ' {"ranked_ids": ["<id1>"], "ranked_parameter_ids": ["<param1>"], '
            '"rationale": "one sentence"}.'
            " Use ONLY the exact id= values from the list.\n"
            f"Target type: {target_type}\n"
            f"Operator objective: {goal}\n"
            f"Endpoints:\n{surface_text}\nInsertion points:\n{insertion_text}"
        )
        text = client.complete(prompt, max_tokens=1024)
        from reachagent.llm.client import extract_json_object

        return extract_json_object(text)


def _validate_ranking(
    raw: dict[str, object],
    known_ids: frozenset[str],
    known_parameter_ids: frozenset[str] = frozenset(),
) -> SurfacePriorityResult | None:
    """Check every ranked id exists in the graph; drop unknown ones."""
    raw_ids = raw.get("ranked_ids")
    if not isinstance(raw_ids, list):
        return None
    seen: set[str] = set()
    valid: list[str] = []
    for item in raw_ids:
        sid = str(item).strip()
        if sid in known_ids and sid not in seen:
            seen.add(sid)
            valid.append(sid)
        if len(valid) >= _MAX_RANKED:
            break
    raw_parameter_ids = raw.get("ranked_parameter_ids", [])
    parameter_ids: list[str] = []
    if isinstance(raw_parameter_ids, list):
        seen_parameters: set[str] = set()
        for item in raw_parameter_ids:
            sid = str(item).strip()
            if sid in known_parameter_ids and sid not in seen_parameters:
                seen_parameters.add(sid)
                parameter_ids.append(sid)
            if len(parameter_ids) >= _MAX_RANKED * 5:
                break
    if not valid and not parameter_ids:
        return None
    rationale = str(raw.get("rationale", ""))[:300]
    return SurfacePriorityResult(
        ranked_ids=tuple(valid),
        rationale=rationale,
        ranked_parameter_ids=tuple(parameter_ids),
    )


def propose_surface_priority(
    graph: object,
    *,
    target_type: str = "url",
    operator_prompt: str | None = None,
    client: SurfaceTunerClient | None = None,
) -> SurfacePriorityResult | None:
    """Rank discovered endpoints by attack value; None on any failure.

    Flag-gated (REACHAGENT_SURFACE_TUNING): off by default, never crashes
    the scan. Returns None when disabled or validation yields nothing usable;
    the caller falls back to the default Coordinator ordering.
    """
    if not os.environ.get("REACHAGENT_SURFACE_TUNING"):
        return None
    try:
        summaries = build_endpoint_summaries(graph)
        if not summaries:
            return None
        tuner = client if client is not None else OpenAISurfaceClient()
        raw = tuner.propose(summaries, operator_prompt or "", target_type)
        known_ids = frozenset(s.node_id for s in summaries)
        known_parameter_ids = frozenset(
            parameter.node_id for parameter in build_insertion_summaries(graph)
        )
        validated = _validate_ranking(raw, known_ids, known_parameter_ids)
        if validated is not None:
            return validated
        _log.warning("surface-tuning validation failed; falling back to default order")
        return None
    except Exception as exc:  # noqa: BLE001 - must never crash the scan
        _log.debug("surface-tuning skipped (%s)", exc)
        return None
