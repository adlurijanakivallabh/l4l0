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


@dataclass(frozen=True)
class SurfacePriorityResult:
    """Validated endpoint-priority ordering plus the LLM rationale."""

    ranked_ids: tuple[str, ...]
    rationale: str


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
            )
        )
    return tuple(summaries)


class OpenAISurfaceClient:
    """OpenAI-compatible implementation of the surface-tuner protocol."""

    def propose(
        self,
        summaries: tuple[EndpointSummary, ...],
        operator_prompt: str,
        target_type: str,
    ) -> dict[str, object]:
        from reachagent.llm.client import build_openai_compatible_client

        client = build_openai_compatible_client()
        if client is None:
            raise RuntimeError("no LLM provider configured")
        lines = [
            f"- [{s.method} {s.path}]"
            + (f" params={{{s.parameters}}}" if s.parameters else "")
            + (f" tech={s.technology}" if s.technology else "")
            + (f" restricted={s.access_restricted}" if s.access_restricted else "")
            + f" id={s.node_id}"
            for s in summaries
        ]
        surface_text = "\n".join(lines)
        goal = operator_prompt[:500] if operator_prompt else "general vulnerability coverage"
        prompt = (
            "You are an authorized-security-assessment surface analyst."
            " Rank which endpoints are MOST worth testing first."
            " Consider: auth/session paths (login/token/user/admin),"
            " file/upload operations, API routes with parameters"
            " (injection points), admin/config/debug surfaces, and anything"
            " the operator objective emphasizes. Return JSON:"
            ' {"ranked_ids": ["<id1>"], "rationale": "one sentence"}.'
            " Use ONLY the exact id= values from the list.\n"
            f"Target type: {target_type}\n"
            f"Operator objective: {goal}\n"
            f"Endpoints:\n{surface_text}"
        )
        text = client.complete(prompt, max_tokens=1024)
        from reachagent.llm.client import extract_json_object

        return extract_json_object(text)


def _validate_ranking(
    raw: dict[str, object], known_ids: frozenset[str]
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
    if not valid:
        return None
    rationale = str(raw.get("rationale", ""))[:300]
    return SurfacePriorityResult(ranked_ids=tuple(valid), rationale=rationale)


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
        validated = _validate_ranking(raw, known_ids)
        if validated is not None:
            return validated
        _log.warning("surface-tuning validation failed; falling back to default order")
        return None
    except Exception as exc:  # noqa: BLE001 - must never crash the scan
        _log.debug("surface-tuning skipped (%s)", exc)
        return None
