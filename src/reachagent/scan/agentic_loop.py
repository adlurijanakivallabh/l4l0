"""Bounded agentic re-planning between scan phases.

After each phase completes, the LLM sees what that phase found (a compact,
deterministic summary) and decides how the remaining phases should adapt:

  * SKIP — mark a not-yet-run phase as not applicable for this target
    (e.g. no auth endpoints discovered -> JWT-focused work is skipped)
  * REVISE — reorder or add target hints for the next phase
    (e.g. blind-SQLi confirmed -> revisit sibling insertion points first)
  * CONTINUE — no change needed

Blast radius: phase skipping/annotating only. The deterministic engine still
owns every decision about what fires and what becomes a finding. A skipped
phase emits an honest event so the report shows it was deliberately omitted.
The loop is bounded by MAX_REASSESSMENTS so a failing LLM cannot stall a scan.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Protocol

_log = logging.getLogger(__name__)

# Phases that can be revisited/skipped, in run order. "plan"/"report" are fixed.
REVISITABLE_PHASES: tuple[str, ...] = ("recon", "endpoints", "payloads", "verification")

MAX_REASSESSMENTS = 8  # bounded so a misbehaving LLM cannot stall a scan
_DEFAULT_ACTION = "continue"
_ACTIONS = frozenset({"continue", "skip", "revise"})


@dataclass(frozen=True)
class PhaseDecision:
    """The LLM's one-phase directive after seeing prior results."""

    action: str  # continue | skip | revise
    rationale: str = ""
    hint: str = ""  # e.g. suggested next insertion point or class focus


class LoopAdvisorClient(Protocol):
    """Thin swappable LLM boundary for the agentic loop."""

    def advise(
        self,
        completed_phase: str,
        phase_summary: str,
        remaining_phases: tuple[str, ...],
        operator_prompt: str,
    ) -> dict[str, object]:
        """Return raw JSON {action, rationale, hint}."""
        ...


def build_phase_summary(graph: object, completed_phase: str) -> str:
    """A compact, deterministic summary of what the last phase produced."""
    if completed_phase == "recon":
        hosts = len(list(graph.hosts()))  # type: ignore[attr-defined]
        endpoints = len(list(graph.endpoints()))  # type: ignore[attr-defined]
        techs = sorted(
            {
                h.technology
                for _, h in graph.hosts()  # type: ignore[attr-defined]
                if h.technology and not h.technology.startswith("wildcard")
            }
        )[:6]
        return f"hosts={hosts} endpoints={endpoints} technologies={techs}"
    if completed_phase == "endpoints":
        params_with_sinks = []
        for ep_id, ep in graph.endpoints():  # type: ignore[attr-defined]
            for _pn, p in graph.parameters_of(ep_id):  # type: ignore[attr-defined]
                if p.inferred_sink_type:
                    params_with_sinks.append(f"{ep.path}:{p.name}->{p.inferred_sink_type.value}")
        sample = "; ".join(params_with_sinks[:10])
        return f"parameters-with-sinks={len(params_with_sinks)} [{sample}]"
    # payloads/verification: count confirmed findings
    finding_nodes = list(graph.findings())  # type: ignore[attr-defined]
    classes = sorted({str(getattr(f, "vuln_class", "?")) for _, f in finding_nodes})
    return f"confirmed-findings={len(finding_nodes)} classes={classes}"


def validate_decision(raw: dict[str, object]) -> PhaseDecision | None:
    """Validate the LLM's decision; unknown actions are refused (never guessed)."""
    action = str(raw.get("action", "")).strip().lower()
    if action not in _ACTIONS:
        return None
    rationale = str(raw.get("rationale", ""))[:300]
    hint = str(raw.get("hint", ""))[:200]
    return PhaseDecision(action=action, rationale=rationale, hint=hint)


class DefaultLoopAdvisor:
    """OpenAI-compatible implementation of the loop advisor protocol."""

    def advise(
        self,
        completed_phase: str,
        phase_summary: str,
        remaining_phases: tuple[str, ...],
        operator_prompt: str,
    ) -> dict[str, object]:
        from reachagent.llm.client import build_openai_compatible_client, extract_json_object

        client = build_openai_compatible_client()
        if client is None:
            raise RuntimeError("no LLM provider configured")
        goal = operator_prompt[:400] if operator_prompt else "general coverage"
        prompt = (
            "You are the reasoning loop of an authorized security assessment."
            f" The {completed_phase} phase just completed. Summary: {phase_summary}."
            f" Remaining phases: {', '.join(remaining_phases)}."
            f" Operator objective: {goal}\\n"
            "Decide how to proceed: 'continue' (run next phase as planned),"
            " 'skip' (a remaining phase cannot apply — say why), or"
            " 'revise' (prioritize something specific in hint, e.g. revisit an"
            " insertion point because a related finding elsewhere suggests it)."
            ' Return JSON: {"action": "continue", "rationale": "...", "hint": ""}.'
        )
        text = client.complete(prompt, max_tokens=1024)
        return extract_json_object(text)


def reassess_after_phase(
    graph: object,
    completed_phase: str,
    remaining_phases: tuple[str, ...],
    *,
    operator_prompt: str | None = None,
    client: LoopAdvisorClient | None = None,
) -> PhaseDecision | None:
    """Ask the LLM how to adapt after one phase; None on flag-off/failure."""
    if not os.environ.get("REACHAGENT_AGENTIC_LOOP"):
        return None
    if not remaining_phases:
        return None
    if completed_phase not in REVISITABLE_PHASES:
        return None
    try:
        summary = build_phase_summary(graph, completed_phase)
        advisor = client if client is not None else DefaultLoopAdvisor()
        raw = advisor.advise(completed_phase, summary, remaining_phases, operator_prompt or "")
        decision = validate_decision(raw)
        if decision is not None:
            return decision
        _log.warning("agentic-loop decision validation failed; continuing as planned")
        return None
    except Exception as exc:  # noqa: BLE001 - never crash the scan
        _log.debug("agentic-loop reassessment skipped (%s)", exc)
        return None
