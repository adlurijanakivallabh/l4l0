"""LLM-driven signal-tool selection - which exploitation tools to invoke.

After recon + surface prioritization complete, the LLM reads the discovered
surface (endpoints, parameters, inferred sinks, technologies) and reasons
about WHICH signal-gated tools are worth invoking. The signal-gated base
still enforces its own gate (has_signal must return True), so the LLM's pick
is an additional reasoning filter, not a bypass of the safety boundary.

Blast radius: tool invocation ordering only. No finding written, no oracle
called by this module.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

_log = logging.getLogger(__name__)

# Signal-gated tools the LLM may select from (must match the dispatch registry).
SIGNAL_TOOL_ALLOWLIST: tuple[str, ...] = (
    "sqlmap",
    "nuclei",
    "nikto",
    "dalfox",
    "commix",
    "jwt-tool",
)

_MAX_SIGNAL_TOOLS = 6  # all six is the ceiling; never more


@dataclass(frozen=True)
class SignalToolChoice:
    """Validated subset of signal tools the LLM wants to invoke."""

    selected_tools: tuple[str, ...]
    rationale: str = ""


class SignalToolTunerClient(Protocol):
    """Thin swappable LLM boundary for signal-tool selection."""

    def propose(
        self,
        surface_summary: str,
        allowlist: tuple[str, ...],
        operator_prompt: str,
    ) -> dict[str, object]:
        """Return raw JSON with selected_tools (list) and rationale (str)."""
        ...


class OpenAISignalToolClient:
    """OpenAI-compatible implementation."""

    def propose(
        self,
        surface_summary: str,
        allowlist: tuple[str, ...],
        operator_prompt: str,
    ) -> dict[str, object]:
        from reachagent.llm.client import build_openai_compatible_client, extract_json_object

        client = build_openai_compatible_client(tier="grunt")
        if client is None:
            raise RuntimeError("no LLM provider configured")
        goal = operator_prompt[:2000] if operator_prompt else "general coverage"
        prompt = (
            "You are a security-assessment tool selector for an authorized"
            " assessment. Given the discovered surface summary, decide which"
            " verification tools to invoke. Each tool has a specific trigger:"
            " sqlmap needs a SQL-sink parameter, dalfox needs html_reflection,"
            " commix needs a shell sink, nuclei needs a tech fingerprint,"
            " nikto needs a server/service signal, jwt-tool needs auth paths."
            " Only select tools whose preconditions exist in the surface."
            " Return JSON:"
            ' {"selected_tools": ["tool1"], "rationale": "one sentence"}.'
            f"\nAllowlist: {', '.join(allowlist)}\n"
            f"Operator objective: {goal}\n"
            f"Surface:\n{surface_summary[:2000]}"
        )
        text = client.complete(prompt, max_tokens=1024)
        return extract_json_object(text)


def _validate_selection(raw: dict[str, object]) -> SignalToolChoice | None:
    """Validate the model response without allowing fields to alter execution."""
    if not isinstance(raw, dict) or set(raw) - {"selected_tools", "rationale"}:
        return None
    raw_tools = raw.get("selected_tools")
    if not isinstance(raw_tools, list) or not all(isinstance(item, str) for item in raw_tools):
        return None
    allowed = set(SIGNAL_TOOL_ALLOWLIST)
    seen: set[str] = set()
    valid: list[str] = []
    for item in raw_tools:
        name = item.strip().lower()
        if name in allowed and name not in seen:
            seen.add(name)
            valid.append(name)
        if len(valid) >= _MAX_SIGNAL_TOOLS:
            break
    if not valid:
        return None
    raw_rationale = raw.get("rationale", "")
    if not isinstance(raw_rationale, str):
        return None
    rationale = raw_rationale.strip()[:300]
    return SignalToolChoice(selected_tools=tuple(valid), rationale=rationale)


def propose_signal_tools(
    graph: object,
    *,
    operator_prompt: str | None = None,
    client: SignalToolTunerClient | None = None,
) -> SignalToolChoice | None:
    """Rank which signal-gated tools to invoke based on the discovered surface.

    No flag gate. Returns None when no provider is configured or validation
    yields nothing usable; caller falls back to default.
    """
    try:
        lines = []
        for _ep_id, ep in graph.endpoints():  # type: ignore[attr-defined]
            params = ", ".join(
                f"{p.name}({p.location})"
                + (f"->{p.inferred_sink_type.value}" if p.inferred_sink_type else "")
                for _, p in graph.parameters_of(_ep_id)  # type: ignore[attr-defined]
            )
            tech = ep.technology or ""
            line = f"[{ep.method} {ep.path}]"
            if params:
                line += f" params={{{params}}}"
            if tech:
                line += f" tech={tech}"
            lines.append(line)
        for _host_id, host in graph.hosts():  # type: ignore[attr-defined]
            if host.technology and not host.technology.startswith("wildcard"):
                lines.append(f"[host {host.address} tech={host.technology}]")

        if not lines:
            return None
        tuner = client if client is not None else OpenAISignalToolClient()
        raw = tuner.propose("\n".join(lines), SIGNAL_TOOL_ALLOWLIST, operator_prompt or "")
        validated = _validate_selection(raw)
        if validated is not None:
            return validated
        _log.warning("signal-tuning validation failed; falling back")
        return None
    except Exception as exc:  # noqa: BLE001 - never crash the scan
        _log.debug("signal-tuning skipped (%s)", exc)
        return None
