"""LLM-driven nmap depth escalation (v3 plan V2).

After nmap's first (quick) pass completes, the LLM reads the discovered
Host/Service facts (ports, banners, OS fingerprint) and decides whether a
deeper follow-up pass is warranted on THIS target — widen the port range
and/or run a category of NSE scripts — instead of depth being a single
static, operator-chosen preset. This is the autonomous half of V2; the
GUI's manual "Nmap recon depth" selector (``gui/app.py``) sets the other
half: a FLOOR the operator can require, never a ceiling that caps what the
LLM decides on top of it — see :func:`apply_floor`.

Freedom is real but bounded: the LLM picks a script category, never a raw
NSE script name or arbitrary flag string. ``nmap.py`` itself independently
re-validates the category against the same allowlist (defense in depth) —
this module's validation is not the only gate.

Blast radius: recon depth/parameter choice only. No finding written, no
oracle called, no fire against the target beyond nmap's own two invocations.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Protocol

from reachagent.recon.tools.nmap import SAFE_SCRIPT_CATEGORIES

_log = logging.getLogger(__name__)

_NO_CATEGORY = "none"


@dataclass(frozen=True)
class DepthChoice:
    """A validated nmap depth decision — widen ports and/or an NSE category."""

    widen_ports: bool
    script_category: str = _NO_CATEGORY  # one of SAFE_SCRIPT_CATEGORIES, or "none"
    rationale: str = ""

    def env(self) -> dict[str, str]:
        """The exact env vars ``NmapRunner.command`` reads for this choice."""
        env: dict[str, str] = {}
        if self.widen_ports:
            env["REACHAGENT_NMAP_WIDEN_PORTS"] = "1"
        if self.script_category in SAFE_SCRIPT_CATEGORIES:
            env["REACHAGENT_NMAP_SCRIPT_CATEGORY"] = self.script_category
        return env

    def is_deeper_than(self, other: DepthChoice) -> bool:
        """True if this choice asks for strictly more than ``other`` on either axis."""
        return (self.widen_ports and not other.widen_ports) or (
            self.script_category != _NO_CATEGORY and other.script_category == _NO_CATEGORY
        )


NO_ESCALATION = DepthChoice(widen_ports=False, script_category=_NO_CATEGORY)


def apply_floor(choice: DepthChoice, floor: DepthChoice) -> DepthChoice:
    """The operator's own manual selection is a FLOOR: the LLM's choice can only
    escalate from it, never silently drop below it (v3 V2, per operator
    feedback that an explicit setting must never become a ceiling on
    autonomous behavior).

    ``widen_ports`` is a simple bool, so "escalate" just means OR. Script
    categories are not linearly ordered (``vuln`` isn't "more" than
    ``default``), so an operator-required category is authoritative — the
    LLM may only ADD a category when the operator left this unset, never
    substitute a different one for a category the operator specifically
    asked for.
    """
    return DepthChoice(
        widen_ports=choice.widen_ports or floor.widen_ports,
        script_category=(
            floor.script_category
            if floor.script_category != _NO_CATEGORY
            else choice.script_category
        ),
        rationale=choice.rationale,
    )


class DepthEscalationClient(Protocol):
    """Thin swappable LLM boundary for the depth-escalation decision."""

    def propose(self, surface_summary: str, operator_prompt: str) -> dict[str, object]:
        """Return raw JSON with widen_ports (bool), script_category (str), rationale (str)."""
        ...


class OpenAIDepthEscalationClient:
    """OpenAI-compatible implementation."""

    def propose(self, surface_summary: str, operator_prompt: str) -> dict[str, object]:
        from reachagent.llm.client import build_openai_compatible_client, extract_json_object

        client = build_openai_compatible_client(tier="grunt")
        if client is None:
            raise RuntimeError("no LLM provider configured")
        goal = operator_prompt[:500] if operator_prompt else "general coverage"
        prompt = (
            "You are deciding whether an nmap follow-up pass is worth running against"
            " an authorized assessment target, given what a quick first pass already"
            " found. Widening the port range costs more time; running NSE scripts costs"
            " more time and a little more load on the target. Only ask for either when"
            " the discovered facts genuinely suggest it — e.g. a non-standard port, a"
            " banner that doesn't match the fingerprinted service, or an unusually"
            " small number of open ports for this kind of target."
            ' Return JSON: {"widen_ports": true/false,'
            f' "script_category": one of {sorted(SAFE_SCRIPT_CATEGORIES)} or "none",'
            ' "rationale": "one sentence"}.'
            f"\nOperator objective: {goal}\n"
            f"Discovered so far:\n{surface_summary[:2000]}"
        )
        text = client.complete(prompt, max_tokens=300)
        return extract_json_object(text)


def _validate_choice(raw: object) -> DepthChoice | None:
    if not isinstance(raw, dict):
        return None
    widen_ports = bool(raw.get("widen_ports", False))
    category = str(raw.get("script_category", "") or _NO_CATEGORY).strip().lower()
    if category not in SAFE_SCRIPT_CATEGORIES:
        category = _NO_CATEGORY
    rationale = str(raw.get("rationale", "") or "")[:200]
    return DepthChoice(widen_ports=widen_ports, script_category=category, rationale=rationale)


def propose_depth_escalation(
    hosts: object,
    *,
    floor: DepthChoice = NO_ESCALATION,
    operator_prompt: str | None = None,
    client: DepthEscalationClient | None = None,
) -> DepthChoice | None:
    """Decide whether nmap's next pass on this target should go deeper.

    Flag-gated (``REACHAGENT_RECON_DEPTH_TUNING``): off by default, matching
    every other opt-in recon-tuning layer's shape. Returns ``None`` when
    disabled, nothing usable was discovered, or the choice (after the floor
    is applied) asks for nothing beyond the floor — the caller then skips the
    second nmap pass entirely rather than re-running it for no reason.
    """
    if not os.environ.get("REACHAGENT_RECON_DEPTH_TUNING"):
        return None
    try:
        lines = [
            f"[host {host.address} tech={host.technology or 'unknown'}]"
            for _nid, host in hosts  # type: ignore[attr-defined]
        ]
        if not lines:
            return None
        tuner = client if client is not None else OpenAIDepthEscalationClient()
        raw = tuner.propose("\n".join(lines), operator_prompt or "")
        choice = _validate_choice(raw)
        if choice is None:
            _log.warning("recon-depth-tuning validation failed; falling back")
            return None
        final = apply_floor(choice, floor)
        return final if final.is_deeper_than(floor) else None
    except Exception as exc:  # noqa: BLE001 — never crash the scan
        _log.debug("recon-depth-tuning skipped (%s)", exc)
        return None
