"""LLM-driven wordlist escalation (v3 plan V2 follow-up).

After a content-discovery tool's first pass yields zero endpoints, the LLM
reads the discovered surface (host/tech facts) and decides whether a larger
or technology-specific wordlist is warranted for a follow-up pass — instead
of wordlist depth being a single static, operator-chosen preset. This is
the autonomous half of ``recon/tools/_wordlist.py``'s own disclosed
follow-up; the GUI's manual "Content-discovery wordlist" selector sets the
other half: a FLOOR the operator can require, never a ceiling — see
:func:`apply_floor`, mirroring ``recon/depth_escalation.py``'s exact nmap
pattern.

Freedom is real but bounded: the LLM picks a size tier or a tech hint, both
re-validated against the SAME fixed, curated tables ``_wordlist.py`` already
exposes (defense in depth) — never an arbitrary path string.

Blast radius: wordlist choice only. No finding written, no oracle called, no
fire against the target beyond the content-discovery tool's own second
invocation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

from reachagent.recon.tools._wordlist import SIZE_TIERS, TECH_HINTS

_log = logging.getLogger(__name__)

_SIZE_ORDER = ("small", "medium", "large")


def _size_rank(size: str) -> int:
    """-1 for unset/no-preference; else its ordinal position in _SIZE_ORDER."""
    try:
        return _SIZE_ORDER.index(size)
    except ValueError:
        return -1


@dataclass(frozen=True)
class WordlistChoice:
    """A validated wordlist depth decision — a size tier and/or a tech hint."""

    size: str = ""  # one of SIZE_TIERS, or "" for no preference
    tech: str = ""  # one of TECH_HINTS, or "" for no preference
    rationale: str = ""

    def env(self) -> dict[str, str]:
        """The exact env vars ``preferred_wordlist`` reads for this choice."""
        env: dict[str, str] = {}
        if self.size:
            env["REACHAGENT_WORDLIST_SIZE"] = self.size
        if self.tech:
            env["REACHAGENT_WORDLIST_TECH"] = self.tech
        return env

    def is_deeper_than(self, other: WordlistChoice) -> bool:
        """True if this choice asks for strictly more than ``other`` on either axis."""
        return _size_rank(self.size) > _size_rank(other.size) or (
            bool(self.tech) and not other.tech
        )


NO_ESCALATION = WordlistChoice()


def apply_floor(choice: WordlistChoice, floor: WordlistChoice) -> WordlistChoice:
    """The operator's own manual selection is a FLOOR: the LLM's choice can only
    escalate from it, never silently drop below it (v3 V2, per operator feedback
    that an explicit setting must never become a ceiling on autonomous behavior).

    ``size`` is linearly ordered (unlike nmap's script categories), so
    "escalate" means take whichever of the two ranks higher — the same OR-like
    monotonic widening ``depth_escalation.py`` uses for ``widen_ports``. ``tech``
    is not ordered (wordpress isn't "more" than joomla), so an operator-required
    hint is authoritative — the LLM may only ADD a hint when the operator left
    it unset, never substitute a different one.
    """
    choice_rank = _size_rank(choice.size)
    floor_rank = _size_rank(floor.size)
    size = (choice.size or floor.size) if choice_rank >= floor_rank else floor.size
    tech = floor.tech if floor.tech else choice.tech
    return WordlistChoice(size=size, tech=tech, rationale=choice.rationale)


class WordlistEscalationClient(Protocol):
    """Thin swappable LLM boundary for the wordlist-escalation decision."""

    def propose(self, surface_summary: str, operator_prompt: str) -> dict[str, object]:
        """Return raw JSON with size (str), tech (str), rationale (str)."""
        ...


class OpenAIWordlistEscalationClient:
    """OpenAI-compatible implementation."""

    def propose(self, surface_summary: str, operator_prompt: str) -> dict[str, object]:
        from reachagent.llm.client import build_openai_compatible_client, extract_json_object

        client = build_openai_compatible_client(tier="grunt")
        if client is None:
            raise RuntimeError("no LLM provider configured")
        goal = operator_prompt[:2000] if operator_prompt else "general coverage"
        prompt = (
            "You are deciding whether a content-discovery follow-up pass against an"
            " authorized assessment target needs a LARGER or technology-specific"
            " wordlist, given that the first pass with today's default wordlist found"
            " zero endpoints. A larger wordlist costs more requests/time; a"
            " technology-specific one is only worth it when the discovered facts"
            " clearly point to that stack. Only ask for either when genuinely"
            " warranted, not by default."
            f' Return JSON: {{"size": one of {sorted(SIZE_TIERS)} or "",'
            f' "tech": one of {sorted(TECH_HINTS)} or "",'
            ' "rationale": "one sentence"}.'
            f"\nOperator objective: {goal}\n"
            f"Discovered so far:\n{surface_summary[:2000]}"
        )
        text = client.complete(prompt, max_tokens=300)
        return extract_json_object(text)


def _validate_choice(raw: object) -> WordlistChoice | None:
    if not isinstance(raw, dict):
        return None
    size = str(raw.get("size", "") or "").strip().lower()
    if size not in SIZE_TIERS:
        size = ""
    tech = str(raw.get("tech", "") or "").strip().lower()
    if tech not in TECH_HINTS:
        tech = ""
    rationale = str(raw.get("rationale", "") or "")[:200]
    return WordlistChoice(size=size, tech=tech, rationale=rationale)


def propose_wordlist_escalation(
    hosts: object,
    *,
    floor: WordlistChoice = NO_ESCALATION,
    operator_prompt: str | None = None,
    client: WordlistEscalationClient | None = None,
) -> WordlistChoice | None:
    """Decide whether a content-discovery tool's next pass should use a bigger list.

    No flag gate. Returns ``None`` when no provider is configured, nothing
    usable was discovered, or the choice (after the floor is applied) asks
    for nothing beyond the floor — the caller then skips the second pass
    entirely rather than re-running it for no reason.
    """
    try:
        lines = [
            f"[host {host.address} tech={host.technology or 'unknown'}]"
            for _nid, host in hosts  # type: ignore[attr-defined]
        ]
        if not lines:
            return None
        tuner = client if client is not None else OpenAIWordlistEscalationClient()
        raw = tuner.propose("\n".join(lines), operator_prompt or "")
        choice = _validate_choice(raw)
        if choice is None:
            _log.warning("wordlist-depth-tuning validation failed; falling back")
            return None
        final = apply_floor(choice, floor)
        return final if final.is_deeper_than(floor) else None
    except Exception as exc:  # noqa: BLE001 — never crash the scan
        _log.debug("wordlist-depth-tuning skipped (%s)", exc)
        return None
