"""Isolated LLM guardian advisor (Build Order 3).

A second, isolated opinion beside the deterministic boundary
(``execution.scope.ScopeGuard`` + read-only-first) — never a replacement
for it. Two properties make this safe to add without reopening anything
the deterministic gate already closes:

  * **Isolated input.** The advisor sees only a structured description of
    the proposed action — ``{tool, host, method}`` — never the target's raw
    response content. This isn't a policy choice layered on top; it's
    structural: the firer calls this advisor *before* the request is sent,
    at a point where no response from the target exists yet to poison the
    call with. A hostile target cannot inject instructions into a decision
    that happens before it ever gets to speak.
  * **Add-only, never override.** The advisor can only ADD a denial on top
    of what ``ScopeGuard`` already allowed; it is consulted strictly after
    the deterministic scope check passes, and its "allow" verdict does
    nothing on its own — the deterministic gates still all apply unchanged.
    On ANY failure (no provider, malformed response, timeout, exception)
    it fails OPEN (allow=True) — ``ScopeGuard`` is the real, load-bearing
    gate; this advisor's job is to catch an obviously-destructive-looking
    action ScopeGuard's scope check wouldn't itself have an opinion on
    (scope answers "is this host allowed", not "does this action look
    reckless"), never to throttle ordinary in-scope testing.

Same propose → validate → fail-open shape as recon.live_tuning /
recon.payload_tuning. Flag-gated on REACHAGENT_GUARDIAN_ADVISOR (part of
the auto-activated set for every GUI scan, llm.runtime.override).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class GuardianDecision:
    """One advisory verdict — never itself a scope or oracle decision."""

    allow: bool
    reason: str = ""


class GuardianClient(Protocol):
    """Thin swappable LLM boundary for the guardian advisor."""

    def propose(self, action: dict[str, str]) -> dict[str, object]:
        """Return a raw proposal dict with keys ``allow`` (bool), ``reason`` (str)."""
        ...


class OpenAIGuardianClient:
    """OpenAI-compatible implementation of the guardian protocol."""

    def __init__(self, *, client: object | None = None) -> None:
        self._client = client

    def propose(self, action: dict[str, str]) -> dict[str, object]:
        from reachagent.llm.client import build_openai_compatible_client

        client = self._client or build_openai_compatible_client()
        if client is None:
            raise RuntimeError("no LLM provider configured for guardian advisory")
        prompt = (
            "You are a second-opinion safety check for an AUTHORIZED security "
            "assessment. A deterministic allowlist has already confirmed this "
            "host is in scope — that is not your job. Your ONLY job: does this "
            "specific action, described structurally below, look like it would "
            "cause irreversible or destructive harm (e.g. mass data deletion, "
            "irreversible resource destruction) rather than ordinary security "
            "testing? Default to allow=true unless clearly destructive — you "
            "must not throttle ordinary testing.\n"
            f"Tool: {action.get('tool', '')}\n"
            f"Host: {action.get('host', '')}\n"
            f"Method: {action.get('method', '')}\n"
            'Respond as JSON {"allow": true, "reason": "short reason"}.'
        )
        return client.propose_json(prompt, max_tokens=200)


def _validate_decision(raw: object) -> GuardianDecision | None:
    if not isinstance(raw, dict) or set(raw) - {"allow", "reason"}:
        return None
    allow = raw.get("allow")
    if not isinstance(allow, bool):
        return None
    reason = raw.get("reason", "")
    if not isinstance(reason, str):
        return None
    return GuardianDecision(allow=allow, reason=reason[:300])


def advise_on_action(
    tool: str,
    host: str,
    method: str,
    *,
    client: GuardianClient | None = None,
) -> GuardianDecision:
    """Ask the isolated guardian advisor about one proposed action.

    No flag gate — attempted on every call. Fails open (allow=True) on no
    configured provider, a malformed response, or any exception — this is a
    conservative add-on check, never the load-bearing gate.
    """
    try:
        advisor = client or OpenAIGuardianClient()
        raw = advisor.propose({"tool": tool, "host": host, "method": method})
        decision = _validate_decision(raw)
        if decision is not None:
            return decision
        _log.warning("guardian advisor response malformed; failing open")
        return GuardianDecision(allow=True, reason="malformed advisor response — failed open")
    except Exception as exc:  # noqa: BLE001 — the advisor must never break firing
        _log.warning("guardian advisor call failed (%s); failing open", exc)
        return GuardianDecision(allow=True, reason=f"advisor unavailable ({type(exc).__name__})")
