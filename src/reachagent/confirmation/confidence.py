"""LLM-confidence annotation on already-confirmed findings (Build Order 5).

The oracle stays necessary and sufficient to decide whether a ``Finding`` is
written at all — this module is called strictly AFTER ``verdict.is_violation``
is already ``True``, so it can never cause a finding to be written that
wasn't already deterministically confirmed, and it can never block one from
being written either (a failure here yields no annotation, never a raised
exception). What it adds is an ADDITIONAL signal on top of that already-
confirmed finding: an LLM's own confidence label + short rationale, recorded
in the finding's ``metadata`` dict, so a human reviewing the report gets a
second opinion alongside the deterministic proof — never a substitute for
it, and never itself capable of raising or lowering whether the finding
exists.

Same propose/validate/fail-open shape as every other live-reasoning module
this session (recon.live_tuning, recon.payload_tuning, guardian.advisor).
Flag-gated on REACHAGENT_CONFIDENCE_ANNOTATION.
"""

from __future__ import annotations

import logging
from typing import Protocol

_log = logging.getLogger(__name__)

_CONFIDENCE_LEVELS = frozenset({"high", "medium", "low"})


class ConfidenceClient(Protocol):
    """Thin swappable LLM boundary for confidence annotation."""

    def propose(self, context: dict[str, str]) -> dict[str, object]:
        """Return a raw proposal dict with keys ``confidence``, ``rationale``."""
        ...


class OpenAIConfidenceClient:
    """OpenAI-compatible implementation of the confidence protocol."""

    def __init__(self, *, client: object | None = None) -> None:
        self._client = client

    def propose(self, context: dict[str, str]) -> dict[str, object]:
        from reachagent.llm.client import build_openai_compatible_client

        client = self._client or build_openai_compatible_client()
        if client is None:
            raise RuntimeError("no LLM provider configured for confidence annotation")
        prompt = (
            "A vulnerability finding has ALREADY been deterministically confirmed "
            "by an automated oracle — your role is purely advisory annotation for "
            "a human reviewer, you cannot change whether this finding exists. "
            "Given the finding's class and the oracle's own reason string, rate "
            "your confidence that this is a real, actionable, non-noisy result: "
            "'high' for classes with a low false-positive ceiling (direct "
            "content-match/execution-confirmed classes), 'medium' for classes "
            "with some inherent ambiguity, 'low' only for classes known to have "
            "residual noise (e.g. timing-based signals under network jitter).\n"
            f"Vuln class: {context.get('vuln_class', '')}\n"
            f"Severity: {context.get('severity', '')}\n"
            f"Oracle reason: {context.get('reason', '')}\n"
            'Respond as JSON {"confidence": "high", "rationale": "short reason"}.'
        )
        return client.propose_json(prompt, max_tokens=200)


def _validate(raw: object) -> tuple[str, str] | None:
    if not isinstance(raw, dict) or set(raw) - {"confidence", "rationale"}:
        return None
    confidence = raw.get("confidence")
    if not isinstance(confidence, str) or confidence not in _CONFIDENCE_LEVELS:
        return None
    rationale = raw.get("rationale", "")
    if not isinstance(rationale, str):
        return None
    return confidence, rationale[:300]


def annotate_confidence(
    vuln_class: str,
    severity: str,
    reason: str,
    *,
    client: ConfidenceClient | None = None,
) -> dict[str, str]:
    """Return metadata fields to merge onto an already-confirmed finding.

    Returns an empty dict (no annotation, never an error) on a disabled
    flag, no configured provider, a malformed response, or any exception —
    an annotation is a nice-to-have overlay, never load-bearing.
    """
    from reachagent.llm.runtime import flag_enabled

    if not flag_enabled("REACHAGENT_CONFIDENCE_ANNOTATION"):
        return {}
    try:
        advisor = client or OpenAIConfidenceClient()
        raw = advisor.propose({"vuln_class": vuln_class, "severity": severity, "reason": reason})
        validated = _validate(raw)
        if validated is None:
            _log.warning("confidence annotation response malformed; skipping")
            return {}
        confidence, rationale = validated
        return {"llm_confidence": confidence, "llm_confidence_rationale": rationale}
    except Exception as exc:  # noqa: BLE001 — an annotation failure must never break a finding
        _log.warning("confidence annotation failed (%s); skipping", exc)
        return {}
