"""Live-reasoning payload choice — propose/validate/execute (proposal-only).

Third layer of docs/live-reasoning-design.md §4b: given endpoint shape +
vuln_class + the sink-matched bucket get_payloads already returned, Claude
ranks which *existing* payload_ref to try first. Dynamic allowlist is the
exact bucket set — no invented string, value in tagging + oracle wiring.

Same propose → allowlist validate → existing fire → run_oracle → Validator
pattern as recon/live_tuning.py. No new payload invented, no Finding written.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Protocol

from reachagent.llm.client import OpenAICompatibleClient, build_openai_compatible_client

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PayloadChoice:
    """Validated ordering of payload_refs — every ref is from the bucket."""

    payload_refs: tuple[str, ...]


class PayloadTunerClient(Protocol):
    """Thin swappable LLM client — Anthropic now, OpenAI later."""

    def propose(
        self,
        signals: dict[str, str],
        vuln_class: str,
        candidate_refs: list[str],
    ) -> dict[str, object]:
        """Return raw proposal dict with key ``payload_refs`` (list of strings)."""
        ...


class AnthropicPayloadClient:
    """Anthropic-only implementation."""

    def __init__(
        self, *, api_key: str | None = None, model: str = "claude-3-5-sonnet-20240620"
    ) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = model

    def propose(
        self, signals: dict[str, str], vuln_class: str, candidate_refs: list[str]
    ) -> dict[str, object]:
        if not self._api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        try:
            import anthropic  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"anthropic SDK not available: {exc}") from exc
        client = anthropic.Anthropic(api_key=self._api_key)
        sig_str = "; ".join(f"{k}={v}" for k, v in sorted(signals.items()))
        cands = ", ".join(candidate_refs[:20])
        prompt = (
            "You are a payload-choice proposer for an AUTHORIZED"
                "lab assessment. Given endpoint signals, "
            f"vuln_class={vuln_class}, and the candidate bucket, rank which "
            "payload_refs to try first for THIS target (e.g. WordPress sqli "
            "prefers WP-flavored). Respond as JSON "
            '{"payload_refs": ["ref1", "ref2"]}. '
            f"Signals: {sig_str}. Bucket: {cands}. "
            "Pick only refs FROM the bucket verbatim, no invented strings."
        )
        resp = client.messages.create(
            model=self._model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )
        text = ""
        for block in resp.content:
            if getattr(block, "type", "") == "text":
                text += getattr(block, "text", "")
        import json as _json

        try:
            data = _json.loads(text)
        except Exception as exc:
            import re as _re

            m = _re.search(r"\{.*\}", text, flags=_re.DOTALL)
            if not m:
                raise ValueError(f"no JSON in model response: {text[:500]!r}") from exc
            data = _json.loads(m.group(0))
        return {"payload_refs": data.get("payload_refs", [])}


class OpenAIPayloadClient:
    """OpenAI-compatible implementation of the payload-choice protocol."""

    def __init__(self, *, client: OpenAICompatibleClient | None = None) -> None:
        self._client = client or OpenAICompatibleClient()

    def propose(
        self, signals: dict[str, str], vuln_class: str, candidate_refs: list[str]
    ) -> dict[str, object]:
        sig_str = "; ".join(f"{k}={v}" for k, v in sorted(signals.items()))
        cands = ", ".join(candidate_refs[:20])
        prompt = (
            "You are a payload-choice proposer. Given endpoint signals, "
            f"vuln_class={vuln_class}, and the candidate bucket, rank which "
            "payload_refs to try first for THIS target (e.g. WordPress sqli "
            "prefers WP-flavored). Respond as JSON "
            '{"payload_refs": ["ref1", "ref2"]}. '
            f"Signals: {sig_str}. Bucket: {cands}. "
            "Pick only refs FROM the bucket verbatim, no invented strings."
        )
        data = self._client.propose_json(prompt, max_tokens=4096)
        return {"payload_refs": data.get("payload_refs", [])}


def _validate_choice(raw: dict[str, object], candidate_refs: list[str]) -> PayloadChoice | None:
    val = raw.get("payload_refs")
    if not isinstance(val, list):
        _log.warning("payload tuning not a list: %r", val)
        return None
    allowed = set(candidate_refs)
    cleaned: list[str] = []
    for item in val:
        if not isinstance(item, str):
            _log.warning("payload tuning entry not a string: %r", item)
            return None
        item = item.strip()
        if item not in allowed:
            _log.warning("payload tuning ref not in bucket: %r", item)
            return None
        if item not in cleaned:
            cleaned.append(item)
    if not cleaned:
        _log.warning("payload tuning empty after validation")
        return None
    return PayloadChoice(payload_refs=tuple(cleaned))


def _safe_default(candidate_refs: list[str]) -> PayloadChoice:
    # Fallback is original confidence order (first 20), never an invented ref.
    return PayloadChoice(payload_refs=tuple(candidate_refs[:20]))


def propose_payload_choice(
    endpoint_signals: dict[str, str],
    vuln_class: str,
    candidate_refs: list[str],
    *,
    client: PayloadTunerClient | None = None,
) -> PayloadChoice:
    """Propose payload ordering for a bucket, dynamic-allowlist-validated.

    Model-agnostic entry — ``client`` swappable (Anthropic now, OpenAI later).
    Any failure, timeout, or non-bucket ref falls back to original confidence
    order (first 20) and logs why — never trusts raw API output.
    """
    if not candidate_refs:
        return PayloadChoice(payload_refs=())
    try:
        if client is not None:
            tuner = client
        else:
            compatible = build_openai_compatible_client()
            tuner = (
                OpenAIPayloadClient(client=compatible) if compatible else AnthropicPayloadClient()
            )
        raw = tuner.propose(endpoint_signals, vuln_class, candidate_refs)
        validated = _validate_choice(raw, candidate_refs)
        if validated is not None:
            return validated
        _log.info("payload choice fallback to original order (validation failed)")
        return _safe_default(candidate_refs)
    except Exception as exc:  # noqa: BLE001 — live call must never crash caller
        from reachagent.llm.runtime import llm_required

        if llm_required():
            raise
        _log.warning("payload choice failed (%s); fallback to original order", exc)
        return _safe_default(candidate_refs)
