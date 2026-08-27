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

from reachagent.llm.client import (
    OpenAICompatibleClient,
    build_openai_compatible_client,
    is_model_output_error,
)
from reachagent.llm.runtime import llm_required

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PayloadChoice:
    """Validated ordering of payload_refs — every ref is from the bucket."""

    payload_refs: tuple[str, ...]


@dataclass(frozen=True)
class PayloadAttemptContext:
    """What happened when a payload was tried — feeds mutation reasoning."""

    tried_ref: str
    outcome: str  # "no_reflection" | "waf_blocked" | "error_response" | "timeout"
    status_code: int = 0
    detail: str = ""


class PayloadTunerClient(Protocol):
    """Thin swappable LLM client — Anthropic now, OpenAI later."""

    def propose(
        self,
        signals: dict[str, str],
        vuln_class: str,
        candidate_refs: list[str],
        prior_attempts: tuple[PayloadAttemptContext, ...] = (),
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
        self,
        signals: dict[str, str],
        vuln_class: str,
        candidate_refs: list[str],
        prior_attempts: tuple[PayloadAttemptContext, ...] = (),
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
            "You are a defensive coverage planner for an authorized application. "
            "Choose the order of existing validation-reference labels for this "
            "insertion point. Do not generate payload content, exploit steps, "
            "or new references. The labels are opaque handles selected only "
            "from the supplied bucket. Respond as JSON "
            '{"payload_refs": ["reference_from_bucket"]}. '
            f"Signals: {sig_str}. Bucket: {cands}. "
            "Return bucket labels verbatim, most relevant first."
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
        self,
        signals: dict[str, str],
        vuln_class: str,
        candidate_refs: list[str],
        prior_attempts: tuple[PayloadAttemptContext, ...] = (),
    ) -> dict[str, object]:
        sig_str = "; ".join(f"{k}={v}" for k, v in sorted(signals.items()))
        cands = ", ".join(candidate_refs[:20])
        attempts_text = ""
        if prior_attempts:
            attempt_lines = [
                f"  - {a.tried_ref}: {a.outcome} (status={a.status_code}) {a.detail}"
                for a in prior_attempts[:5]
            ]
            attempts_text = "\nPreviously tried (avoid repeating the same approach):\n" + "\n".join(
                attempt_lines
            )
        prompt = (
            "You are a defensive coverage planner. Choose the order of existing "
            "validation-reference labels for this insertion point. Never create "
            "payload content, exploit steps, or new references. If previous "
            "checks were blocked or inconclusive, prefer a different existing "
            "reference within the same category. Respond as JSON "
            '{"payload_refs": ["reference_from_bucket"]}. '
            f"Signals: {sig_str}. Bucket: {cands}. "
            f"{attempts_text}"
            "Return bucket labels verbatim, most relevant first."
        )
        data = self._client.propose_json(prompt, max_tokens=1024)
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
    prior_attempts: tuple[PayloadAttemptContext, ...] = (),
) -> PayloadChoice:
    """Propose payload ordering for a bucket, dynamic-allowlist-validated.

    Model-agnostic entry — ``client`` swappable (Anthropic now, OpenAI later).
    Any failure, timeout, or non-bucket ref falls back to original confidence
    order (first 20) and logs why — never trusts raw API output.
    """
    if not candidate_refs:
        return PayloadChoice(payload_refs=())
    try:
        tuner: PayloadTunerClient
        if client is not None:
            tuner = client
        else:
            compatible = build_openai_compatible_client()
            tuner = (
                OpenAIPayloadClient(client=compatible) if compatible else AnthropicPayloadClient()
            )  # noqa: E501 — type annotation needed for mypy
        raw = tuner.propose(endpoint_signals, vuln_class, candidate_refs, prior_attempts)
        validated = _validate_choice(raw, candidate_refs)
        if validated is not None:
            return validated
        _log.info("payload choice fallback to original order (validation failed)")
        return _safe_default(candidate_refs)
    except Exception as exc:  # noqa: BLE001 — live call must never crash caller
        if llm_required() and not is_model_output_error(exc):
            raise
        _log.warning("tuning LLM call failed: %s", exc)
        _log.warning("payload choice failed (%s); fallback to original order", exc)
        return _safe_default(candidate_refs)
