"""Live-reasoning vuln-class targeting — propose/validate/execute (proposal-only).

Given an insertion point's shape (method, path, param location, inferred sink,
host tech, operator objective), the LLM proposes a RANKED LIST of which vuln
classes to try first - with reasoning about why each fits. A login form gets
sqli/nosqli before xss; a file path gets traversal before command injection;
a URL param gets ssrf before anything else.

Three-layer reuse: same propose → allowlist validate → existing
fire_request/fire_browser → run_oracle → Validator pattern as
recon/live_tuning.py. No payload invented, no Finding written, no oracle
bypass. Blast radius is the ORDER in which existing vuln classes are attempted
on each insertion point. The caller iterates the ranked list when earlier
classes fail.
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

# ---------------------------------------------------------------------------
# Allowlist — only classes with existing oracle wiring (copy of §5 matrix,
# no invented string). ponytail: one tuple, not per-endpoint config file.
# ---------------------------------------------------------------------------

VULN_CLASS_ALLOWLIST: tuple[str, ...] = (
    "sqli",
    "sqli_blind",
    "nosqli",
    "ldap_injection",
    "command_injection",
    "xss_reflected",
    "xss_stored",
    "xss_dom",
    "ssti",
    "ssrf",
    "path_traversal",
    "file_upload",
    "jwt_forgery",
    "bola",
    "bfla",
    "mass_assignment",
    "idor",
    "business_logic",
    "clickjacking",
    "cors_misconfig",
    "csrf_missing_protection",
    "graphql",
    "race",
)

_SAFE_DEFAULT_CLASSES: tuple[str, ...] = (
    "sqli",
    "xss_reflected",
    "path_traversal",
    "ssti",
    "nosqli",
    "ldap_injection",
    "command_injection",
)


@dataclass(frozen=True)
class VulnTargetChoice:
    """Validated subset of vuln classes to try first — all allowlisted."""

    vuln_classes: tuple[str, ...]


@dataclass(frozen=True)
class VulnTuningChoice(VulnTargetChoice):
    """Alias for prompt's propose_vuln_targets name."""


@dataclass(frozen=True)
class InsertionPointSignals:
    """Everything the LLM needs to reason about one insertion point."""

    method: str = "GET"
    path: str = "/"
    param_name: str = ""
    param_location: str = ""
    sink: str = ""
    host_tech: str = ""
    operator_goal: str = ""


class VulnTunerClient(Protocol):
    """Thin swappable LLM client — Anthropic now, OpenAI later."""

    def propose(self, signals: dict[str, str], allowlist: tuple[str, ...]) -> dict[str, object]:
        """Return raw proposal dict with key ``vuln_classes`` (list of strings)."""
        ...


class AnthropicVulnClient:
    """Anthropic-only implementation."""

    def __init__(
        self, *, api_key: str | None = None, model: str = "claude-3-5-sonnet-20240620"
    ) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = model

    def propose(self, signals: dict[str, str], allowlist: tuple[str, ...]) -> dict[str, object]:
        if not self._api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        try:
            import anthropic  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"anthropic SDK not available: {exc}") from exc
        client = anthropic.Anthropic(api_key=self._api_key)
        allowed = ", ".join(allowlist)
        sig_str = "; ".join(f"{k}={v}" for k, v in sorted(signals.items()))
        prompt = (
            "You are a defensive coverage planner for an authorized application. "
            "Map this insertion-point schema to a prioritized checklist of "
            "deterministic security-validation modules. Do not provide payloads, "
            "exploit steps, or attack instructions. Choose module names only "
            "from the allowlist (for example, a file field maps to file_upload; "
            "a URL field maps to ssrf). Respond as JSON "
            '{"vuln_classes": ["class_from_allowlist"]}. '
            f"Signals: {sig_str}. Allowlist: {allowed}. "
            "Pick only from the allowlist, no invented strings, most relevant first."
        )
        resp = client.messages.create(
            model=self._model,
            max_tokens=2048,
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
        return {"vuln_classes": data.get("vuln_classes", [])}


class OpenAIVulnClient:
    """OpenAI-compatible implementation of the vuln targeting protocol."""

    def __init__(self, *, client: OpenAICompatibleClient | None = None) -> None:
        self._client = client or OpenAICompatibleClient()

    def propose(self, signals: dict[str, str], allowlist: tuple[str, ...]) -> dict[str, object]:
        allowed = ", ".join(allowlist)
        sig_str = "; ".join(f"{k}={v}" for k, v in sorted(signals.items()))
        prompt = (
            "System: authorized defensive application assessment. You are "
            "choosing an ordered checklist of deterministic validation modules, "
            "not generating an attack or payload. Never output exploit steps.\n"
            "Given this insertion point's shape, rank module names FROM the "
            "allowlist by relevance: credential fields favor database/input "
            "validation; file paths favor path normalization; URL fields favor "
            "outbound-request validation; reflected content favors output-encoding "
            "validation. Respond as JSON "
            '{"vuln_classes": ["class_from_allowlist"]}. '
            f"Signals: {sig_str}. Allowlist: {allowed}. "
            "Pick only from the allowlist, no invented strings, most relevant first."
        )
        data = self._client.propose_json(prompt, max_tokens=1024)
        return {"vuln_classes": data.get("vuln_classes", [])}


def _validate_choice(raw: dict[str, object]) -> VulnTargetChoice | None:
    val = raw.get("vuln_classes")
    if not isinstance(val, list):
        _log.warning("vuln tuning not a list: %r", val)
        return None
    cleaned: list[str] = []
    allowed = set(VULN_CLASS_ALLOWLIST)
    for item in val:
        if not isinstance(item, str):
            _log.warning("vuln tuning entry not a string: %r", item)
            return None
        item = item.strip()
        if item not in allowed:
            _log.warning("vuln tuning class not allowlisted: %r", item)
            return None
        if item not in cleaned:
            cleaned.append(item)
    if not cleaned:
        _log.warning("vuln tuning empty after validation")
        return None
    return VulnTargetChoice(vuln_classes=tuple(cleaned))


def _safe_default() -> VulnTargetChoice:
    return VulnTargetChoice(vuln_classes=_SAFE_DEFAULT_CLASSES)


def propose_vuln_targets(
    endpoint_signals: dict[str, str],
    *,
    client: VulnTunerClient | None = None,
) -> VulnTargetChoice:
    """Propose vuln classes for an endpoint shape, allowlist-validated.

    Model-agnostic entry — ``client`` swappable (Anthropic now, OpenAI later).
    In compatibility mode, failures and non-allowlisted/invented strings fall
    back to the safe default and log why; strict scan-local LLM requirements
    re-raise provider failures.
    """
    try:
        if client is not None:
            tuner = client
        else:
            compatible = build_openai_compatible_client()
            tuner = OpenAIVulnClient(client=compatible) if compatible else AnthropicVulnClient()
        raw = tuner.propose(endpoint_signals, VULN_CLASS_ALLOWLIST)
        validated = _validate_choice(raw)
        if validated is not None:
            return validated
        _log.info("vuln targeting fallback to safe default (validation failed)")
        return _safe_default()
    except Exception as exc:  # noqa: BLE001 — live call must never crash caller
        if llm_required() and not is_model_output_error(exc):
            raise
        _log.warning("tuning LLM call failed: %s", exc)
        _log.warning("vuln targeting failed (%s); fallback to safe default", exc)
        return _safe_default()
