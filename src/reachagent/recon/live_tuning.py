"""Live-reasoning recon tuning — propose/validate/execute separation (proposal-only).

Three-layer model (see :doc:`docs/live-reasoning-design.md`):
  1. PROPOSE — Claude (Anthropic API) picks *from* a fixed allowlist of safe
     wordlists / flag combos / status-code filters given target signals.
  2. VALIDATE — fixed code checks the proposal is a member of the allowlist;
     fall back to safe default if API fails, times out, or returns outside.
  3. EXECUTE — existing ``fire_request``/``fire_browser`` → ``run_oracle`` →
     ``Validator`` confirms; live step never writes a Finding.

This module is the ONLY place a live LLM call is made for recon tuning.
It never imports ``run_oracle``/``write_finding`` and never bypasses the
six-family deterministic system. Blast radius capped at which gobuster wordlist
/ flags run with — never "this is confirmed vulnerable".
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Protocol

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowlist — safety boundary. Nothing outside can be selected, even if the
# model invents it. ponytail: one dict, not per-tool config file.
# ---------------------------------------------------------------------------

RECON_ALLOWLIST: dict[str, tuple[str, ...] | tuple[tuple[str, ...], ...]] = {
    # Safe wordlist paths — all read-only on-disk lists, never a payload string.
    # Ponytail: reuse preferred_wordlist candidates + common WP/API variants;
    # every entry is a path that exists on a typical Kali + vendored fallback.
    "wordlists": (
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
        "/usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ),
    # Safe flag combos — each tuple is an argv fragment appended after the base
    # ``gobuster dir -q -u <target> -w <wordlist>``. No shell, no extra binary.
    "flag_presets": (
        (),
        ("-t", "20"),
        ("-t", "50"),
        ("--timeout", "10s"),
        ("-t", "20", "--timeout", "10s"),
    ),
    # Safe status-code filter sets — which ``-s``-style codes to show; empty
    # means tool default. Kept as strings for direct argv use.
    "status_codes": (
        "200,204,301,302,307,401,403",
        "200,301,302",
        "200,204,301,302,307",
    ),
}

_SAFE_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
_SAFE_DEFAULT_FLAGS: tuple[str, ...] = ()
_SAFE_DEFAULT_STATUS = "200,204,301,302,307,401,403"


@dataclass(frozen=True)
class ReconTuningChoice:
    """Validated choice for gobuster tuning — every field is allowlisted."""

    wordlist_path: str
    flags: tuple[str, ...]
    filter_codes: str


@dataclass(frozen=True)
class RunConfig(ReconTuningChoice):
    """Alias kept for the prompt's ``propose_recon_tuning(...) -> RunConfig`` name."""


# ---------------------------------------------------------------------------
# Provider-neutral interface — single function, swappable client
# ---------------------------------------------------------------------------


class ReconTunerClient(Protocol):
    """Thin swappable LLM client — Anthropic now, OpenAI later without touching logic."""

    def propose(
        self, target_signals: dict[str, str], allowlist: dict[str, object]
    ) -> dict[str, str]:
        """Return a raw proposal dict with keys ``wordlist_path``, ``flags``, ``filter_codes``."""
        ...


class AnthropicTunerClient:
    """Anthropic-only implementation; OpenAI support is a different session/model."""

    def __init__(
        self, *, api_key: str | None = None, model: str = "claude-3-5-sonnet-20240620"
    ) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = model

    def propose(
        self, target_signals: dict[str, str], allowlist: dict[str, object]
    ) -> dict[str, str]:
        if not self._api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        # Lazy import so hermetic tests without anthropic installed still load.
        try:
            import anthropic  # type: ignore[import-not-found]
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"anthropic SDK not available: {exc}") from exc
        client = anthropic.Anthropic(api_key=self._api_key)
        wordlists = ", ".join(str(x) for x in allowlist.get("wordlists", ()))  # type: ignore
        flag_presets = "; ".join(
            " ".join(p) if p else "(default)"
            for p in allowlist.get("flag_presets", ())  # type: ignore
        )
        status_codes = ", ".join(str(x) for x in allowlist.get("status_codes", ()))  # type: ignore
        signals = "; ".join(f"{k}={v}" for k, v in sorted(target_signals.items()))
        prompt = (
            "You are a recon tuning proposer for gobuster dir. "
            "Given target signals, pick ONE value from each allowlist exactly — "
            "do not invent new paths or flags. Respond as JSON with keys "
            "wordlist_path, flags (space-joined), filter_codes.\n"
            f"Signals: {signals}\n"
            f"Allowlist wordlists: {wordlists}\n"
            f"Allowlist flag_presets: {flag_presets}\n"
            f"Allowlist status_codes: {status_codes}\n"
            'Example: {"wordlist_path": "/usr/share/wordlists/dirb/common.txt", '
            '"flags": "-t 20", "filter_codes": "200,204,301,302,307,401,403"}'
        )
        resp = client.messages.create(
            model=self._model,
            max_tokens=256,
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
            # Try to extract first JSON object if model wrapped it.
            import re as _re

            m = _re.search(r"\{.*\}", text, flags=_re.DOTALL)
            if not m:
                raise ValueError(f"no JSON in model response: {text[:500]!r}") from exc
            data = _json.loads(m.group(0))
        return {
            "wordlist_path": str(data.get("wordlist_path", "")),
            "flags": str(data.get("flags", "")),
            "filter_codes": str(data.get("filter_codes", "")),
        }


def _validate_choice(raw: dict[str, str]) -> ReconTuningChoice | None:
    """Return validated choice if every field is allowlisted, else None."""
    wordlist = raw.get("wordlist_path", "").strip()
    flags_raw = raw.get("flags", "").strip()
    filter_codes = raw.get("filter_codes", "").strip()
    allowed_wordlists = set(RECON_ALLOWLIST["wordlists"])
    allowed_flags = {tuple(p) for p in RECON_ALLOWLIST["flag_presets"]}
    allowed_status = set(RECON_ALLOWLIST["status_codes"])
    if wordlist not in allowed_wordlists:
        _log.warning("live tuning wordlist not allowlisted: %r", wordlist)
        return None
    flags = tuple(flags_raw.split()) if flags_raw else ()
    if flags not in allowed_flags:
        _log.warning("live tuning flags not allowlisted: %r", flags)
        return None
    if filter_codes not in allowed_status:
        _log.warning("live tuning status codes not allowlisted: %r", filter_codes)
        return None
    return ReconTuningChoice(wordlist_path=wordlist, flags=flags, filter_codes=filter_codes)


def _safe_default() -> ReconTuningChoice:
    return ReconTuningChoice(
        wordlist_path=_SAFE_DEFAULT_WORDLIST,
        flags=_SAFE_DEFAULT_FLAGS,
        filter_codes=_SAFE_DEFAULT_STATUS,
    )


def propose_recon_tuning(
    target_signals: dict[str, str],
    *,
    client: ReconTunerClient | None = None,
) -> ReconTuningChoice:
    """Propose gobuster tuning from target signals via live reasoning, allowlist-validated.

    Model-agnostic entry: ``client`` is swappable (Anthropic now, OpenAI later).
    When ``client`` is None, an :class:`AnthropicTunerClient` is built from env.
    Any failure, timeout, or non-allowlisted response falls back to safe default
    and logs why — never trusts raw API output.
    """
    try:
        tuner = client if client is not None else AnthropicTunerClient()
        raw = tuner.propose(target_signals, dict(RECON_ALLOWLIST))
        validated = _validate_choice(raw)
        if validated is not None:
            return validated
        _log.info("live tuning fallback to safe default (validation failed)")
        return _safe_default()
    except Exception as exc:  # noqa: BLE001 — live call must never crash the runner
        _log.warning("live tuning failed (%s); fallback to safe default", exc)
        return _safe_default()
