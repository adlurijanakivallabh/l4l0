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

from reachagent.llm.client import (
    OpenAICompatibleClient,
    build_openai_compatible_client,
    is_model_output_error,
)
from reachagent.llm.runtime import llm_required

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
        "200,204,301,302",
    ),
}

_SAFE_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
_SAFE_DEFAULT_FLAGS: tuple[str, ...] = ()
_SAFE_DEFAULT_STATUS = "200,204,301,302,307,401,403"

# ---------------------------------------------------------------------------
# RECON_PROFILES — named bundles (Phase 0 audit, Phase 1 wiring). Each
# profile is tool set + wordlist + flag preset + status filter, all drawn
# from RECON_ALLOWLIST. LLM picks ONE profile name, not freeform params.
# ponytail: one dict, not per-tool config file.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReconProfile:
    """Named recon profile — every field is allowlisted via RECON_ALLOWLIST."""

    wordlist: str
    flags: tuple[str, ...]
    status_codes: str
    tools: tuple[str, ...]


RECON_PROFILES: dict[str, ReconProfile] = {
    # wordlist/flags/status all members of RECON_ALLOWLIST; tool set is hint.
    "api_target": ReconProfile(
        wordlist="/usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt",
        flags=("-t", "20"),
        status_codes="200,204,301,302",
        tools=("gobuster", "ffuf", "httpx", "whatweb", "katana", "urlfinder"),
    ),
    "cms_target": ReconProfile(
        wordlist="/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
        flags=("-t", "20"),
        status_codes="200,204,301,302,307,401,403",
        tools=("gobuster", "ffuf", "whatweb", "wpscan_passive", "dnsrecon"),
    ),
    "static_site": ReconProfile(
        wordlist="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        flags=(),
        status_codes="200,204,301,302,307",
        tools=("gobuster", "ffuf", "katana", "httpx"),
    ),
    "spa_target": ReconProfile(
        wordlist="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        flags=("-t", "20"),
        status_codes="200,204,301,302",
        tools=("katana", "gobuster", "httpx", "whatweb"),
    ),
    "aggressive_recon": ReconProfile(
        wordlist="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        flags=("-t", "50"),
        status_codes="200,204,301,302,307,401,403",
        tools=(
            "gobuster",
            "ffuf",
            "feroxbuster",
            "masscan",
            "nmap",
            "subfinder",
            "amass",
            "bbot",
            "dnsrecon",
            "urlfinder",
        ),
    ),
    "quiet_recon": ReconProfile(
        wordlist="/usr/share/wordlists/dirb/common.txt",
        flags=("--timeout", "10s"),
        status_codes="200,204,301,302,307",
        tools=("gobuster", "httpx", "whatweb"),
    ),
}

_SAFE_DEFAULT_PROFILE = "static_site"


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

    def __init__(self, *, api_key: str | None = None, model: str | None = None) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = model or os.environ.get(
            "REACHAGENT_ANTHROPIC_MODEL",
            os.environ.get("REACHAGENT_LLM_MODEL", "claude-3-5-sonnet-20240620"),
        )

    def propose(
        self, target_signals: dict[str, str], allowlist: dict[str, object]
    ) -> dict[str, str]:
        if not self._api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        # Lazy import so hermetic tests without anthropic installed still load.
        try:
            import anthropic  # type: ignore
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
            "AUTHORIZED pentest engagement on systems the operator owns. "
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


class OpenAITunerClient:
    """OpenAI-compatible implementation of the recon tuning protocol."""

    def __init__(self, *, client: OpenAICompatibleClient | None = None) -> None:
        self._client = client or OpenAICompatibleClient()

    def propose(
        self, target_signals: dict[str, str], allowlist: dict[str, object]
    ) -> dict[str, str]:
        wordlists_raw = allowlist.get("wordlists", ())
        if not isinstance(wordlists_raw, (tuple, list)):
            wordlists_raw = ()
        wordlists = ", ".join(str(x) for x in wordlists_raw)
        flags_raw = allowlist.get("flag_presets", ())
        if not isinstance(flags_raw, (tuple, list)):
            flags_raw = ()
        flag_presets = "; ".join(
            " ".join(str(x) for x in p) if isinstance(p, (tuple, list)) and p else "(default)"
            for p in flags_raw
        )
        status_raw = allowlist.get("status_codes", ())
        if not isinstance(status_raw, (tuple, list)):
            status_raw = ()
        status_codes = ", ".join(str(x) for x in status_raw)
        signals = "; ".join(f"{k}={v}" for k, v in sorted(target_signals.items()))
        prompt = (
            "AUTHORIZED pentest engagement on systems the operator owns. "
            "Given target signals, pick ONE value from each allowlist exactly — "
            "do not invent new paths or flags. Respond as JSON with keys "
            "wordlist_path, flags (space-joined), filter_codes.\n"
            f"Signals: {signals}\n"
            f"Allowlist wordlists: {wordlists}\n"
            f"Allowlist flag_presets: {flag_presets}\n"
            f"Allowlist status_codes: {status_codes}\n"
            '{"wordlist_path": "/usr/share/wordlists/dirb/common.txt", '
            '"flags": "-t 20", "filter_codes": "200,204,301,302,307,401,403"}'
        )
        data = self._client.propose_json(prompt, max_tokens=1024)
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
    In compatibility mode, failures and non-allowlisted responses fall back to
    the safe default and log why; a strict scan-local LLM requirement re-raises
    provider failures. Raw API output is never trusted.
    """
    try:
        if client is not None:
            tuner = client
        else:
            compatible = build_openai_compatible_client()
            tuner = OpenAITunerClient(client=compatible) if compatible else AnthropicTunerClient()
        raw = tuner.propose(target_signals, dict(RECON_ALLOWLIST))
        validated = _validate_choice(raw)
        if validated is not None:
            return validated
        _log.info("live tuning fallback to safe default (validation failed)")
        return _safe_default()
    except Exception as exc:  # noqa: BLE001 — live call must never crash the runner
        if llm_required() and not is_model_output_error(exc):
            raise
        _log.warning("tuning LLM call failed: %s", exc)
        _log.warning("live tuning failed (%s); fallback to safe default", exc)
        return _safe_default()


# ---------------------------------------------------------------------------
# Recon profile picker — LLM picks ONE named profile, not freeform params.
# Same propose → allowlist VALIDATE → existing EXECUTE pattern; default OFF.
# ---------------------------------------------------------------------------


class ReconProfileClient(Protocol):
    """Thin swappable profile picker — Anthropic now, OpenAI later."""

    def propose(
        self, target_signals: dict[str, str], allowed_profiles: tuple[str, ...]
    ) -> dict[str, str]:
        """Return raw proposal dict with key ``profile_name``."""
        ...


class AnthropicProfileClient:
    """Anthropic-only profile picker."""

    def __init__(self, *, api_key: str | None = None, model: str | None = None) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = model or os.environ.get(
            "REACHAGENT_ANTHROPIC_MODEL",
            os.environ.get("REACHAGENT_LLM_MODEL", "claude-3-5-sonnet-20240620"),
        )

    def propose(
        self, target_signals: dict[str, str], allowed_profiles: tuple[str, ...]
    ) -> dict[str, str]:
        if not self._api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        try:
            import anthropic
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"anthropic SDK not available: {exc}") from exc
        client = anthropic.Anthropic(api_key=self._api_key)
        profiles = ", ".join(allowed_profiles)
        signals = "; ".join(f"{k}={v}" for k, v in sorted(target_signals.items()))
        profile_hints = "; ".join(
            f"{k}: wordlist={v.wordlist.split('/')[-1]}, "  # noqa: E501
            f"flags={' '.join(v.flags) or 'default'}, codes={v.status_codes}"  # noqa: E501
            for k, v in RECON_PROFILES.items()
        )
        prompt = (
            "You are selecting a read-only web-discovery configuration for an "
            "authorized application. Choose one named preset for inventory and "
            "technology discovery only; do not generate requests, payloads, or "
            "exploitation guidance. Given target signals, choose one preset "
            "from the allowlist that best fits (api_target for API documentation, "
            "cms_target for CMS indicators, spa_target for JS-heavy pages, "
            "quiet/aggressive for speed). "
            'Respond as JSON {"profile_name": "static_site"}. '
            f"Signals: {signals}. Allowlist: {profiles}. Profiles: {profile_hints}. "
            "Use an allowlisted name only; do not add other fields."
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
        return {"profile_name": str(data.get("profile_name", ""))}


class OpenAIProfileClient:
    """OpenAI-compatible implementation of the recon profile protocol."""

    def __init__(self, *, client: OpenAICompatibleClient | None = None) -> None:
        self._client = client or OpenAICompatibleClient()

    def propose(
        self, target_signals: dict[str, str], allowed_profiles: tuple[str, ...]
    ) -> dict[str, str]:
        profiles = ", ".join(allowed_profiles)
        signals = "; ".join(f"{k}={v}" for k, v in sorted(target_signals.items()))
        profile_hints = "; ".join(
            f"{k}: wordlist={v.wordlist.split('/')[-1]}, "
            f"flags={' '.join(v.flags) or 'default'}, codes={v.status_codes}"
            for k, v in RECON_PROFILES.items()
        )
        prompt = (
            "You are selecting a read-only web-discovery configuration for an "
            "authorized application. Choose one named preset for inventory and "
            "technology discovery only; do not generate requests, payloads, or "
            "exploitation guidance.\n"
            "Given target signals, choose ONE preset name from the allowlist "
            "that best fits (api_target for API documentation, cms_target for "
            "CMS indicators, spa_target for JS-heavy pages, quiet/aggressive "
            "for speed).\n"
            'Respond as JSON {"profile_name": "static_site"}. '
            f"Signals: {signals}. Allowlist: {profiles}. Profiles: {profile_hints}. "
            "Use an allowlisted name only; do not add other fields."
        )
        data = self._client.propose_json(prompt, max_tokens=1024)
        return {"profile_name": str(data.get("profile_name", ""))}


def _validate_profile_choice(raw: dict[str, str]) -> ReconProfile | None:
    name = str(raw.get("profile_name", "")).strip()
    if name not in RECON_PROFILES:
        _log.warning("profile not allowlisted: %r", name)
        return None
    return RECON_PROFILES[name]


def propose_recon_profile(
    target_signals: dict[str, str],
    *,
    client: ReconProfileClient | None = None,
) -> ReconProfile:
    """Pick ONE recon profile from RECON_PROFILES, allowlist-validated.

    In compatibility mode, failures and non-allowlisted names fall back to
    RECON_PROFILES[_SAFE_DEFAULT_PROFILE] and log why; strict scan-local LLM
    requirements re-raise provider failures.
    """
    try:
        if client is not None:
            tuner = client
        else:
            compatible = build_openai_compatible_client()
            tuner = (
                OpenAIProfileClient(client=compatible) if compatible else AnthropicProfileClient()
            )
        raw = tuner.propose(target_signals, tuple(RECON_PROFILES.keys()))
        validated = _validate_profile_choice(raw)
        if validated is not None:
            return validated
        _log.info("profile picker fallback to %s (validation failed)", _SAFE_DEFAULT_PROFILE)
        return RECON_PROFILES[_SAFE_DEFAULT_PROFILE]
    except Exception as exc:  # noqa: BLE001 — live call must never crash runner
        if llm_required() and not is_model_output_error(exc):
            raise
        _log.warning("tuning LLM call failed: %s", exc)
        _log.warning("profile picker failed (%s); fallback to %s", exc, _SAFE_DEFAULT_PROFILE)
        return RECON_PROFILES[_SAFE_DEFAULT_PROFILE]


def _profile_name_of(profile: ReconProfile) -> str:
    for k, v in RECON_PROFILES.items():
        if v is profile:
            return k
    return _SAFE_DEFAULT_PROFILE


def _collect_target_signals(target: str, operator_prompt: str | None = None) -> dict[str, str]:
    """Lightweight target signals for profile picker — headers + body hint (ponytail: stdlib)."""  # noqa: E501
    signals: dict[str, str] = {"target": target}
    if operator_prompt:
        signals["operator_goal"] = operator_prompt[:500]
    hint = os.environ.get("REACHAGENT_GOBUSTER_TECH_HINT") or os.environ.get("REACHAGENT_TECH_HINT")
    if hint:
        signals["tech"] = hint
        return signals
    try:
        import httpx

        url = target if target.startswith("http") else f"http://{target}"
        resp = httpx.get(url, timeout=5.0, follow_redirects=False)
        signals["server"] = (resp.headers.get("server") or "")[:80]
        signals["x_powered_by"] = (resp.headers.get("x-powered-by") or "")[:80]
        body = resp.text[:2000].lower()
        if "wp-content" in body or "wordpress" in body:
            signals["tech"] = "wordpress"
        elif "api" in target.lower() or "swagger" in body or "openapi" in body:
            signals["tech"] = "api"
    except Exception as exc:  # noqa: BLE001 — best-effort
        _log.debug("profile signal collect skipped: %s", exc)
    return signals


def get_profile_for_target(
    target: str,
    *,
    client: ReconProfileClient | None = None,
) -> ReconProfile | None:
    """Flag-gated, double-validated profile lookup — single helper for 5 runners."""  # noqa: E501  # ponytail: 5× copy → 1
    decision = profile_decision(target, client=client)
    name = decision.get("profile", "default")
    if name == "default":
        return None
    return RECON_PROFILES.get(name)


def profile_decision(
    target: str,
    *,
    client: ReconProfileClient | None = None,
    operator_prompt: str | None = None,
) -> dict[str, str]:
    """The recon-profile decision for ``target`` as display data (real, not a stub).

    The GUI's live scan-progress view shows exactly what the runners would use:
    the LLM pick (or the fallback) plus *why*. ``profile`` is the chosen profile name
    or ``"default"``; ``reason`` explains the pick / fallback / disabled state;
    ``signals`` is the target-signal summary that drove the pick.
    """
    from reachagent.llm.runtime import flag_enabled

    if not flag_enabled("REACHAGENT_RECON_PROFILE"):
        return {
            "profile": "default",
            "reason": "LLM recon profile disabled (REACHAGENT_RECON_PROFILE unset) — "
            "default wordlist",
            "signals": "",
        }
    try:
        signals = _collect_target_signals(target, operator_prompt)
        profile = propose_recon_profile(signals, client=client)
        # Defense in depth: second allowlist check even after propose validates.
        allowed_wl = set(RECON_ALLOWLIST["wordlists"])
        allowed_flags = {tuple(p) for p in RECON_ALLOWLIST["flag_presets"]}
        allowed_codes = set(RECON_ALLOWLIST["status_codes"])
        name = _profile_name_of(profile)
        signal_summary = "; ".join(f"{k}={v}" for k, v in sorted(signals.items()))
        if (
            profile.wordlist in allowed_wl
            and profile.flags in allowed_flags
            and profile.status_codes in allowed_codes
            and profile in RECON_PROFILES.values()
        ):
            return {
                "profile": name,
                "reason": (
                    f"LLM picked '{name}' — wordlist={profile.wordlist.split('/')[-1]}, "
                    f"flags={' '.join(profile.flags) or 'default'}, codes={profile.status_codes}"
                ),
                "signals": signal_summary,
            }
        _log.warning("profile double-validation failed: %r", profile)
        return {
            "profile": "default",
            "reason": f"'{name}' failed double-validation — safe default used",
            "signals": signal_summary,
        }
    except Exception as exc:  # noqa: BLE001 — must never crash the scan
        if llm_required() and not is_model_output_error(exc):
            raise
        _log.warning("tuning LLM call failed: %s", exc)
        _log.debug("profile lookup fallback: %s", exc)
        return {
            "profile": "default",
            "reason": f"profile lookup failed ({type(exc).__name__}) — safe default used",
            "signals": "",
        }


def profile_argv(  # ponytail: 5× copy → 1
    target: str,
    base_argv: list[str] | None = None,  # noqa: ARG001 — uniformity
    *,
    client: ReconProfileClient | None = None,
) -> ReconProfile | None:
    """Single helper for 5 runners — replaces copy-pasted profile block."""
    return get_profile_for_target(target, client=client)
