"""Per-scan LLM settings without mutating process-global environment state."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeConfig:
    """Feature flags and provider override for one scan execution context."""

    flags: frozenset[str]
    provider: str | None = None
    required: bool = False
    grunt_model: str | None = None
    base_url: str | None = None
    api_key: str | None = None
    model: str | None = None
    api_style: str | None = None


_current: ContextVar[RuntimeConfig | None] = ContextVar("reachagent_llm_runtime", default=None)


def flag_enabled(name: str) -> bool:
    """Read a tuning flag from the active scan, falling back to the environment."""
    config = _current.get()
    if config is not None:
        return name in config.flags
    return os.environ.get(name) == "1"


def selected_provider() -> str:
    """Return the active provider name, if one was selected."""
    config = _current.get()
    if config is not None and config.provider:
        return config.provider
    selected = os.environ.get("REACHAGENT_LLM_PROVIDER", "").strip()
    if selected:
        return selected
    # A generic endpoint is an explicit provider selection even when callers
    # omit the redundant provider name. Do not infer a provider from vendor
    # keys: that can send credentials to the wrong gateway.
    if any(
        os.environ.get(name, "").strip()
        for name in (
            "REACHAGENT_LLM_API_KEY",
            "REACHAGENT_LLM_BASE_URL",
            "REACHAGENT_LLM_MODEL",
            "REACHAGENT_LLM_API_STYLE",
        )
    ):
        return "openai-compatible"
    return ""


def llm_required() -> bool:
    """Whether provider/proposal failures must abort the active scan."""
    config = _current.get()
    if config is not None:
        return config.required
    return os.environ.get("REACHAGENT_LLM_REQUIRED") == "1"


def grunt_model() -> str:
    """Per-role model tiering (v2 W6): the cheaper model for high-volume, low-stakes
    tuning calls (recon tool selection, class/surface-priority ordering, wordlist/
    payload tuning), if one is configured. Empty means "use the same model as
    everything else" — tiering is additive and optional, never required.
    """
    config = _current.get()
    if config is not None and config.grunt_model:
        return config.grunt_model
    return os.environ.get("REACHAGENT_LLM_GRUNT_MODEL", "").strip()


def provider_base_url() -> str:
    """The active scan's LLM base URL override, if one was selected (see ``override``)."""
    config = _current.get()
    if config is not None and config.base_url:
        return config.base_url
    return os.environ.get("REACHAGENT_LLM_BASE_URL", "").strip()


def provider_api_key() -> str:
    """The active scan's LLM API key override, if one was selected (see ``override``)."""
    config = _current.get()
    if config is not None and config.api_key:
        return config.api_key
    return os.environ.get("REACHAGENT_LLM_API_KEY", "").strip()


def provider_model() -> str:
    """The active scan's LLM model override, if one was selected (see ``override``)."""
    config = _current.get()
    if config is not None and config.model:
        return config.model
    return os.environ.get("REACHAGENT_LLM_MODEL", "").strip()


def provider_api_style() -> str:
    """The active scan's LLM API style override, if one was selected (see ``override``)."""
    config = _current.get()
    if config is not None and config.api_style:
        return config.api_style
    return os.environ.get("REACHAGENT_LLM_API_STYLE", "").strip()


@contextmanager
def override(
    *,
    enabled: bool,
    provider: str | None = None,
    required: bool = False,
    grunt_model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    api_style: str | None = None,
) -> Iterator[None]:
    """Apply scan-local flags AND a scan-local named-provider connection (v2 Phase 6
    Stage D fix) for the duration of a worker call.

    The provider connection fields (``base_url``/``api_key``/``model``/``api_style``)
    exist specifically so a GUI-selected named provider never needs
    ``os.environ`` mutation: a live-verification run found that two concurrent GUI
    scans sharing one process can otherwise race on the process-global environment —
    one scan's cleanup (restoring the pre-scan env, typically unset) wipes the
    variable a DIFFERENT, still-running scan's next LLM call depends on, surfacing as
    an unrelated-looking "LLM base URL is required" crash mid-scan. Each concurrent
    scan's own asyncio task gets its own isolated ``RuntimeConfig`` via this
    contextvar instead — no shared mutable state between them.
    """
    flags = (
        frozenset(
            {
                "REACHAGENT_RECON_PROFILE",
                "REACHAGENT_RECON_LIVE_TUNING",
                "REACHAGENT_GOBUSTER_LIVE_TUNING",
                "REACHAGENT_VULN_TUNING",
                "REACHAGENT_PAYLOAD_TUNING",
            }
        )
        if enabled
        else frozenset()
    )
    token: Token[RuntimeConfig | None] = _current.set(
        RuntimeConfig(
            flags,
            provider,
            required=required,
            grunt_model=grunt_model,
            base_url=base_url,
            api_key=api_key,
            model=model,
            api_style=api_style,
        )
    )
    try:
        yield
    finally:
        _current.reset(token)
