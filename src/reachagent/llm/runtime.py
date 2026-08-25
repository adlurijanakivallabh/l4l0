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


@contextmanager
def override(
    *, enabled: bool, provider: str | None = None, required: bool = False
) -> Iterator[None]:
    """Apply scan-local flags for the duration of a worker call."""
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
        RuntimeConfig(flags, provider, required=required)
    )
    try:
        yield
    finally:
        _current.reset(token)
