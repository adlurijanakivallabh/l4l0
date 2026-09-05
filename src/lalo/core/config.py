"""Configuration loading for L4L0.

Minimal for now (provider credentials + role→provider routing); grows per phase.
Provider API keys are read from the environment and never logged (the redaction
module guards any accidental spill).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

# Environment variable that each known provider's API key is read from.
_PROVIDER_KEY_ENV: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    # "local" needs no key.
}


@dataclass(frozen=True)
class ProviderConfig:
    """Static configuration for one LLM provider."""

    name: str
    api_key: str | None = None
    model: str | None = None
    base_url: str | None = None


@dataclass(frozen=True)
class Settings:
    """Top-level L4L0 settings (extended per phase)."""

    providers: tuple[ProviderConfig, ...] = ()
    # role -> ordered provider-name failover chain
    routes: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    default_route: tuple[str, ...] = ()

    def configured_provider_names(self) -> tuple[str, ...]:
        return tuple(p.name for p in self.providers if p.api_key or p.name == "local")


# Default routing: each role tries the strong model first, then cheaper/other
# providers, so a refusal or outage on one fails over rather than aborting.
_DEFAULT_ROUTES: dict[str, tuple[str, ...]] = {
    "reasoning": ("anthropic", "openai", "gemini"),
    "triage": ("anthropic", "openai", "gemini"),
    "report": ("anthropic", "openai", "gemini"),
}


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Build :class:`Settings` from the environment (defaults when unset)."""
    environ: Mapping[str, str] = env if env is not None else os.environ
    providers: list[ProviderConfig] = []
    for name, key_env in _PROVIDER_KEY_ENV.items():
        providers.append(ProviderConfig(name=name, api_key=environ.get(key_env)))
    providers.append(ProviderConfig(name="local", base_url=environ.get("LOCAL_LLM_BASE_URL")))
    return Settings(
        providers=tuple(providers),
        routes=dict(_DEFAULT_ROUTES),
        default_route=("anthropic", "openai", "gemini", "local"),
    )
