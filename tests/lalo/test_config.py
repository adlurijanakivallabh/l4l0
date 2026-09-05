"""Tests for settings loading."""

from __future__ import annotations

from lalo.core.config import load_settings


def test_load_settings_reads_provider_keys_from_env() -> None:
    settings = load_settings({"ANTHROPIC_API_KEY": "sk-ant-x", "OPENAI_API_KEY": "sk-y"})
    names = settings.configured_provider_names()
    assert "anthropic" in names
    assert "openai" in names
    # gemini has no key in this env -> not "configured"; local is always available.
    assert "gemini" not in names
    assert "local" in names


def test_default_routes_present() -> None:
    settings = load_settings({})
    # A locally-configured gateway is preferred first, with hosted providers as failover.
    assert settings.routes["reasoning"][0] == "opencodex"
    assert "anthropic" in settings.routes["reasoning"]
    assert settings.default_route  # non-empty fallback chain
