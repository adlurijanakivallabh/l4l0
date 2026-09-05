"""Tests for the curated-provider config table + generic fallback + model spec."""

from __future__ import annotations

from lalo.core.config import CURATED_PROVIDERS, ModelSpec, load_settings, parse_model_spec


def test_no_env_resolves_nothing() -> None:
    settings = load_settings({})
    assert settings.resolved == ()
    assert settings.failover_order == ()


def test_resolves_only_configured_providers_in_preference_order() -> None:
    settings = load_settings({"ANTHROPIC_API_KEY": "sk-ant-x", "OPENAI_API_KEY": "sk-y"})
    ids = [p.id for p in settings.resolved]
    assert ids == ["anthropic", "openai"]  # curated order preserved, opencodex absent
    assert settings.get("anthropic") is not None
    assert settings.get("gemini") is None


def test_generic_custom_provider_needs_both_key_and_base_url() -> None:
    only_key = load_settings({"LALO_CUSTOM_API_KEY": "k"})
    assert only_key.get("custom") is None  # missing LALO_CUSTOM_BASE_URL
    both = load_settings({"LALO_CUSTOM_API_KEY": "k", "LALO_CUSTOM_BASE_URL": "http://x"})
    assert both.get("custom") is not None
    assert both.get("custom").base_url == "http://x"  # type: ignore[union-attr]


def test_missing_credential_hints_lists_unconfigured_providers() -> None:
    settings = load_settings({"ANTHROPIC_API_KEY": "sk-ant-x"})
    hints = settings.missing_credential_hints()
    assert "anthropic" not in hints
    assert hints["opencodex"] == "OPENCODEX_API_KEY"


def test_parse_model_spec_splits_on_first_colon_only() -> None:
    parsed = parse_model_spec("opencodex:some:weird:model-id")
    assert isinstance(parsed, ModelSpec)
    assert parsed.provider_id == "opencodex"
    assert parsed.model == "some:weird:model-id"


def test_parse_model_spec_malformed_returns_error_string() -> None:
    assert isinstance(parse_model_spec("no-colon-here"), str)
    assert isinstance(parse_model_spec(":missing-provider"), str)


def test_lalo_model_pins_provider_to_front_with_override_model() -> None:
    env = {
        "ANTHROPIC_API_KEY": "sk-ant-x",
        "OPENCODEX_API_KEY": "ocx-x",
        "LALO_MODEL": "anthropic:claude-opus-5",
    }
    settings = load_settings(env)
    assert settings.failover_order[0] == "anthropic"
    assert settings.get("anthropic").model == "claude-opus-5"  # type: ignore[union-attr]
    # opencodex still present later in the chain (failover still works).
    assert "opencodex" in settings.failover_order


def test_lalo_model_ignored_if_provider_not_configured() -> None:
    settings = load_settings({"ANTHROPIC_API_KEY": "sk-ant-x", "LALO_MODEL": "openai:gpt-9"})
    assert settings.failover_order[0] == "anthropic"  # openai has no credential -> not forced


def test_every_curated_provider_has_a_non_empty_hint() -> None:
    for spec in CURATED_PROVIDERS:
        assert spec.credential_hint
