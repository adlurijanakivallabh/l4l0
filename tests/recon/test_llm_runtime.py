"""Scan-local LLM flags do not leak into the process environment."""

from __future__ import annotations

import pytest

from reachagent.llm.runtime import (
    flag_enabled,
    grunt_model,
    llm_required,
    override,
    selected_provider,
)


def test_runtime_override_isolated_and_restored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REACHAGENT_RECON_PROFILE", "1")
    monkeypatch.setenv("REACHAGENT_LLM_PROVIDER", "anthropic")
    assert flag_enabled("REACHAGENT_RECON_PROFILE")
    with override(enabled=False, provider="deepseek"):
        assert not flag_enabled("REACHAGENT_RECON_PROFILE")
        assert selected_provider() == "deepseek"
    assert flag_enabled("REACHAGENT_RECON_PROFILE")
    assert selected_provider() == "anthropic"


def test_enabled_runtime_turns_on_all_proposal_phases() -> None:
    with override(enabled=True, provider="openai", required=True):
        assert flag_enabled("REACHAGENT_RECON_PROFILE")
        assert flag_enabled("REACHAGENT_VULN_TUNING")
        assert flag_enabled("REACHAGENT_PAYLOAD_TUNING")
        assert selected_provider() == "openai"
        assert llm_required()


def test_required_bit_is_scan_local() -> None:
    assert not llm_required()
    with override(enabled=True, provider="deepseek", required=True):
        assert llm_required()
    assert not llm_required()


def test_generic_settings_select_compatible_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REACHAGENT_LLM_PROVIDER", raising=False)
    monkeypatch.setenv("REACHAGENT_LLM_API_KEY", "test-key")
    assert selected_provider() == "openai-compatible"


def test_grunt_model_empty_by_default() -> None:
    assert grunt_model() == ""


def test_grunt_model_reads_env_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REACHAGENT_LLM_GRUNT_MODEL", "cheap-model-v1")
    assert grunt_model() == "cheap-model-v1"


def test_grunt_model_env_fallback_works_even_inside_an_active_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """override() doesn't carry a grunt_model today (GUI sets it via env_overrides
    applied to os.environ for the scan's duration, same mechanism as the tuning
    flags) — grunt_model() must still see it through the RuntimeConfig fallback."""
    monkeypatch.setenv("REACHAGENT_LLM_GRUNT_MODEL", "cheap-model-v1")
    with override(enabled=True, provider="deepseek"):
        assert grunt_model() == "cheap-model-v1"


def test_grunt_model_is_scan_local_like_the_other_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("REACHAGENT_LLM_GRUNT_MODEL", raising=False)
    assert grunt_model() == ""
