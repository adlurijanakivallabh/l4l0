"""Scan-local LLM flags do not leak into the process environment."""

from __future__ import annotations

import pytest

from reachagent.llm.runtime import flag_enabled, llm_required, override, selected_provider


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
