"""Scan-local LLM flags do not leak into the process environment."""

from __future__ import annotations

import contextvars

import pytest

from reachagent.llm.runtime import (
    flag_enabled,
    grunt_model,
    llm_required,
    override,
    provider_api_key,
    provider_api_style,
    provider_base_url,
    provider_model,
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
    """override() CAN carry an explicit grunt_model (v2 Phase 6 Stage D — routed
    through the contextvar like the other LLM connection fields now, closing a
    concurrent-scan os.environ race); when a caller doesn't pass one, grunt_model()
    still falls back to the environment through the RuntimeConfig fallback."""
    monkeypatch.setenv("REACHAGENT_LLM_GRUNT_MODEL", "cheap-model-v1")
    with override(enabled=True, provider="deepseek"):
        assert grunt_model() == "cheap-model-v1"


def test_grunt_model_is_scan_local_like_the_other_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("REACHAGENT_LLM_GRUNT_MODEL", raising=False)
    assert grunt_model() == ""


def test_provider_connection_fields_are_scan_local_and_restored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v2 Phase 6 Stage D fix: base_url/api_key/model/api_style route through the
    same contextvar as provider, not os.environ — isolated during the override and
    cleanly gone afterward (never left "stuck" at the last scan's value)."""
    for key in (
        "REACHAGENT_LLM_BASE_URL",
        "REACHAGENT_LLM_API_KEY",
        "REACHAGENT_LLM_MODEL",
        "REACHAGENT_LLM_API_STYLE",
    ):
        monkeypatch.delenv(key, raising=False)
    assert provider_base_url() == ""
    assert provider_api_key() == ""
    with override(
        enabled=True,
        provider="openai-compatible",
        base_url="https://a.test/v1",
        api_key="key-a",
        model="model-a",
        api_style="responses",
    ):
        assert provider_base_url() == "https://a.test/v1"
        assert provider_api_key() == "key-a"
        assert provider_model() == "model-a"
        assert provider_api_style() == "responses"
    assert provider_base_url() == ""
    assert provider_api_key() == ""


def test_a_finishing_concurrent_scan_context_never_corrupts_a_still_running_ones_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The actual live-verification bug this closes: two GUI scans previously shared
    one process's os.environ for their named-provider connection — scan B finishing
    (restoring the pre-scan, typically-unset env) wiped the base_url/api_key scan A
    was still mid-flight relying on, surfacing as an unrelated "LLM base URL is
    required" crash. asyncio.create_task forks each GUI scan's OWN
    contextvars.Context from the same clean caller context (the request handler,
    which has no override active) — never from each other — so two independent
    Context objects, not a parent/child nesting, is the accurate model here."""
    monkeypatch.delenv("REACHAGENT_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("REACHAGENT_LLM_API_KEY", raising=False)

    # Two independent forks of the same clean baseline, exactly like two
    # asyncio.create_task calls from the same (override-free) request handler.
    ctx_a = contextvars.copy_context()
    ctx_b = contextvars.copy_context()

    cm_a = override(
        enabled=True, provider="openai-compatible", base_url="https://a.test", api_key="key-a"
    )
    ctx_a.run(cm_a.__enter__)

    def run_scan_b_fully() -> tuple[str, str]:
        with override(
            enabled=True, provider="openai-compatible", base_url="https://b.test", api_key="key-b"
        ):
            during = (provider_base_url(), provider_api_key())
        after = (provider_base_url(), provider_api_key())
        return during, after

    b_during, b_after = ctx_b.run(run_scan_b_fully)
    assert b_during == ("https://b.test", "key-b")
    assert b_after == ("", "")  # B's own context correctly cleaned up after itself

    # Scan A is still "mid-flight" in its own context — B finishing must not affect it.
    a_after_b_finished = ctx_a.run(lambda: (provider_base_url(), provider_api_key()))
    assert a_after_b_finished == ("https://a.test", "key-a")
    ctx_a.run(lambda: cm_a.__exit__(None, None, None))
