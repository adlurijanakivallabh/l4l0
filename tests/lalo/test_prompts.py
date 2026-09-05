"""Tests for per-role system prompt loading: built-ins, overrides, fallback."""

from __future__ import annotations

from pathlib import Path

import pytest

from lalo.prompts import PromptLoadError, load_prompt_template, render_prompt
from lalo.prompts.loader import PROMPTS_DIR, _validate_template


def test_every_built_in_role_loads_and_validates() -> None:
    for role in ("agent", "review"):
        assert load_prompt_template(role).strip()


def test_agent_role_declares_the_engagement_scope_placeholder() -> None:
    text = load_prompt_template("agent")
    assert "$engagement_scope" in text


def test_render_prompt_substitutes_the_engagement_scope() -> None:
    rendered = render_prompt("agent", engagement_scope="- example.com")
    assert "- example.com" in rendered
    assert "$engagement_scope" not in rendered


def test_render_prompt_for_review_needs_no_variables() -> None:
    rendered = render_prompt("review")
    assert "adversarial reviewer" in rendered


def test_load_prompt_template_unknown_role_raises() -> None:
    with pytest.raises(PromptLoadError):
        load_prompt_template("no-such-role")


def test_validate_template_rejects_a_missing_required_placeholder() -> None:
    with pytest.raises(PromptLoadError, match="missing required placeholder"):
        _validate_template("agent", "no placeholder here at all")


def test_validate_template_rejects_malformed_placeholder_syntax() -> None:
    with pytest.raises(PromptLoadError, match="malformed placeholder syntax"):
        _validate_template("review", "a dangling dollar sign: $")


def test_a_valid_override_shadows_the_built_in(tmp_path: Path) -> None:
    (tmp_path / "review.txt").write_text("A custom reviewer prompt.", encoding="utf-8")
    text = load_prompt_template("review", overrides_dir=tmp_path)
    assert text == "A custom reviewer prompt."


def test_a_malformed_override_falls_back_to_the_built_in(tmp_path: Path) -> None:
    (tmp_path / "agent.txt").write_text("missing the required placeholder", encoding="utf-8")
    text = load_prompt_template("agent", overrides_dir=tmp_path)
    assert text == load_prompt_template("agent")


def test_no_override_file_present_falls_back_to_the_built_in(tmp_path: Path) -> None:
    text = load_prompt_template("review", overrides_dir=tmp_path)
    assert text == load_prompt_template("review")


def test_built_in_content_files_actually_exist_on_disk() -> None:
    assert (PROMPTS_DIR / "agent.txt").exists()
    assert (PROMPTS_DIR / "review.txt").exists()


def test_agent_prompt_states_target_content_is_untrusted_data() -> None:
    text = load_prompt_template("agent")
    assert "never instructions you\nfollow" in text or "never instructions you follow" in text


def test_agent_prompt_states_closure_discipline_states() -> None:
    text = load_prompt_template("agent")
    for token in ("confirmed", "ruled_out", "open_proof_gap"):
        assert token in text


def test_agent_prompt_does_not_instruct_the_model_to_suppress_its_own_judgment() -> None:
    text = load_prompt_template("agent").lower()
    for banned in ("never question your authority", "refusal avoidance", "never refuse"):
        assert banned not in text
