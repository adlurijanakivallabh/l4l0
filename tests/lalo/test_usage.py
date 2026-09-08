"""Tests for persistent, cross-run token/cost usage stats."""

from __future__ import annotations

from pathlib import Path

import pytest

from lalo.core.errors import CostLimitExceededError
from lalo.core.model_router import CompletionResponse
from lalo.core.usage import load_usage, record_usage

_PRICING = {"claude-sonnet-5": (3.0, 15.0)}  # $3/1M input, $15/1M output


def _response(
    input_tokens: int = 100, output_tokens: int = 50, model: str = "claude-sonnet-5"
) -> CompletionResponse:
    return CompletionResponse(
        text="x",
        provider="anthropic",
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )


def test_load_usage_on_a_missing_file_is_all_zero(tmp_path: Path) -> None:
    stats = load_usage(tmp_path / "usage.json")
    assert stats.total_requests == 0
    assert stats.total_cost_usd == 0.0


def test_load_usage_on_a_corrupt_file_degrades_to_zero_never_raises(tmp_path: Path) -> None:
    path = tmp_path / "usage.json"
    path.write_text("not json at all {{{", encoding="utf-8")
    stats = load_usage(path)
    assert stats.total_requests == 0


def test_record_usage_accumulates_tokens_and_cost(tmp_path: Path) -> None:
    path = tmp_path / "usage.json"
    record_usage(_response(input_tokens=1000, output_tokens=500), path=path, pricing_table=_PRICING)
    stats = record_usage(
        _response(input_tokens=2000, output_tokens=1000), path=path, pricing_table=_PRICING
    )
    assert stats.total_requests == 2
    assert stats.total_input_tokens == 3000
    assert stats.total_output_tokens == 1500
    assert stats.total_cost_usd > 0


def test_record_usage_persists_across_separate_calls(tmp_path: Path) -> None:
    path = tmp_path / "usage.json"
    record_usage(_response(), path=path)
    stats = load_usage(path)
    assert stats.total_requests == 1


def test_record_usage_without_a_pricing_table_still_tracks_tokens(tmp_path: Path) -> None:
    path = tmp_path / "usage.json"
    stats = record_usage(_response(input_tokens=100, output_tokens=50), path=path)
    assert stats.total_input_tokens == 100
    assert stats.total_cost_usd == 0.0  # never estimated, never fabricated


def test_record_usage_tracks_a_per_provider_breakdown(tmp_path: Path) -> None:
    path = tmp_path / "usage.json"
    record_usage(_response(model="claude-sonnet-5"), path=path, pricing_table=_PRICING)
    record_usage(
        CompletionResponse(
            text="x", provider="openai", model="gpt-5.4", input_tokens=10, output_tokens=5
        ),
        path=path,
    )
    stats = load_usage(path)
    assert set(stats.by_provider) == {"anthropic", "openai"}
    assert stats.by_provider["anthropic"]["requests"] == 1
    assert stats.by_provider["openai"]["requests"] == 1


def test_record_usage_tracks_a_per_agent_breakdown(tmp_path: Path) -> None:
    path = tmp_path / "usage.json"
    record_usage(_response(input_tokens=1000, output_tokens=500), path=path, agent_id="root")
    record_usage(_response(input_tokens=200, output_tokens=100), path=path, agent_id="child-1")
    record_usage(_response(input_tokens=50, output_tokens=25), path=path, agent_id="root")
    stats = load_usage(path)
    assert set(stats.by_agent) == {"root", "child-1"}
    assert stats.by_agent["root"]["requests"] == 2
    assert stats.by_agent["root"]["input_tokens"] == 1050
    assert stats.by_agent["child-1"]["requests"] == 1


def test_record_usage_with_a_step_key_replaces_not_adds_a_second_attempt(
    tmp_path: Path,
) -> None:
    path = tmp_path / "usage.json"
    record_usage(
        _response(input_tokens=1000, output_tokens=500),
        path=path,
        pricing_table=_PRICING,
        agent_id="root",
        step_key="root:0",
    )
    # The crash-timing race this closes: the SAME step is redone (a
    # genuinely new completion, different token counts here to prove it's
    # not coincidentally identical) after a crash that landed between the
    # first attempt's usage recording and its own journal write.
    stats = record_usage(
        _response(input_tokens=200, output_tokens=100),
        path=path,
        pricing_table=_PRICING,
        agent_id="root",
        step_key="root:0",
    )
    assert stats.total_requests == 1  # not 2
    assert stats.total_input_tokens == 200  # the SECOND attempt's numbers only
    assert stats.total_output_tokens == 100
    assert stats.by_provider["anthropic"]["requests"] == 1
    assert stats.by_agent["root"]["requests"] == 1
    assert stats.by_agent["root"]["input_tokens"] == 200


def test_record_usage_with_different_step_keys_both_count(tmp_path: Path) -> None:
    path = tmp_path / "usage.json"
    record_usage(_response(input_tokens=100), path=path, step_key="root:0")
    stats = record_usage(_response(input_tokens=200), path=path, step_key="root:1")
    assert stats.total_requests == 2
    assert stats.total_input_tokens == 300


def test_record_usage_without_a_step_key_still_accumulates_normally(tmp_path: Path) -> None:
    path = tmp_path / "usage.json"
    record_usage(_response(input_tokens=100), path=path)
    stats = record_usage(_response(input_tokens=200), path=path)
    assert stats.total_requests == 2  # no step_key -> no dedup, exactly today's behavior
    assert stats.total_input_tokens == 300


def test_usage_stats_round_trips_by_step(tmp_path: Path) -> None:
    path = tmp_path / "usage.json"
    record_usage(_response(input_tokens=100), path=path, step_key="root:0")
    stats = load_usage(path)
    assert stats.by_step["root:0"]["input_tokens"] == 100


def test_record_usage_with_no_agent_id_leaves_by_agent_empty(tmp_path: Path) -> None:
    path = tmp_path / "usage.json"
    stats = record_usage(_response(), path=path)
    assert stats.by_agent == {}
    assert stats.total_requests == 1


def test_record_usage_raises_after_persisting_once_the_limit_is_crossed(tmp_path: Path) -> None:
    """The record must land BEFORE the raise - the API call already happened
    and already cost real money, so the ledger has to reflect it regardless
    of whether the caller then stops the run."""
    path = tmp_path / "usage.json"
    with pytest.raises(CostLimitExceededError):
        record_usage(
            _response(input_tokens=1_000_000, output_tokens=1_000_000),
            path=path,
            pricing_table=_PRICING,
            cost_limit_usd=1.0,
        )
    # the triggering usage was still recorded, not discarded by the raise
    stats = load_usage(path)
    assert stats.total_requests == 1
    assert stats.total_cost_usd > 1.0


def test_record_usage_under_the_limit_never_raises(tmp_path: Path) -> None:
    path = tmp_path / "usage.json"
    stats = record_usage(
        _response(input_tokens=10, output_tokens=10), path=path, cost_limit_usd=100.0
    )
    assert stats.total_requests == 1
