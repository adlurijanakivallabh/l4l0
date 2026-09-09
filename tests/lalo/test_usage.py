"""Tests for persistent, cross-run token/cost usage stats."""

from __future__ import annotations

from pathlib import Path

import pytest

import lalo.core.usage as usage_module
from lalo.core.atomic_io import AtomicWriteError
from lalo.core.errors import CostLimitExceededError
from lalo.core.model_router import CompletionResponse
from lalo.core.usage import load_usage, record_usage, usage_accounting_status

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


def test_record_usage_survives_concurrent_calls_with_no_lost_update(tmp_path: Path) -> None:
    """Two threads calling record_usage() with the same path must never lose an
    update to a race - the real hazard this closes: spawn_agents runs several
    children as real OS threads, all sharing ScanConfig.usage_path."""
    import threading

    path = tmp_path / "usage.json"
    call_count = 50

    def _hit() -> None:
        for _ in range(call_count):
            record_usage(_response(input_tokens=1, output_tokens=1), path=path)

    threads = [threading.Thread(target=_hit) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    stats = load_usage(path)
    assert stats.total_requests == 4 * call_count
    assert stats.total_input_tokens == 4 * call_count
    assert stats.total_output_tokens == 4 * call_count


def test_usage_accounting_status_defaults_to_true() -> None:
    assert usage_accounting_status() is True


def test_a_failed_record_usage_call_flips_accounting_status_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "usage.json"
    record_usage(_response(), path=path)  # first call succeeds, establishes the file

    def _always_fails(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(usage_module, "atomic_write_verified", _always_fails)
    try:
        with pytest.raises(OSError, match="disk full"):
            record_usage(_response(), path=path)
        assert usage_accounting_status() is False
    finally:
        usage_module._accounting_complete = True  # don't leak into other tests


def test_a_byte_verify_failure_also_flips_accounting_status_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: AtomicWriteError (a byte-verify mismatch, raised BEFORE
    the swap - see core/atomic_io.py) is not an OSError, so record_usage's
    old `except OSError` missed exactly this failure mode - the write is
    genuinely lost, yet the honesty flag stayed True."""
    path = tmp_path / "usage.json"
    record_usage(_response(), path=path)

    def _always_fails_verify(*_args: object, **_kwargs: object) -> None:
        raise AtomicWriteError("simulated byte-verify mismatch")

    monkeypatch.setattr(usage_module, "atomic_write_verified", _always_fails_verify)
    try:
        with pytest.raises(AtomicWriteError, match="simulated byte-verify mismatch"):
            record_usage(_response(), path=path)
        assert usage_accounting_status() is False
    finally:
        usage_module._accounting_complete = True  # don't leak into other tests


def test_load_usage_on_a_corrupt_file_logs_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a corrupt/unreadable usage file silently reset the
    running total to zero with no log call at all - the operator's real
    cost-ceiling enforcement (record_usage's cost_limit_usd check reads
    this same total) could silently restart from zero with zero signal.
    core/logging.py's own get_logger() sets propagate=False, which defeats
    pytest's caplog (it relies on propagation to the root logger's
    handler), so this asserts on the call directly instead."""
    warnings: list[str] = []
    monkeypatch.setattr(
        usage_module._log, "warning", lambda msg, *args, **kwargs: warnings.append(msg % args)
    )
    path = tmp_path / "usage.json"
    path.write_text("not json at all {{{", encoding="utf-8")
    load_usage(path)
    assert any("unreadable/corrupt" in w for w in warnings)
