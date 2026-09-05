"""Tests for recall/precision/calibration scoring and the tracked composite history."""

from __future__ import annotations

from pathlib import Path

from lalo.eval.cases import BenchmarkCase, CaseResult
from lalo.eval.scoring import (
    append_composite_history,
    calibration_gap,
    load_composite_history,
    precision,
    recall,
    score_composite,
)

_CASE = BenchmarkCase(
    name="t", description="d", ground_truth_classes=frozenset({"xss", "sql-injection"})
)


def _result(found: frozenset[str], confidences: dict[str, int] | None = None) -> CaseResult:
    return CaseResult(
        case=_CASE,
        found_classes=found,
        confidence_by_class=confidences or dict.fromkeys(found, 50),
    )


def test_recall_full_match() -> None:
    result = _result(frozenset({"xss", "sql-injection"}))
    assert recall(result) == 1.0


def test_recall_partial_match() -> None:
    result = _result(frozenset({"xss"}))
    assert recall(result) == 0.5


def test_recall_no_match() -> None:
    result = _result(frozenset())
    assert recall(result) == 0.0


def test_recall_with_empty_ground_truth_is_vacuously_perfect() -> None:
    case = BenchmarkCase(name="t", description="d", ground_truth_classes=frozenset())
    result = CaseResult(case=case, found_classes=frozenset(), confidence_by_class={})
    assert recall(result) == 1.0


def test_precision_all_found_classes_correct() -> None:
    result = _result(frozenset({"xss"}))
    assert precision(result) == 1.0


def test_precision_with_a_false_positive() -> None:
    result = _result(frozenset({"xss", "ssrf"}))
    assert precision(result) == 0.5


def test_precision_with_nothing_found_is_vacuously_perfect() -> None:
    result = _result(frozenset())
    assert precision(result) == 1.0


def test_calibration_gap_none_when_no_mix_of_true_and_false_positives() -> None:
    result = _result(frozenset({"xss"}), {"xss": 80})
    assert calibration_gap([result]) is None


def test_calibration_gap_positive_when_true_positives_score_higher() -> None:
    result = _result(frozenset({"xss", "ssrf"}), {"xss": 90, "ssrf": 20})
    assert calibration_gap([result]) == 70


def test_calibration_gap_negative_when_poorly_calibrated() -> None:
    result = _result(frozenset({"xss", "ssrf"}), {"xss": 10, "ssrf": 90})
    assert calibration_gap([result]) == -80


def test_score_composite_on_no_results() -> None:
    composite = score_composite([])
    assert composite.case_count == 0
    assert composite.mean_recall == 0.0
    assert composite.calibration_gap is None


def test_score_composite_averages_across_cases() -> None:
    full = _result(frozenset({"xss", "sql-injection"}))
    half = _result(frozenset({"xss"}))
    composite = score_composite([full, half])
    assert composite.case_count == 2
    assert composite.mean_recall == 0.75


def test_append_and_load_composite_history_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "history.json"
    score = score_composite([_result(frozenset({"xss"}))])
    append_composite_history(score, path, label="run-1", recorded_at="2026-01-01")
    history = load_composite_history(path)
    assert len(history) == 1
    assert history[0]["label"] == "run-1"
    assert history[0]["recorded_at"] == "2026-01-01"
    assert history[0]["case_count"] == 1


def test_append_composite_history_never_overwrites_prior_entries(tmp_path: Path) -> None:
    path = tmp_path / "history.json"
    score = score_composite([_result(frozenset({"xss"}))])
    append_composite_history(score, path, label="run-1")
    append_composite_history(score, path, label="run-2")
    history = load_composite_history(path)
    assert [entry["label"] for entry in history] == ["run-1", "run-2"]


def test_load_composite_history_on_a_missing_file_returns_empty(tmp_path: Path) -> None:
    assert load_composite_history(tmp_path / "nonexistent.json") == []
