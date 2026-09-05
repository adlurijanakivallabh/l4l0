"""Tests for the eval harness (recall-first scoring + calibration)."""

from __future__ import annotations

from lalo.eval import BenchmarkCase, run_benchmark, score_case
from lalo.models import Finding, Severity


def _finding(vuln_class: str, confidence: float) -> Finding:
    f = Finding.create(vuln_class, vuln_class, Severity.HIGH, "https://x/")
    f.confidence = confidence
    return f


def test_score_case_recall_precision() -> None:
    case = BenchmarkCase("c", "x", "o", expected_classes=frozenset({"sqli", "xss", "cmdi"}))
    findings = [_finding("sqli", 90), _finding("xss", 80), _finding("open_redirect", 30)]
    result = score_case(case, findings)
    assert result.recall == round(2 / 3, 3)  # found sqli+xss of 3 expected
    assert result.precision == round(2 / 3, 3)  # 2 of 3 found are real
    assert "cmdi" in result.false_negatives
    assert "open_redirect" in result.false_positives


def test_calibration_positive_when_tp_more_confident() -> None:
    case = BenchmarkCase("c", "x", "o", expected_classes=frozenset({"sqli"}))
    findings = [_finding("sqli", 90), _finding("open_redirect", 20)]
    result = score_case(case, findings)
    assert result.calibration == 70.0  # 90 (TP) - 20 (FP)


def test_run_benchmark_composite() -> None:
    cases = [
        BenchmarkCase("a", "t1", "o", frozenset({"sqli"})),
        BenchmarkCase("b", "t2", "o", frozenset({"xss"})),
    ]

    def scan_fn(case: BenchmarkCase) -> list[Finding]:
        return [_finding(next(iter(case.expected_classes)), 88)]  # perfect recall

    composite = run_benchmark(cases, scan_fn)
    assert composite.mean_recall == 1.0
    assert composite.mean_precision == 1.0
    assert len(composite.cases) == 2
