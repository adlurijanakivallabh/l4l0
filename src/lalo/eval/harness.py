"""Benchmark cases, per-case scoring, and the recall-first composite."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from ..models import Finding

# A scan function takes a case and returns the findings it produced.
ScanFn = Callable[["BenchmarkCase"], list[Finding]]


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    target: str
    objective: str
    expected_classes: frozenset[str]  # ground-truth vuln classes present


@dataclass
class CaseResult:
    name: str
    found: frozenset[str]
    expected: frozenset[str]
    recall: float
    precision: float
    calibration: float  # mean confidence(TP) - mean confidence(FP); >0 is good
    true_positives: frozenset[str] = field(default_factory=frozenset)
    false_positives: frozenset[str] = field(default_factory=frozenset)
    false_negatives: frozenset[str] = field(default_factory=frozenset)


def _mean_conf(findings: list[Finding], classes: frozenset[str]) -> float | None:
    vals = [f.confidence for f in findings if f.vuln_class in classes and f.confidence is not None]
    return sum(vals) / len(vals) if vals else None


def score_case(case: BenchmarkCase, findings: list[Finding]) -> CaseResult:
    found = frozenset(f.vuln_class for f in findings)
    expected = case.expected_classes
    tp = found & expected
    fp = found - expected
    fn = expected - found
    recall = len(tp) / len(expected) if expected else 1.0
    precision = len(tp) / len(found) if found else 1.0
    tp_conf = _mean_conf(findings, tp)
    fp_conf = _mean_conf(findings, fp)
    calibration = (tp_conf or 0.0) - (fp_conf or 0.0)
    return CaseResult(
        name=case.name,
        found=found,
        expected=expected,
        recall=round(recall, 3),
        precision=round(precision, 3),
        calibration=round(calibration, 3),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
    )


@dataclass
class Composite:
    cases: list[CaseResult]

    @property
    def mean_recall(self) -> float:
        return round(sum(c.recall for c in self.cases) / len(self.cases), 3) if self.cases else 0.0

    @property
    def mean_precision(self) -> float:
        return (
            round(sum(c.precision for c in self.cases) / len(self.cases), 3) if self.cases else 0.0
        )

    @property
    def mean_calibration(self) -> float:
        return (
            round(sum(c.calibration for c in self.cases) / len(self.cases), 3)
            if self.cases
            else 0.0
        )


def run_benchmark(cases: Sequence[BenchmarkCase], scan_fn: ScanFn) -> Composite:
    return Composite(cases=[score_case(case, scan_fn(case)) for case in cases])
