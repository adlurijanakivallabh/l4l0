"""Eval harness — per-target scoring + a recall-first composite.

Recall is primary (nothing is gated on precision anymore), with confidence
calibration as a secondary metric: real findings should score higher than false
positives. Cases carry ground-truth vuln classes; a scan function returns
findings; the harness computes recall/precision/calibration per case + composite.
"""

from .harness import (
    BenchmarkCase,
    CaseResult,
    Composite,
    run_benchmark,
    score_case,
)

__all__ = ["BenchmarkCase", "CaseResult", "Composite", "run_benchmark", "score_case"]
