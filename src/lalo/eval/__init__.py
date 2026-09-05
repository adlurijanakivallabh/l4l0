"""The eval harness: benchmark cases, recall-first scoring, a tracked composite score."""

from .cases import BenchmarkCase, CaseResult, run_case
from .scoring import (
    CompositeScore,
    append_composite_history,
    calibration_gap,
    load_composite_history,
    precision,
    recall,
    score_composite,
)
from .targets import CRAPI, DVWA, JUICE_SHOP, LAB_TARGETS, VAMPI

__all__ = [
    "CRAPI",
    "DVWA",
    "JUICE_SHOP",
    "LAB_TARGETS",
    "VAMPI",
    "BenchmarkCase",
    "CaseResult",
    "CompositeScore",
    "append_composite_history",
    "calibration_gap",
    "load_composite_history",
    "precision",
    "recall",
    "run_case",
    "score_composite",
]
