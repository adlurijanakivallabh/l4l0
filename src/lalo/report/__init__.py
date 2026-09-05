"""Deterministic report assembly: collect, dedupe-by-construction, sort, render."""

from .collect import SEVERITY_ORDER, FindingRecord, collect_findings, sort_findings
from .coverage import CoverageSummary, build_coverage_summary
from .overrides import SeverityOverride, apply_overrides

__all__ = [
    "SEVERITY_ORDER",
    "CoverageSummary",
    "FindingRecord",
    "SeverityOverride",
    "apply_overrides",
    "build_coverage_summary",
    "collect_findings",
    "sort_findings",
]
