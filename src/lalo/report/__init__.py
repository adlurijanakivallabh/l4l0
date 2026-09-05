"""Deterministic report assembly: collect, dedupe-by-construction, sort, render."""

from .collect import SEVERITY_ORDER, FindingRecord, collect_findings, sort_findings
from .coverage import CoverageSummary, build_coverage_summary
from .markdown import render_finding_md, render_report_md, safe_fence
from .overrides import SeverityOverride, apply_overrides
from .sarif import render_sarif
from .writer import write_report

__all__ = [
    "SEVERITY_ORDER",
    "CoverageSummary",
    "FindingRecord",
    "SeverityOverride",
    "apply_overrides",
    "build_coverage_summary",
    "collect_findings",
    "render_finding_md",
    "render_report_md",
    "render_sarif",
    "safe_fence",
    "sort_findings",
    "write_report",
]
