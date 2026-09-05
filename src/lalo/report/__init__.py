"""Reporting — deterministic report + PoC generation + exporters.

Findings are rendered sorted by confidence with their component breakdown; the
coverage ledger's gaps appear as an explicit "Not assessed" section (never a
silent clean). CVSS is a computed nominal base (compute-don't-trust). Exporters:
Markdown / JSON / SARIF.
"""

from .cvss import compute_cvss3, nominal_cvss
from .export import to_json, to_markdown, to_sarif
from .poc import curl_poc
from .render import dedup_findings, render_markdown

__all__ = [
    "compute_cvss3",
    "curl_poc",
    "dedup_findings",
    "nominal_cvss",
    "render_markdown",
    "to_json",
    "to_markdown",
    "to_sarif",
]
