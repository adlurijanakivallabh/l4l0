"""Ties the report together and finalizes it byte-verified.

Reuses :func:`lalo.core.atomic_io.atomic_write_verified` (Phase 7) rather
than reimplementing atomic-write-then-verify — the same primitive the
reachability graph itself persists through. A reference agent's own
``atomic_write_text`` (``report/writer.py``, read in full for Phase 16a/b)
writes atomically but never reads the file back to confirm the bytes landed
intact; Phase 7's version already closes that gap, so this module has
nothing further to add there, only to reuse.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from ..core.atomic_io import atomic_write_verified
from ..graph.model import ReachabilityGraph
from ..skills.loader import Skill
from .collect import collect_findings, sort_findings
from .coverage import build_coverage_summary
from .markdown import render_report_md
from .overrides import SeverityOverride, apply_overrides
from .sarif import render_sarif

MARKDOWN_FILENAME = "report.md"
JSON_FILENAME = "report.json"
SARIF_FILENAME = "findings.sarif"


def write_report(
    run_dir: Path,
    graph: ReachabilityGraph,
    skills: list[Skill],
    *,
    overrides: list[SeverityOverride] | None = None,
    generated_at: str | None = None,
) -> dict[str, Path]:
    """Assemble every format from ``graph`` and write them, byte-verified.

    Returns the written path for each format, keyed by ``"markdown"``,
    ``"json"``, and ``"sarif"``.
    """
    # Overrides before sort, not after: sort_findings reads effective_severity
    # (display_severity if set, else cvss_severity) - sorting first would rank
    # every finding by its PRE-override severity, so an operator's "this is
    # actually critical" correction would still be ordered under an
    # unrelated higher-severity finding in the delivered report.
    records = sort_findings(apply_overrides(collect_findings(graph), overrides or []))
    coverage = build_coverage_summary(skills, records)

    markdown = render_report_md(records, coverage, generated_at=generated_at)
    json_document = {
        "generated_at": generated_at,
        "findings": [asdict(record) for record in records],
        "coverage": asdict(coverage),
    }
    sarif_document = render_sarif(records)

    paths = {
        "markdown": run_dir / MARKDOWN_FILENAME,
        "json": run_dir / JSON_FILENAME,
        "sarif": run_dir / SARIF_FILENAME,
    }
    atomic_write_verified(paths["markdown"], markdown.encode("utf-8"))
    atomic_write_verified(
        paths["json"], json.dumps(json_document, ensure_ascii=False, indent=2).encode("utf-8")
    )
    atomic_write_verified(
        paths["sarif"], json.dumps(sarif_document, ensure_ascii=False, indent=2).encode("utf-8")
    )
    return paths
