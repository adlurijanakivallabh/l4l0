"""Ties the report together and finalizes it byte-verified.

Reuses :func:`lalo.core.atomic_io.atomic_write_verified` (Phase 7) rather
than reimplementing atomic-write-then-verify — the same primitive the
reachability graph itself persists through. A reference agent's own
``atomic_write_text`` (``report/writer.py``, read in full for Phase 16a/b)
writes atomically but never reads the file back to confirm the bytes landed
intact; Phase 7's version already closes that gap, so this module has
nothing further to add there, only to reuse.

A second reference's own finalization design is more rigorous than this
module in one specific dimension worth naming, not silently matching: its
``exact-output-commit.ts``/``report-finalization.ts`` (read via comparison
doc, real source confirmed) publish Markdown+JSON+SARIF+manifest as **one**
atomic git commit — verified to have changed exactly the declared paths,
idempotently re-adoptable after a lost acknowledgement, with any digest
mismatch treated as a non-retryable integrity error. :func:`write_report`
instead calls :func:`atomic_write_verified` once per format — each
individual file is atomic and byte-verified, but a crash mid-way can leave a
run directory with some fresh outputs and some stale (or absent) ones from a
prior run, which the reference's single-commit design would not permit.
Accepted as a real, open gap rather than closed here: L4L0 has no git-backed
run-directory layer for a commit-style multi-file transaction to attach to,
and adding one solely for this would be exactly the kind of unrequested
infrastructure this project's own conventions warn against. A future
run-directory redesign that does need atomic multi-file publication should
build on this reference's design rather than reinvent it.

PDF and DOCX are both rendered from the SAME intermediate HTML
(:mod:`lalo.report.html`), not built independently of each other or of the
Markdown/JSON/SARIF outputs — one escaped, deterministic source of truth for
every human-facing rendering, matching this module's own "assemble once,
write many formats" shape rather than re-deriving report content per format.
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
from .docx import render_report_docx
from .html import render_report_html
from .markdown import render_report_md
from .overrides import SeverityOverride, apply_overrides
from .pdf import render_report_pdf
from .sarif import render_sarif

MARKDOWN_FILENAME = "report.md"
JSON_FILENAME = "report.json"
SARIF_FILENAME = "findings.sarif"
PDF_FILENAME = "report.pdf"
DOCX_FILENAME = "report.docx"


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
    ``"json"``, ``"sarif"``, ``"pdf"``, and ``"docx"``.
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
    html = render_report_html(records, coverage, generated_at=generated_at)
    pdf_bytes = render_report_pdf(html)
    docx_bytes = render_report_docx(html)

    paths = {
        "markdown": run_dir / MARKDOWN_FILENAME,
        "json": run_dir / JSON_FILENAME,
        "sarif": run_dir / SARIF_FILENAME,
        "pdf": run_dir / PDF_FILENAME,
        "docx": run_dir / DOCX_FILENAME,
    }
    atomic_write_verified(paths["markdown"], markdown.encode("utf-8"))
    atomic_write_verified(
        paths["json"], json.dumps(json_document, ensure_ascii=False, indent=2).encode("utf-8")
    )
    atomic_write_verified(
        paths["sarif"], json.dumps(sarif_document, ensure_ascii=False, indent=2).encode("utf-8")
    )
    atomic_write_verified(paths["pdf"], pdf_bytes)
    atomic_write_verified(paths["docx"], docx_bytes)
    return paths
