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

**Severity-graded failure, not uniform failure** (a fresh finding from this
project's own Phase 16 reference-pass cycle): a second reference's own
report-finalization design (``report-output-surface.ts``, read via its
comparison doc) deliberately downgrades a PDF-generation failure to a
warning while treating canonical-data corruption as always terminal —
"these are secondary artifacts," a customer-facing re-render of already-
canonical data, not the record of truth itself. :func:`write_report`
previously had no such distinction: a WeasyPrint or html2docx bug on either
export would raise straight out of this function and leave the operator
with NO report at all, even though Markdown/JSON/SARIF — the actual
canonical, structured record — had already rendered successfully. PDF and
DOCX generation are now each independently wrapped: a failure there is
logged and that format is simply absent from the returned mapping, while a
Markdown/JSON/SARIF failure still propagates uncaught, exactly matching
that reference's own canonical-vs-secondary distinction.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from ..core.atomic_io import atomic_write_verified
from ..core.logging import get_logger
from ..graph.model import ReachabilityGraph
from ..orchestrator.budget import RunStatus
from ..skills.loader import Skill
from .collect import build_chain_records, collect_findings, sort_findings
from .coverage import build_coverage_summary
from .docx import render_report_docx
from .html import render_report_html
from .markdown import render_report_md
from .overrides import SeverityOverride, apply_overrides
from .pdf import render_report_pdf
from .sarif import render_sarif

_log = get_logger("lalo.report")

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
    status: RunStatus | None = None,
) -> dict[str, Path]:
    """Assemble every format from ``graph`` and write them, byte-verified.

    ``status`` is the scan's own closed-taxonomy outcome (see
    :class:`~lalo.orchestrator.budget.RunStatus`) - passing it surfaces
    *why* a scan stopped (budget exhausted, an unverified stop, an error)
    directly in the delivered report, rather than that information living
    only in the live GUI event stream and being lost once the run ends.

    Returns the written path for each format, keyed by ``"markdown"``,
    ``"json"``, and ``"sarif"`` (always present - a failure here propagates
    uncaught), plus ``"pdf"`` and ``"docx"`` (present only if that specific
    export succeeded; a renderer failure there is logged and the key is
    simply absent, never fatal to this call).
    """
    # Overrides before sort, not after: sort_findings reads effective_severity
    # (display_severity if set, else cvss_severity) - sorting first would rank
    # every finding by its PRE-override severity, so an operator's "this is
    # actually critical" correction would still be ordered under an
    # unrelated higher-severity finding in the delivered report.
    records = sort_findings(apply_overrides(collect_findings(graph), overrides or []))
    coverage = build_coverage_summary(skills, records)
    chains = build_chain_records(graph.all_enabling_chains(), records)
    status_value = status.value if status is not None else None

    markdown = render_report_md(
        records, coverage, chains=chains, generated_at=generated_at, status=status_value
    )
    json_document = {
        "generated_at": generated_at,
        "status": status_value,
        "findings": [asdict(record) for record in records],
        "coverage": asdict(coverage),
        "chains": [asdict(chain) for chain in chains],
    }
    sarif_document = render_sarif(
        records,
        execution_successful=status is None or status != RunStatus.ERROR,
        automation_id=run_dir.name,
    )
    html = render_report_html(
        records, coverage, chains=chains, generated_at=generated_at, status=status_value
    )

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

    # PDF/DOCX are secondary, customer-convenience re-renders of the SAME
    # canonical data already durably written above - a renderer bug (a
    # WeasyPrint/html2docx edge case) must never cost the operator the
    # report they already have. Each is independently best-effort: logged
    # and simply absent from the result, never fatal to this call.
    try:
        atomic_write_verified(run_dir / PDF_FILENAME, render_report_pdf(html))
    except Exception:
        _log.warning("PDF report export failed; other formats were still written", exc_info=True)
    else:
        paths["pdf"] = run_dir / PDF_FILENAME

    try:
        atomic_write_verified(run_dir / DOCX_FILENAME, render_report_docx(html))
    except Exception:
        _log.warning("DOCX report export failed; other formats were still written", exc_info=True)
    else:
        paths["docx"] = run_dir / DOCX_FILENAME

    return paths
