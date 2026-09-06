"""Deterministic HTML rendering — the shared source both PDF and DOCX export
convert from, never an LLM call, matching :mod:`lalo.report.markdown`'s own
"pure string assembly" discipline for the exact same reason.

Every dynamic value (target-observed evidence, an LLM-authored title or
description, anything that ultimately traces back to content this project
does not control) goes through :func:`html.escape` before it is ever
concatenated into the document. This is the HTML analogue of
:mod:`lalo.report.markdown`'s ``safe_fence`` - but simpler, not a port of
anything: Markdown's fenced-code-block problem (a backtick run inside
content long enough to close the fence early) has no HTML equivalent to
guard against in the same way, because HTML escaping neutralizes markup
injection unconditionally, regardless of what characters or structure the
escaped text contains — there is no "run of some character" that can ever
close a tag once ``<``/``>``/``&`` are all entity-escaped. A different real
risk this rendering path does carry, absent from the Markdown/JSON/SARIF
outputs entirely: :mod:`lalo.report.pdf`'s WeasyPrint renderer can fetch
external resources an ``<img src>``/``@import`` references — a report
containing target-influenced content is exactly adversarial-input-reaching-
a-renderer, the same category of concern strix's own PDF-generation path
(``reportlab``, read via its comparison doc) explicitly guards against by
escaping unrecognized markup tokens. Escaping here closes the injection
vector at the source (no live tag ever reaches the renderer to begin with);
:mod:`lalo.report.pdf`'s own locked-down ``url_fetcher`` is the second,
independent layer in case an escaping bug ever let one through anyway.
"""

from __future__ import annotations

from html import escape

from .collect import FindingRecord
from .coverage import CoverageSummary

_STYLE = """
body { font-family: sans-serif; font-size: 11pt; color: #1a1a1a; }
h1 { font-size: 20pt; }
h2 { font-size: 14pt; border-bottom: 1px solid #ccc; padding-bottom: 4px; margin-top: 28px; }
h3 { font-size: 11pt; margin-bottom: 4px; }
dl { margin: 0 0 12px 0; }
dt { font-weight: bold; float: left; clear: left; width: 130px; }
dd { margin-left: 140px; }
pre { background: #f4f4f4; padding: 8px; white-space: pre-wrap; word-break: break-word; }
.warning { color: #a33; font-weight: bold; }
"""


def _e(value: object) -> str:
    return escape(str(value))


def render_finding_html(record: FindingRecord) -> str:
    parts = [f"<h2>{_e(record.title or record.finding_id)}</h2>", "<dl>"]
    parts.append(f"<dt>ID</dt><dd>{_e(record.finding_id)}</dd>")
    parts.append(f"<dt>Class</dt><dd>{_e(record.vuln_class)}</dd>")
    target_line = _e(record.target)
    if record.param:
        target_line += f" (param: <code>{_e(record.param)}</code>)"
    parts.append(f"<dt>Target</dt><dd>{target_line}</dd>")
    severity_line = _e(record.effective_severity.upper())
    if record.override_reason:
        severity_line += f" <em>(overridden: {_e(record.override_reason)})</em>"
    parts.append(f"<dt>Severity</dt><dd>{severity_line}</dd>")
    parts.append(
        f"<dt>CVSS</dt><dd>{record.cvss_score:.1f} ({_e(record.cvss_severity)}) "
        f"— <code>{_e(record.cvss_vector)}</code></dd>"
    )
    parts.append(f"<dt>Confidence</dt><dd>{record.confidence.score}/100</dd>")
    if record.review_verdict:
        proof = f" ({_e(record.review_proof_level)})" if record.review_proof_level else ""
        parts.append(f"<dt>Adversarial Review</dt><dd>{_e(record.review_verdict)}{proof}</dd>")
    parts.append("</dl>")

    parts.append(f"<h3>Description</h3><p>{_e(record.description) or '(none provided)'}</p>")

    parts.append("<h3>Evidence</h3>")
    if not record.evidence_grounded:
        parts.append(
            '<p class="warning">Warning: the stated evidence excerpt could not be verified '
            "against the evidence below - treat this finding's proof as unconfirmed.</p>"
        )
    for i, blob in enumerate(record.evidence, start=1):
        parts.append(f"<p>Evidence {i}:</p><pre>{_e(blob)}</pre>")

    parts.append(f"<h3>Counterevidence</h3><p>{_e(record.counterevidence) or '(none stated)'}</p>")
    parts.append(
        "<h3>What Would Change This Severity</h3>"
        f"<p>{_e(record.severity_change_conditions) or '(none stated)'}</p>"
    )
    parts.append(f"<h3>Remediation</h3><p>{_e(record.remediation) or '(none stated)'}</p>")

    parts.append("<h3>Confidence Breakdown</h3><ul>")
    parts += [
        f"<li>{_e(name)}: {points}</li>" for name, points in record.confidence.breakdown.items()
    ]
    parts.append("</ul>")
    if record.confidence.flags:
        parts.append("<p>Flags:</p><ul>")
        parts += [f"<li>{_e(flag)}</li>" for flag in record.confidence.flags]
        parts.append("</ul>")

    return "\n".join(parts)


def render_report_html(
    records: list[FindingRecord],
    coverage: CoverageSummary,
    *,
    generated_at: str | None = None,
) -> str:
    parts = [
        "<!doctype html>",
        f"<html><head><meta charset='utf-8'><style>{_STYLE}</style></head><body>",
        "<h1>L4L0 Security Assessment Report</h1>",
    ]
    if generated_at:
        parts.append(f"<p><strong>Generated:</strong> {_e(generated_at)}</p>")
    parts.append(f"<p><strong>Findings:</strong> {len(records)}</p>")

    parts.append("<h2>Coverage</h2>")
    parts.append(
        f"<p><strong>Assessed:</strong> {_e(', '.join(coverage.assessed) or '(none)')}</p>"
    )
    parts.append(
        f"<p><strong>Not assessed:</strong> {_e(', '.join(coverage.not_assessed) or '(none)')}</p>"
    )
    parts.append(
        "<p><em>A class marked 'not assessed' means no finding was filed for it - this "
        "does not distinguish 'tested and found clean' from 'never examined'.</em></p>"
    )

    parts.append("<h2>Findings</h2>")
    if not records:
        parts.append("<p>No findings recorded.</p>")
    for record in records:
        try:
            parts.append(render_finding_html(record))
        except Exception as exc:  # noqa: BLE001 - one malformed finding must not blank the report
            parts.append(
                f"<h2>{_e(record.finding_id)}</h2><p>Failed to render this finding: {_e(exc)}</p>"
            )

    parts.append("</body></html>")
    return "\n".join(parts)
