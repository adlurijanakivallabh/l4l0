"""PDF export via WeasyPrint, rendered from :mod:`lalo.report.html`'s own
escaped HTML — with all external resource fetching disabled.

A reference agent's own PDF report generator (``reportlab``-based, read via
its comparison doc) explicitly escapes unrecognized markup tokens in
LLM-authored finding fields specifically because those fields ultimately
trace back to target-observed content — the same defensive reasoning
:mod:`lalo.report.html` already applies here via :func:`html.escape`. This
module adds a second, independent layer specific to WeasyPrint (a real
HTML/CSS renderer, not a markup mini-language like ReportLab's): WeasyPrint
can fetch external resources (``<img src>``, ``@import`` in CSS) if a
document references any, which — even with every dynamic value escaped —
is disabled outright here rather than merely trusted to never come up,
since a report is a fully self-contained document with no legitimate
external-resource dependency (the shared ``<style>`` block is inlined by
:mod:`lalo.report.html`) and a permissive default fetcher would otherwise be
a real SSRF/local-file-read surface fed by an escaping bug elsewhere.
"""

from __future__ import annotations

from weasyprint import HTML


class ExternalResourceBlockedError(RuntimeError):
    """Raised by the locked-down fetcher for any URL a report document tries to load."""


def _deny_all_external_resources(url: str, **_kwargs: object) -> None:
    raise ExternalResourceBlockedError(
        f"report PDF rendering may not fetch external resources: {url!r}"
    )


def render_report_pdf(html: str) -> bytes:
    """Render ``html`` (from :func:`lalo.report.html.render_report_html`) to PDF bytes."""
    document = HTML(string=html, url_fetcher=_deny_all_external_resources)
    pdf_bytes: bytes = document.write_pdf()
    return pdf_bytes
