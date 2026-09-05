"""DOCX export via ``html2docx``, converting the same escaped HTML the PDF
export uses — see :mod:`lalo.report.html` for why every dynamic value in
that HTML is already escaped before this module ever sees it.
"""

from __future__ import annotations

from html2docx import html2docx

_TITLE = "L4L0 Security Assessment Report"


def render_report_docx(html: str) -> bytes:
    """Render ``html`` (from :func:`lalo.report.html.render_report_html`) to DOCX bytes."""
    buffer = html2docx(html, title=_TITLE)
    return buffer.getvalue()
