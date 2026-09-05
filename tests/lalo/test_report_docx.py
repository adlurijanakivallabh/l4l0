"""Tests for DOCX export."""

from __future__ import annotations

from lalo.report.docx import render_report_docx

_MINIMAL_HTML = "<!doctype html><html><body><h1>Report</h1><p>hello world</p></body></html>"


def test_render_report_docx_produces_a_real_docx_zip() -> None:
    docx_bytes = render_report_docx(_MINIMAL_HTML)
    # A .docx file is a zip archive - "PK" is the zip local-file-header magic.
    assert docx_bytes.startswith(b"PK")
    assert len(docx_bytes) > 100
