"""PDF export via WeasyPrint, rendered from :mod:`lalo.report.html`'s own
escaped HTML — with all external resource fetching disabled.

A reference agent's own PDF report generator (``reportlab``-based read in
full, not just via its comparison doc, for this project's own Phase 16
reference-pass cycle: ``strix/interface/viewer/report_pdf.py``, 705 lines)
explicitly escapes unrecognized markup tokens in LLM-authored finding
fields specifically because those fields ultimately trace back to
target-observed content — the same defensive reasoning
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

That same full re-read surfaced a genuine, previously-missing capability:
that reference's own ``encrypt_pdf``/``generate_password`` protect the
full-detail PDF (which, like L4L0's own, carries PoC/evidence content) with
a CSPRNG-generated, AES-256 password, "shown only to the local browser...
never leaves the machine except in the user's own hands." A pentest
report is exactly the artifact most likely to be copied, emailed, or
shared outside the machine it was generated on, so this is adopted
directly via :func:`generate_password`/:func:`encrypt_pdf` (``pypdf``
instead of that reference's own choice, but the same design: a fresh
password per report, the caller decides where it goes). Deliberately kept
OUT of :func:`~lalo.report.writer.write_report`'s own default flow rather
than made unconditional: changing that function's return shape to also
carry a password is a real API-shape decision with its own UX tradeoffs
(where does the password surface, what happens if it's lost) that this
phase's own scope — closing a reference-identified capability gap — does
not need to force. An operator/GUI layer that wants an encrypted copy for
external sharing calls these two functions directly on the already-
rendered PDF bytes.
"""

from __future__ import annotations

import secrets
from io import BytesIO

from pypdf import PdfReader, PdfWriter
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


def generate_password() -> str:
    """A fresh, >=20-character URL-safe password from a CSPRNG.

    Call once per report and hand it to the caller alongside the encrypted
    bytes — this module never stores or logs it.
    """
    return secrets.token_urlsafe(16)


def encrypt_pdf(pdf_bytes: bytes, password: str) -> bytes:
    """Re-encode ``pdf_bytes`` as an AES-256-encrypted PDF requiring ``password`` to open."""
    reader = PdfReader(BytesIO(pdf_bytes))
    writer = PdfWriter()
    writer.append(reader)
    writer.encrypt(user_password=password, algorithm="AES-256")
    out = BytesIO()
    writer.write(out)
    return out.getvalue()
