"""Tests for PDF export: real WeasyPrint rendering, external resources blocked.

WeasyPrint itself catches a url_fetcher's exception per-resource (logs it,
renders the rest of the document without that one image/stylesheet) rather
than letting it abort the whole render - a fault-isolation behavior worth
relying on here, matching this project's own "one bad piece never blanks the
whole report" convention elsewhere (render_report_md/render_report_html's
own per-finding try/except). So the property actually worth testing is not
"blocking raises" but "the fetcher is genuinely invoked and genuinely
refuses, and the render still completes without ever touching the network."
"""

from __future__ import annotations

from io import BytesIO

import pytest
from pypdf import PdfReader
from pypdf.errors import FileNotDecryptedError

from lalo.report import pdf as pdf_module
from lalo.report.pdf import (
    ExternalResourceBlockedError,
    encrypt_pdf,
    generate_password,
    render_report_pdf,
)

_MINIMAL_HTML = "<!doctype html><html><body><h1>Report</h1><p>hello</p></body></html>"


def test_render_report_pdf_produces_real_pdf_bytes() -> None:
    pdf_bytes = render_report_pdf(_MINIMAL_HTML)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 100


def test_deny_all_external_resources_always_raises() -> None:
    with pytest.raises(ExternalResourceBlockedError):
        pdf_module._deny_all_external_resources("http://attacker.example/pixel.png")  # noqa: SLF001


def test_render_report_pdf_never_lets_an_external_image_reach_the_fetcher_unblocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real end-to-end proof the fetcher is actually wired into the render
    call, not just correct in isolation: spy on it, render a document with a
    real external <img>, and confirm the spy (which still refuses) was
    genuinely invoked with that exact attacker-controlled URL."""
    seen_urls: list[str] = []
    original = pdf_module._deny_all_external_resources  # noqa: SLF001

    def spy(url: str, **kwargs: object) -> None:
        seen_urls.append(url)
        original(url, **kwargs)

    monkeypatch.setattr(pdf_module, "_deny_all_external_resources", spy)
    html = '<!doctype html><html><body><img src="http://attacker.example/pixel.png"></body></html>'
    pdf_bytes = render_report_pdf(html)
    assert pdf_bytes.startswith(b"%PDF-")  # render still completes
    assert "http://attacker.example/pixel.png" in seen_urls


# --- generate_password / encrypt_pdf: protecting sensitive report content --


def test_generate_password_is_long_and_varies_every_call() -> None:
    first = generate_password()
    second = generate_password()
    assert len(first) >= 20
    assert len(second) >= 20
    assert first != second


def test_encrypt_pdf_produces_a_real_pdf_that_requires_the_password() -> None:
    plain = render_report_pdf(_MINIMAL_HTML)
    password = generate_password()
    encrypted = encrypt_pdf(plain, password)

    assert encrypted.startswith(b"%PDF-")
    assert encrypted != plain

    reader = PdfReader(BytesIO(encrypted))
    assert reader.is_encrypted
    with pytest.raises(FileNotDecryptedError):
        reader.pages[0].extract_text()


def test_encrypt_pdf_decrypts_with_the_correct_password_and_preserves_content() -> None:
    plain_html = "<!doctype html><html><body><p>secret-marker-xyz</p></body></html>"
    plain = render_report_pdf(plain_html)
    password = generate_password()
    encrypted = encrypt_pdf(plain, password)

    reader = PdfReader(BytesIO(encrypted))
    result = reader.decrypt(password)
    assert result != 0  # 0 == PasswordType.NOT_DECRYPTED
    assert "secret-marker-xyz" in reader.pages[0].extract_text()


def test_encrypt_pdf_rejects_the_wrong_password() -> None:
    plain = render_report_pdf(_MINIMAL_HTML)
    encrypted = encrypt_pdf(plain, generate_password())

    reader = PdfReader(BytesIO(encrypted))
    result = reader.decrypt("definitely-not-the-real-password")
    assert result == 0  # PasswordType.NOT_DECRYPTED
