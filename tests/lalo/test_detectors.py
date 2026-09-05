"""Tests for web detectors and the coverage ledger."""

from __future__ import annotations

from lalo.detectors import (
    CoverageLedger,
    cmdi_output,
    oob_interaction,
    open_redirect,
    path_traversal_read,
    sqli_boolean,
    sqli_error,
    sqli_time,
    ssti_eval,
    xss_reflection,
)
from lalo.models import EvidenceKind


def test_sqli_error_detects_and_locates() -> None:
    ev = sqli_error("... You have an error in your SQL syntax; check ...", fire_ref="r1")
    assert ev is not None and ev.kind is EvidenceKind.STRUCTURAL
    assert "error in your sql syntax" in ev.observed.lower()
    assert sqli_error("all good") is None


def test_sqli_time_and_boolean() -> None:
    assert sqli_time(5200, 200) is not None
    assert sqli_time(300, 200) is None
    assert sqli_boolean("welcome admin dashboard", "invalid login") is not None
    assert sqli_boolean("same page", "same page") is None


def test_xss_reflection_requires_html_and_unencoded() -> None:
    payload = "<script>alert(1)</script>"
    assert xss_reflection(payload, f"<html>{payload}</html>") is not None
    assert xss_reflection(payload, "encoded &lt;script&gt;", content_type="text/html") is None
    json_ct = xss_reflection(payload, f"<html>{payload}</html>", content_type="application/json")
    assert json_ct is None


def test_path_traversal_and_cmdi_are_execution_evidence() -> None:
    lfi = path_traversal_read("root:x:0:0:root:/root:/bin/bash\n")
    assert lfi is not None and lfi.kind is EvidenceKind.EXECUTION
    rce = cmdi_output("uid=0(root) gid=0(root) groups=0(root)")
    assert rce is not None and rce.metadata.get("succeeded") is True


def test_ssti_eval_confirms_evaluation() -> None:
    assert ssti_eval("{{7*7}}", "result is 49") is not None
    # Payload echoed literally (not evaluated) -> no hit.
    assert ssti_eval("{{7*7}}", "you searched for {{7*7}}") is None


def test_open_redirect_and_oob() -> None:
    assert open_redirect("https://evil.example/", "//evil.example") is not None
    assert open_redirect("/dashboard", "//evil.example") is None
    assert oob_interaction([object()]) is not None
    assert oob_interaction([]) is None


def test_coverage_ledger_flags_unassessed() -> None:
    ledger = CoverageLedger()
    ledger.mark_applicable("https://app/x", "sqli")
    ledger.mark_applicable("https://app/x", "xss")
    ledger.mark_assessed("https://app/x", "sqli")
    gaps = ledger.not_assessed()
    assert ("https://app/x", "xss") in gaps
    assert ("https://app/x", "sqli") not in gaps
    assert ledger.report()["coverage_ratio"] == 0.5
