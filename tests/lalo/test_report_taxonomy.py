"""Tests for the curated vuln_class -> CWE mapping."""

from __future__ import annotations

from lalo.report.taxonomy import CWE_BY_VULN_CLASS, cwe_for


def test_cwe_for_known_vuln_class_returns_mapped_id() -> None:
    assert cwe_for("sql-injection") == "CWE-89"


def test_cwe_for_unknown_vuln_class_returns_none() -> None:
    assert cwe_for("not-a-real-class") is None


def test_cwe_for_is_case_and_whitespace_insensitive() -> None:
    assert cwe_for("  SQL-Injection  ") == "CWE-89"


def test_cwe_for_covers_every_real_skill_vuln_class() -> None:
    """Every vuln_class slug in the skill library's own name: frontmatter
    should resolve to a real CWE, except the small, explicitly-documented
    set with no single well-established id."""
    unmapped_by_design = {"subdomain-takeover"}
    real_skill_slugs = {
        "access-control",
        "active-directory-ldap-mapping",
        "agentic-system-security",
        "binary-memory-corruption",
        "browser-security",
        "business-logic",
        "cache-poisoning",
        "cloud-iam-storage-misconfiguration",
        "command-injection",
        "cors-misconfiguration",
        "csrf",
        "graphql",
        "header-injection",
        "http-request-smuggling",
        "information-disclosure",
        "insecure-deserialization",
        "insecure-file-uploads",
        "jwt",
        "kubernetes-serverless-assessment",
        "llm-prompt-injection",
        "mass-assignment",
        "nosql-injection",
        "open-redirect",
        "path-traversal",
        "prototype-pollution",
        "race-conditions",
        "session-replay-and-mitm",
        "sql-injection",
        "ssrf",
        "ssti",
        "subdomain-takeover",
        "weak-credentials",
        "web-cache-deception",
        "xss",
        "xxe",
    }
    for slug in real_skill_slugs - unmapped_by_design:
        assert cwe_for(slug) is not None, f"{slug} has no CWE mapping"
    for slug in unmapped_by_design:
        assert cwe_for(slug) is None


def test_cwe_by_vuln_class_values_all_look_like_cwe_ids() -> None:
    for cwe in CWE_BY_VULN_CLASS.values():
        assert cwe.startswith("CWE-")
        assert cwe[4:].isdigit()
