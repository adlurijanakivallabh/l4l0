"""Curated vuln_class -> CWE mapping for compliance-oriented report
consumers (SARIF viewers, OWASP-mapped dashboards). Intentionally small
and curated, not exhaustive - an unmapped vuln_class degrades to no CWE
line, never an error.

Keys are drawn from the real ``name:`` frontmatter values across every
file in ``src/lalo/skills/content/vulnerabilities/*.md`` (the slug an
agent's own ``record_finding`` call is expected to pass as ``vuln_class``,
per :mod:`lalo.findings.tool`'s own field description), plus a handful of
common synonyms an agent might reasonably use instead of a skill's exact
slug (``idor``, ``authentication-bypass``). A handful of skill classes with
no single well-established CWE (e.g. ``subdomain-takeover``) are
deliberately left unmapped rather than forced onto an inaccurate id.
"""

from __future__ import annotations

CWE_BY_VULN_CLASS: dict[str, str] = {
    # --- floor set -----------------------------------------------------
    "sql-injection": "CWE-89",
    "command-injection": "CWE-78",
    "ssti": "CWE-1336",
    "xxe": "CWE-611",
    "ssrf": "CWE-918",
    "idor": "CWE-639",
    "broken-access-control": "CWE-284",
    "xss": "CWE-79",
    "path-traversal": "CWE-22",
    "insecure-deserialization": "CWE-502",
    "authentication-bypass": "CWE-287",
    "cors-misconfiguration": "CWE-942",
    "prototype-pollution": "CWE-1321",
    "cache-poisoning": "CWE-444",
    "web-cache-deception": "CWE-524",
    "race-conditions": "CWE-362",
    "http-request-smuggling": "CWE-444",
    # --- remaining real skill slugs (src/lalo/skills/content/vulnerabilities) --
    "access-control": "CWE-284",
    "active-directory-ldap-mapping": "CWE-269",
    "agentic-system-security": "CWE-441",
    "binary-memory-corruption": "CWE-787",
    "browser-security": "CWE-346",
    "business-logic": "CWE-840",
    "cloud-iam-storage-misconfiguration": "CWE-732",
    "csrf": "CWE-352",
    "graphql": "CWE-285",
    "header-injection": "CWE-113",
    "information-disclosure": "CWE-200",
    "insecure-file-uploads": "CWE-434",
    "jwt": "CWE-347",
    "kubernetes-serverless-assessment": "CWE-269",
    "llm-prompt-injection": "CWE-1427",
    "mass-assignment": "CWE-915",
    "nosql-injection": "CWE-943",
    "open-redirect": "CWE-601",
    "session-replay-and-mitm": "CWE-294",
    "weak-credentials": "CWE-521",
    # subdomain-takeover: no single well-established CWE id - left unmapped.
}


def cwe_for(vuln_class: str) -> str | None:
    """Best-effort CWE ID for a vuln_class slug, or None if unmapped."""
    return CWE_BY_VULN_CLASS.get(vuln_class.strip().lower())


# --- OWASP API Security Top 10 (2023 edition) ---------------------------
# Curated the same way as CWE_BY_VULN_CLASS above: only vuln_class slugs
# with a genuinely clean fit to a real 2023 category are mapped - BOLA is
# textbook IDOR, "mass assignment" was folded into "Broken Object Property
# Level Authorization" by name in the 2023 edition, SSRF keeps its own
# dedicated category unchanged, and so on. The 2023 edition dropped the old
# 2019 catch-all "Injection" category entirely, so sql-injection/
# command-injection/ssti/xxe/nosql-injection - a real, accurate CWE match
# each - have no honest 2023 API-Top-10 home and are deliberately left
# unmapped here, exactly like subdomain-takeover is left unmapped in
# CWE_BY_VULN_CLASS above.
OWASP_API_TOP10_NAMES: dict[str, str] = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

OWASP_API_BY_VULN_CLASS: dict[str, str] = {
    "idor": "API1:2023",
    "authentication-bypass": "API2:2023",
    "weak-credentials": "API2:2023",
    "jwt": "API2:2023",
    "mass-assignment": "API3:2023",
    "broken-access-control": "API5:2023",
    "access-control": "API5:2023",
    "ssrf": "API7:2023",
    "cors-misconfiguration": "API8:2023",
    "cloud-iam-storage-misconfiguration": "API8:2023",
    "kubernetes-serverless-assessment": "API8:2023",
    "graphql": "API9:2023",
    "subdomain-takeover": "API9:2023",
}


def owasp_api_for(vuln_class: str) -> str | None:
    """Best-effort OWASP API Security Top 10 (2023) category id for a
    vuln_class slug (e.g. "API1:2023"), or None if unmapped - same
    degrade-to-nothing contract as cwe_for above."""
    return OWASP_API_BY_VULN_CLASS.get(vuln_class.strip().lower())


def owasp_api_name_for(vuln_class: str) -> str | None:
    """The mapped category's human-readable name (e.g. "Broken Object Level
    Authorization"), or None if unmapped."""
    category = owasp_api_for(vuln_class)
    return OWASP_API_TOP10_NAMES.get(category) if category else None
