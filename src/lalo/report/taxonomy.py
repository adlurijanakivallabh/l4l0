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
