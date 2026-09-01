"""Professional report template (Build Order 6).

Testfire-style structure — executive summary, a vulnerability-summary "report
card", and a per-finding section (description, risk, affected system, tools
used, evidence, remediation, WSTG reference) — layered entirely over the
existing ``build_evidence_index``. No new detection logic: every technical
fact here already lives on a confirmed ``Finding``; the only additions are
static vuln_class -> (WSTG id, description, remediation) lookups and simple
presentation formatting. Confirmed findings and informational observations
(severity == "informational", e.g. ``information_exposure``) are rendered in
visibly separate sections — an informational observation is never presented
as a confirmed vulnerability.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from reachagent.graph.store import ReachabilityGraph
from reachagent.report.llm_report import ReportClient, generate_narrative
from reachagent.report.renderer import (
    _SEVERITY_SCORE,
    build_evidence_index,
    sanitize_report_markdown,
)

# vuln_class -> (WSTG test id, WSTG test name). Values are the well-known
# WSTG v4.2 leaf IDs where confidently known; classes with no confidently-known
# leaf ID cite the parent category only (never a fabricated sub-number) via
# _WSTG_CATEGORY_FALLBACK below.
_WSTG: dict[str, tuple[str, str]] = {
    "sqli": ("WSTG-INPV-05", "Testing for SQL Injection"),
    "sqli_blind": ("WSTG-INPV-05", "Testing for SQL Injection"),
    "nosqli": ("WSTG-INPV-05", "Testing for SQL Injection"),
    "ldap_injection": ("WSTG-INPV-06", "Testing for LDAP Injection"),
    "command_injection": ("WSTG-INPV-12", "Testing for Command Injection"),
    "xxe": ("WSTG-INPV-07", "Testing for XML Injection"),
    "path_traversal": ("WSTG-ATHZ-01", "Testing Directory Traversal File Include"),
    "ssrf": ("WSTG-INPV-19", "Testing for Server-Side Request Forgery"),
    "ssti": ("WSTG-INPV", "Input Validation Testing (Template Injection)"),
    "xss_reflected": ("WSTG-INPV-01", "Testing for Reflected Cross Site Scripting"),
    "xss_stored": ("WSTG-INPV-02", "Testing for Stored Cross Site Scripting"),
    "xss_dom": ("WSTG-CLNT-01", "Testing for DOM-Based Cross Site Scripting"),
    "clickjacking": ("WSTG-CLNT-09", "Testing for Clickjacking"),
    "csrf_missing_protection": ("WSTG-SESS-05", "Testing for Cross Site Request Forgery"),
    "cors_misconfig": ("WSTG-CLNT", "Client-Side Testing (CORS Configuration)"),
    "bola": ("WSTG-ATHZ-04", "Testing for Insecure Direct Object References"),
    "bfla": ("WSTG-ATHZ-02", "Testing for Bypassing Authorization Schema"),
    "idor": ("WSTG-ATHZ-04", "Testing for Insecure Direct Object References"),
    "mass_assignment": ("WSTG-ATHZ", "Authorization Testing (Mass Assignment)"),
    "default_credentials": ("WSTG-ATHN-02", "Testing for Default Credentials"),
    "rate_limit_absence": ("WSTG-BUSL", "Business Logic Testing (Rate Limiting)"),
    "open_redirect": ("WSTG-CLNT-04", "Testing for Client-Side URL Redirect"),
    "web_cache_poisoning": ("WSTG-INPV", "Input Validation Testing (Cache Poisoning)"),
    "request_smuggling": ("WSTG-INPV", "Input Validation Testing (Request Smuggling)"),
    "subdomain_takeover": ("WSTG-CONF", "Configuration and Deployment Management Testing"),
    "cloud_bucket_exposure": ("WSTG-CONF", "Configuration and Deployment Management Testing"),
    "jwt_forgery": ("WSTG-SESS", "Session Management Testing (JWT)"),
    "graphql": ("WSTG-INPV", "Input Validation Testing (GraphQL)"),
    "business_logic": ("WSTG-BUSL", "Business Logic Testing"),
    "race": ("WSTG-BUSL", "Business Logic Testing (Race Conditions)"),
    "file_upload": ("WSTG-BUSL-09", "Test Upload of Unexpected File Types"),
    "information_exposure": ("WSTG-INFO", "Information Gathering"),
}
_WSTG_DEFAULT: tuple[str, str] = ("WSTG-INFO", "Information Gathering")

_DESCRIPTION: dict[str, str] = {
    "sqli": "User-controlled input reaches a SQL query in a way that alters its logic.",
    "sqli_blind": "A SQL query's behavior changes in response to boolean/time-based "
    "input, confirming injection without a directly visible error or data leak.",
    "nosqli": "User-controlled input reaches a NoSQL query operator in a way that "
    "alters its logic.",
    "ldap_injection": "User-controlled input reaches an LDAP query filter unsanitized.",
    "command_injection": "User-controlled input reaches an OS command execution sink.",
    "xxe": "The XML parser resolves external entities from untrusted input.",
    "path_traversal": "User-controlled input reaches a filesystem path without "
    "normalization, allowing access outside the intended directory.",
    "ssrf": "The server can be induced to issue a request to an attacker-chosen destination.",
    "ssti": "User-controlled input is evaluated as a template expression server-side.",
    "xss_reflected": "User-controlled input is reflected into the response without "
    "sufficient output encoding, executing in a victim's browser.",
    "xss_stored": "User-controlled input is persisted and later rendered without "
    "sufficient output encoding, executing in another user's browser.",
    "xss_dom": "Client-side script writes attacker-controlled input into the DOM in "
    "an executable sink.",
    "clickjacking": "The response lacks a frame-denial defense (X-Frame-Options or a "
    "restrictive frame-ancestors CSP), allowing the page to be framed.",
    "csrf_missing_protection": "A state-changing request relies only on a session "
    "cookie sent cross-site (SameSite=None) with no anti-CSRF token.",
    "cors_misconfig": "The CORS policy reflects an arbitrary Origin with credentials "
    "allowed, letting any site read authenticated responses.",
    "bola": "An authenticated user can read another identity's object by substituting "
    "an object identifier, bypassing an ownership check.",
    "bfla": "An authenticated user can invoke a function or endpoint their role should not permit.",
    "idor": "An object reference (id/path parameter) can be substituted to access "
    "another identity's data without authorization.",
    "mass_assignment": "The endpoint binds request fields directly onto an internal "
    "object, letting a client set fields it should not control.",
    "default_credentials": "A documented or well-known default credential pair "
    "authenticates successfully.",
    "rate_limit_absence": "Repeated authentication attempts are not throttled or "
    "locked out, allowing unbounded guessing.",
    "open_redirect": "A redirect target is taken from user input without validating "
    "it stays within the application's own scope.",
    "web_cache_poisoning": "An unkeyed input influences a cached response, letting an "
    "attacker poison the cache for other users.",
    "request_smuggling": "Front-end and back-end disagree on where one HTTP request "
    "ends and the next begins.",
    "subdomain_takeover": "A DNS record (typically a CNAME) points to a de-provisioned "
    "third-party service that can be claimed by an attacker.",
    "cloud_bucket_exposure": "A cloud storage bucket associated with the target is "
    "publicly listable or readable.",
    "jwt_forgery": "A JWT can be forged or its algorithm/verification bypassed to "
    "produce a token the server accepts.",
    "graphql": "The GraphQL endpoint exposes a violation (e.g. introspection, "
    "authorization bypass, or excessive data exposure) through query manipulation.",
    "business_logic": "An application workflow can be driven into a state the "
    "business rules should have prevented.",
    "race": "A time-of-check/time-of-use window lets a concurrent request bypass an "
    "invariant the application relies on.",
    "file_upload": "The upload endpoint accepts a file type/content it should reject, "
    "with no server-side validation observed.",
    "information_exposure": "The response body discloses implementation detail "
    "(a stack trace, framework banner, or internal path) to an unauthenticated "
    "client.",
}
_DESCRIPTION_DEFAULT = "Automated testing confirmed this condition; see the evidence below."

_REMEDIATION: dict[str, str] = {
    "sqli": "Use parameterized queries/prepared statements for all database access; "
    "never build SQL by string concatenation with user input.",
    "sqli_blind": "Use parameterized queries/prepared statements for all database "
    "access; never build SQL by string concatenation with user input.",
    "nosqli": "Validate and type-check input before it reaches a query operator; "
    "reject operator-shaped input (e.g. objects where a scalar is expected).",
    "ldap_injection": "Escape or use a parameterized API for LDAP filter construction; "
    "never concatenate user input into a filter string.",
    "command_injection": "Avoid invoking a shell with user input; use an argument-array "
    "API and an allowlist of permitted values.",
    "xxe": "Disable external entity resolution and DTD processing in the XML parser configuration.",
    "path_traversal": "Resolve the requested path and verify it stays within an "
    "allowed base directory before use; reject any path containing traversal "
    "sequences.",
    "ssrf": "Validate outbound destinations against an allowlist of expected hosts; "
    "block requests to internal/link-local address ranges.",
    "ssti": "Never render user input as a template; use a logic-less templating mode "
    "or pass input only as template variables, never as template source.",
    "xss_reflected": "Apply context-aware output encoding to all reflected input; "
    "adopt a strict Content-Security-Policy.",
    "xss_stored": "Apply context-aware output encoding at render time for all stored "
    "user input; adopt a strict Content-Security-Policy.",
    "xss_dom": "Avoid writing untrusted data into dangerous DOM sinks "
    "(innerHTML/document.write/eval); use safe DOM APIs or a sanitizer.",
    "clickjacking": "Send X-Frame-Options: DENY (or SAMEORIGIN) or a restrictive "
    "frame-ancestors Content-Security-Policy directive on every response.",
    "csrf_missing_protection": "Issue and validate a per-session anti-CSRF token on "
    "every state-changing request, or set the session cookie's SameSite to Lax/Strict.",
    "cors_misconfig": "Return a fixed, allowlisted Origin (never a reflected wildcard) "
    "when Access-Control-Allow-Credentials is true.",
    "bola": "Enforce an ownership/authorization check on every object lookup, keyed "
    "off the authenticated identity, not the client-supplied identifier.",
    "bfla": "Enforce a role/permission check on every endpoint, not just on the ones "
    "exposed in the primary UI.",
    "idor": "Enforce an ownership/authorization check on every object lookup, keyed "
    "off the authenticated identity, not the client-supplied identifier.",
    "mass_assignment": "Bind requests through an explicit allowlist of permitted "
    "fields; never deserialize a request body directly onto an internal model.",
    "default_credentials": "Remove or force rotation of default/well-known credentials "
    "before deployment; enforce a strong-password policy.",
    "rate_limit_absence": "Add a lockout/backoff (or CAPTCHA) after a small number of "
    "failed authentication attempts per account and per source.",
    "open_redirect": "Validate a redirect target against an allowlist of in-scope "
    "destinations, or resolve it to a relative path only.",
    "web_cache_poisoning": "Include every input that affects the response in the cache "
    "key, or strip unkeyed headers before the response is generated.",
    "request_smuggling": "Ensure front-end and back-end agree on request framing "
    "(prefer HTTP/2 end-to-end, or normalize/reject ambiguous "
    "Content-Length/Transfer-Encoding combinations).",
    "subdomain_takeover": "Remove the dangling DNS record, or reclaim/reconfigure the "
    "referenced third-party resource.",
    "cloud_bucket_exposure": "Set the bucket's access policy to private and verify no "
    "public-read/public-list grant remains.",
    "jwt_forgery": "Verify the JWT signature server-side with a fixed, expected "
    "algorithm (reject 'alg: none' and algorithm confusion); never trust an "
    "unverified claim.",
    "graphql": "Disable introspection in production, enforce the same authorization "
    "checks GraphQL resolvers as REST endpoints, and cap query depth/complexity.",
    "business_logic": "Re-derive the workflow's invariant server-side at each step "
    "rather than trusting client-supplied state.",
    "race": "Serialize the check-then-act sequence (a DB transaction, lock, or "
    "idempotency key) so concurrent requests cannot both pass the check.",
    "file_upload": "Validate file type by content (not extension/Content-Type alone), "
    "store uploads outside the web root, and never execute an uploaded file.",
    "information_exposure": "Disable verbose/debug error output in production and "
    "return a generic error response instead of a stack trace or framework banner.",
}
_REMEDIATION_DEFAULT = (
    "Review the finding evidence and apply the relevant OWASP guidance for this class."
)

# severity -> (likelihood, impact) shown in each confirmed finding's Risk section.
_LIKELIHOOD_IMPACT: dict[str, tuple[str, str]] = {
    "critical": ("High", "High"),
    "high": ("High", "High"),
    "medium": ("Medium", "Medium"),
    "low": ("Low", "Low"),
}
_SEVERITY_RANK: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _wstg_for(vuln_class: str) -> tuple[str, str]:
    return _WSTG.get(vuln_class, _WSTG_DEFAULT)


def _report_card_markdown(confirmed: list[dict[str, Any]]) -> str:
    severity_counts: dict[str, int] = {}
    class_counts: dict[str, int] = {}
    for record in confirmed:
        severity = str(record["severity"]).lower() or "unknown"
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        vuln_class = str(record["vuln_class"])
        class_counts[vuln_class] = class_counts.get(vuln_class, 0) + 1
    lines = ["## Vulnerability Summary\n\n", "| Severity | Count |\n|---|---|\n"]
    for severity in ("critical", "high", "medium", "low"):
        if severity_counts.get(severity):
            lines.append(f"| {severity.capitalize()} | {severity_counts[severity]} |\n")
    if not confirmed:
        lines.append("| — | 0 |\n")
    lines.append("\n| Vulnerability Class | WSTG Reference | Count |\n|---|---|---|\n")
    for vuln_class in sorted(class_counts):
        wstg_id, wstg_name = _wstg_for(vuln_class)
        lines.append(f"| {vuln_class} | {wstg_id}: {wstg_name} | {class_counts[vuln_class]} |\n")
    return "".join(lines)


def _finding_section_markdown(
    position: int, record: dict[str, Any], *, informational: bool = False
) -> str:
    vuln_class = str(record["vuln_class"])
    severity = str(record["severity"]).lower()
    wstg_id, wstg_name = _wstg_for(vuln_class)
    provenance = record.get("provenance", {})
    affected = (
        (provenance.get("endpoint") or provenance.get("target"))
        if isinstance(provenance, Mapping)
        else None
    ) or "See evidence reference"
    description = _DESCRIPTION.get(vuln_class, _DESCRIPTION_DEFAULT)
    handles = record.get("evidence_handles", {})
    evidence_lines = "".join(f"- `{key}`: `{value}`\n" for key, value in handles.items())
    chain_lines = "".join(
        f"- Chain: {' -> '.join(path['nodes'])}\n" for path in record.get("chains", [])
    )

    heading = f"### {position}. {vuln_class} — {severity.capitalize()}"
    if not informational:
        cvss = _SEVERITY_SCORE.get(severity, "n/a")
        heading += f" (indicative CVSS {cvss})"
    parts = [
        heading + "\n\n",
        f"**WSTG Reference:** {wstg_id} — {wstg_name}  \n",
        f"**Finding ID:** `{record['finding_id']}`\n\n",
        "**Description**  \n",
        f"{description}\n\n",
    ]
    if not informational:
        likelihood, impact = _LIKELIHOOD_IMPACT.get(severity, ("Unknown", "Unknown"))
        parts.append(f"**Risk**  \n- Likelihood: {likelihood}\n- Impact: {impact}\n\n")
    parts.append(f"**Affected System**  \n`{affected}`\n\n")
    parts.append(
        f"**Tools Used**  \nReachAgent automated testing — oracle: `{record['oracle_used']}`\n\n"
    )
    parts.append("**Evidence**  \n")
    parts.append(f"- Evidence reference: `{record['evidence_ref']}`\n")
    parts.append(evidence_lines)
    parts.append(chain_lines)
    parts.append("\n")
    if not informational:
        remediation = _REMEDIATION.get(vuln_class, _REMEDIATION_DEFAULT)
        parts.append(f"**Remediation**  \n{remediation}\n\n")
    parts.append(
        f"**References**  \n- OWASP Web Security Testing Guide — {wstg_id}: {wstg_name}\n\n"
    )
    return "".join(parts)


def render_professional_report_markdown(
    graph: ReachabilityGraph,
    audit: object | None = None,
    *,
    client: ReportClient | None = None,
    operator_prompt: str | None = None,
    target: str = "",
    context: Mapping[str, object] | None = None,
) -> str:
    """Testfire-style report: exec summary, report card, per-finding sections.

    Findings with ``severity == "informational"`` (e.g. ``information_exposure``)
    are rendered in a separate, clearly-labeled section — never blended with
    oracle-confirmed vulnerabilities, the same distinction the plan draws for
    the ``known-CVE-dependency`` finding type.
    """
    index = build_evidence_index(graph, audit, context=context)
    all_findings = index["findings"]
    confirmed = [f for f in all_findings if str(f["severity"]).lower() != "informational"]
    informational = [f for f in all_findings if str(f["severity"]).lower() == "informational"]

    narrative = generate_narrative(graph, client=client, operator_prompt=operator_prompt)
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    lines = ["# ReachAgent Security Assessment Report\n\n"]
    if target:
        lines.append(f"**Target:** {target}  \n")
    lines.append(f"**Generated:** {generated_at}  \n")
    lines.append(
        f"**Confirmed findings:** {len(confirmed)} · "
        f"**Informational observations:** {len(informational)}\n\n"
    )
    lines.append("## Executive Summary\n\n")
    lines.append(f"{narrative.strip()}\n\n")
    lines.append(_report_card_markdown(confirmed))

    if confirmed:
        lines.append("\n## Confirmed Vulnerabilities\n\n")
        ordered = sorted(
            confirmed,
            key=lambda r: (
                -_SEVERITY_RANK.get(str(r["severity"]).lower(), 0),
                str(r["vuln_class"]),
            ),
        )
        for position, record in enumerate(ordered, start=1):
            lines.append(_finding_section_markdown(position, record))

    if informational:
        lines.append("\n## Informational Observations\n\n")
        lines.append(
            "Observed during testing; not confirmed vulnerabilities, listed here "
            "for completeness only.\n\n"
        )
        for position, record in enumerate(informational, start=1):
            lines.append(_finding_section_markdown(position, record, informational=True))

    if not confirmed and not informational:
        lines.append("\nNo findings were confirmed during this assessment.\n")

    return sanitize_report_markdown("".join(lines))
