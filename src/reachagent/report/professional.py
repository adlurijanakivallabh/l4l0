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
    evidence_snippet,
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
    "credential_reuse": ("WSTG-ATHN-02", "Testing for Default Credentials"),
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
    "prototype_pollution": ("WSTG-CLNT", "Client-Side Testing (Prototype Pollution)"),
}
_WSTG_DEFAULT: tuple[str, str] = ("WSTG-INFO", "Information Gathering")

# vuln_class -> CWE id. Only well-established, confidently-known MITRE CWE
# entries — same "never a fabricated/guessed id" discipline as _WSTG above.
# A class with no single well-established specific match (subdomain_takeover,
# cloud_bucket_exposure, graphql, web_cache_poisoning — each spans multiple
# underlying weaknesses with no one dedicated CWE) cites the generic
# protection-mechanism-failure category via _CWE_DEFAULT rather than guess.
_CWE: dict[str, str] = {
    "sqli": "CWE-89",
    "sqli_blind": "CWE-89",
    "nosqli": "CWE-943",
    "ldap_injection": "CWE-90",
    "command_injection": "CWE-78",
    "xxe": "CWE-611",
    "path_traversal": "CWE-22",
    "ssrf": "CWE-918",
    "ssti": "CWE-1336",
    "xss_reflected": "CWE-79",
    "xss_stored": "CWE-79",
    "xss_dom": "CWE-79",
    "clickjacking": "CWE-1021",
    "csrf_missing_protection": "CWE-352",
    "cors_misconfig": "CWE-942",
    "bola": "CWE-639",
    "bfla": "CWE-862",
    "idor": "CWE-639",
    "mass_assignment": "CWE-915",
    "default_credentials": "CWE-1392",
    "credential_reuse": "CWE-1392",
    "rate_limit_absence": "CWE-307",
    "open_redirect": "CWE-601",
    "request_smuggling": "CWE-444",
    "jwt_forgery": "CWE-347",
    "business_logic": "CWE-841",
    "race": "CWE-362",
    "file_upload": "CWE-434",
    "information_exposure": "CWE-200",
    "prototype_pollution": "CWE-1321",
}
_CWE_DEFAULT = "CWE-693"  # Protection Mechanism Failure — a generic, defensible fallback

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
    "credential_reuse": "A username/password pair captured from one in-scope host "
    "during this engagement also authenticates on a different in-scope host, "
    "confirming the same credential is valid across independent services.",
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
    "prototype_pollution": "Client-side script merges attacker-controlled query "
    "parameters into an object without guarding __proto__/constructor.prototype, "
    "polluting Object.prototype for the whole page.",
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
    "credential_reuse": "Rotate the shared credential immediately; enforce unique "
    "per-service credentials (or federated SSO with per-service authorization) so a "
    "single leaked secret cannot grant access across independent systems.",
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
    "prototype_pollution": "Use Object.create(null) or a Map for any object built "
    "from user input, or freeze/guard Object.prototype; reject __proto__/constructor "
    "keys before any recursive merge.",
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


def _cwe_for(vuln_class: str) -> str:
    return _CWE.get(vuln_class, _CWE_DEFAULT)


def vuln_class_context(vuln_class: str, severity: str = "") -> dict[str, str]:
    """The deterministic per-class narrative context — description, remediation, WSTG
    reference, CVSS/likelihood/impact — used by every finding section in this report AND
    (Build Order v2, GUI-detail workstream) by the GUI's live finding cards, so both
    surfaces show the exact same reviewed, non-generated text instead of a bare field
    dump. No new data: every value here already backed ``_finding_section_markdown``.
    """
    wstg_id, wstg_name = _wstg_for(vuln_class)
    severity_key = severity.lower()
    likelihood, impact = _LIKELIHOOD_IMPACT.get(severity_key, ("", ""))
    return {
        "wstg_id": wstg_id,
        "wstg_name": wstg_name,
        "cwe_id": _cwe_for(vuln_class),
        "description": _DESCRIPTION.get(vuln_class, _DESCRIPTION_DEFAULT),
        "remediation": _REMEDIATION.get(vuln_class, _REMEDIATION_DEFAULT),
        "cvss": _SEVERITY_SCORE.get(severity_key, ""),
        "likelihood": likelihood,
        "impact": impact,
    }


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


def methodology_markdown(graph: ReachabilityGraph, *, target: str = "") -> str:
    """A real Methodology section — built from actual scan facts, never LLM prose.

    Professional pentest reports always carry a Methodology section (scope, approach,
    proof standard); ReachAgent's had none, both here and in the LLM-full-authority
    report. Built deterministically from the graph so it can never drift from what
    the scan actually did — the same "ground truth the LLM cannot override" discipline
    already used for confirmed findings. Appended verbatim after the LLM's own text in
    ``report/llm_full_report.py`` for the exact same reason.
    """
    hosts = graph.hosts()
    endpoints = graph.endpoints()
    param_count = sum(len(graph.parameters_of(ep_id)) for ep_id, _ep in endpoints)
    confirmed_count = len(graph.findings())
    suspected = graph.suspected_findings()
    llm_leads = sum(1 for _sid, s in suspected if s.source == "llm_judgment")
    tool_leads = len(suspected) - llm_leads
    whitebox = bool(graph.static_advisories() or graph.source_files() or graph.secrets())

    lines = [
        "\n## Methodology\n\n",
        f"**Scope:** {target or '(target not recorded)'}"
        + (f" — {len(hosts)} host(s) tested" if hosts else "")
        + ".\n\n",
        "**Approach:** an autonomous, role-bounded agent performed reconnaissance and "
        "surface mapping, then tested each applicable vulnerability class against the "
        "discovered surface, read-only-first — no state-changing request was sent until "
        "the read-only case was confirmed safe.\n\n",
        "**Proof standard:** a finding is reported as *Confirmed* only after an "
        "independent, deterministic oracle (one of six mechanism families — structural, "
        "differential, timing-statistical, execution-confirmation, out-of-band callback, "
        "or business-rule invariant) verified it against the target's actual response. "
        "LLM judgment is used to prioritize testing and to surface additional leads for "
        "human review, but never to decide that a finding is confirmed — an item the "
        "oracle did not independently verify is always listed separately, in its own "
        "clearly-labeled review-only section below, never blended into the confirmed "
        "count.\n\n",
        f"**Coverage:** {len(endpoints)} endpoint(s) and {param_count} parameter(s) "
        f"mapped; {confirmed_count} confirmed finding(s).",
    ]
    if llm_leads:
        lines.append(
            f" An LLM surface-judgment pass additionally flagged {llm_leads} lead(s) "
            "for manual review (Suspected tier)."
        )
    if tool_leads:
        lines.append(
            f" {tool_leads} additional lead(s) came from a signal-gated scanner claim "
            "the oracle could not independently re-confirm."
        )
    if whitebox:
        lines.append(
            " An optional white-box (source-available) pass also contributed static "
            "observations, listed in their own section below."
        )
    lines.append("\n")
    return "".join(lines)


def _evidence_snippet_markdown(snippet: dict[str, Any]) -> str:
    """Render the real captured proof (v2 Phase 6 Stage E1) as markdown — a fenced
    block per body projection, distinct from the opaque handle refs listed above it.
    ``~~~`` fences (not backticks) since a real target's response could itself
    contain a literal ``` sequence that would otherwise break out of the block.
    """
    lines: list[str] = []
    if snippet.get("baseline_body_projection") or snippet.get("probe_body_projection"):
        if snippet.get("baseline_body_projection"):
            lines.append(
                f"**Baseline response:**\n~~~\n{snippet['baseline_body_projection']}\n~~~\n"
            )
        if snippet.get("probe_body_projection"):
            lines.append(f"**Probe response:**\n~~~\n{snippet['probe_body_projection']}\n~~~\n")
    elif snippet.get("body_projection"):
        lines.append(f"**Response evidence:**\n~~~\n{snippet['body_projection']}\n~~~\n")
    headers = snippet.get("headers")
    if headers:
        lines.append("**Decisive response headers:**\n")
        lines.extend(f"- `{name}`: `{value}`\n" for name, value in headers)
    return "".join(lines) + ("\n" if lines else "")


def _finding_section_markdown(
    position: int, record: dict[str, Any], *, informational: bool = False
) -> str:
    vuln_class = str(record["vuln_class"])
    severity = str(record["severity"]).lower()
    ctx = vuln_class_context(vuln_class, severity)
    wstg_id, wstg_name = ctx["wstg_id"], ctx["wstg_name"]
    provenance = record.get("provenance", {})
    affected = (
        (provenance.get("endpoint") or provenance.get("target"))
        if isinstance(provenance, Mapping)
        else None
    ) or "See evidence reference"
    description = ctx["description"]
    handles = record.get("evidence_handles", {})
    evidence_lines = "".join(f"- `{key}`: `{value}`\n" for key, value in handles.items())
    chain_lines = "".join(
        f"- Chain: {' -> '.join(path['nodes'])}\n" for path in record.get("chains", [])
    )

    heading = f"### {position}. {vuln_class} — {severity.capitalize()}"
    if not informational:
        cvss = ctx["cvss"] or "n/a"
        heading += f" (indicative CVSS {cvss})"
    parts = [
        heading + "\n\n",
        f"**WSTG Reference:** {wstg_id} — {wstg_name}  \n",
        f"**CWE:** {ctx['cwe_id']}  \n",
        f"**Finding ID:** `{record['finding_id']}`\n\n",
        "**Description**  \n",
        f"{description}\n\n",
    ]
    if not informational:
        likelihood = ctx["likelihood"] or "Unknown"
        impact = ctx["impact"] or "Unknown"
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
    snippet = evidence_snippet(record.get("metadata", {}))
    if snippet:
        parts.append(_evidence_snippet_markdown(snippet))
    if not informational:
        parts.append(f"**Remediation**  \n{ctx['remediation']}\n\n")
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
    lines.append(methodology_markdown(graph, target=target))
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

    suspected_section = _suspected_section_markdown(graph)
    if suspected_section:
        lines.append(suspected_section)

    whitebox_section = _whitebox_section_markdown(graph)
    if whitebox_section:
        lines.append(whitebox_section)

    return sanitize_report_markdown("".join(lines))


def _suspected_section_markdown(graph: ReachabilityGraph) -> str:
    """Build Order v2 W2 — the "Suspected / Unconfirmed" tier: leads the agent probed but
    that no deterministic oracle confirmed (oracle ran and returned negative, or a
    signal-gated scanner claimed something the oracle couldn't re-prove). Rendered ONLY if
    any exist. Always visibly, permanently separate from the confirmed-findings section:
    nothing here came from a confirmed ``run_oracle`` verdict, so it is never blended in and
    never counted in the confirmed severity stats.
    """
    suspected = graph.suspected_findings()
    if not suspected:
        return ""
    lines = [
        "\n## Suspected / Unconfirmed (not oracle-verified)\n\n",
        "The agent probed the following but a deterministic oracle did **not** confirm them — "
        "either the oracle ran and returned negative, or an external scanner (nuclei/sqlmap/"
        "dalfox) flagged it and the oracle couldn't independently re-prove it. **These are NOT "
        "findings.** They are leads for manual review: a real bug the oracle missed, or a "
        "false positive the oracle correctly rejected. Verify by hand before reporting.\n\n",
        "| Vuln class | Endpoint | Location | Source | Why unconfirmed |\n|---|---|---|---|---|\n",
    ]

    def esc(value: object) -> str:
        return str(value).replace("|", "\\|").replace("\n", " ")[:200]

    for _sid, s in sorted(
        suspected, key=lambda item: (item[1].vuln_class, item[1].endpoint, item[1].location)
    ):
        lines.append(
            f"| {esc(s.vuln_class)} | {esc(s.endpoint)} | {esc(s.location)} | "
            f"{esc(s.source)} | {esc(s.reason)} |\n"
        )
    return "".join(lines)


def _whitebox_section_markdown(graph: ReachabilityGraph) -> str:
    """Build Order 7 — static/source-level observations from an optional
    white-box repo scan. Rendered ONLY if the graph has any such facts (a
    scan with no ``repo_path`` supplied has none, and this section is
    entirely absent, not an empty header). Always visibly, permanently
    separate from both the confirmed-findings and informational-observations
    sections above: nothing here ever came from ``run_oracle``.
    """
    advisories = graph.static_advisories()
    source_files = graph.source_files()
    secrets = graph.secrets()
    if not advisories and not source_files and not secrets:
        return ""

    lines = [
        "\n## Static Analysis (White-Box — Unconfirmed Reachability)\n\n",
        "The following come from an optional source-repo scan (semgrep/"
        "TruffleHog/dependency-manifest analysis), not the live black-box "
        "test above. **None of these are oracle-confirmed findings** — a "
        "known-CVE dependency match is a manifest version against a public "
        "advisory, not a behavioral confirmation that the vulnerable code "
        "path is reachable from the live application; a SAST hit is a "
        "pattern match, not a proven exploit. Treat this section as "
        "prioritization input for further live testing, not as a "
        "conclusion.\n\n",
    ]

    if advisories:
        lines.append("### Known-Vulnerable Dependencies\n\n")
        lines.append(
            "| Package | Version | CVE | CVSS | EPSS | Manifest |\n|---|---|---|---|---|---|\n"
        )
        for _aid, advisory in sorted(
            advisories, key=lambda item: (-(item[1].cvss_score or 0.0), item[1].package)
        ):
            cvss = f"{advisory.cvss_score:.1f}" if advisory.cvss_score is not None else "n/a"
            epss = f"{advisory.epss_score:.3f}" if advisory.epss_score is not None else "n/a"
            lines.append(
                f"| {advisory.package} | {advisory.version} | {advisory.cve_id} | "
                f"{cvss} | {epss} | {advisory.manifest} |\n"
            )
        lines.append("\n")

    if source_files:
        lines.append("### Static Analysis Hits (SAST)\n\n")
        lines.append("| File | Line | Rule | Severity | Message |\n|---|---|---|---|---|\n")
        for _fid, source_file in sorted(
            source_files, key=lambda item: (item[1].path, item[1].line)
        ):
            message = source_file.message.replace("|", "\\|")
            lines.append(
                f"| {source_file.path} | {source_file.line} | {source_file.rule_id} | "
                f"{source_file.severity} | {message} |\n"
            )
        lines.append("\n")

    if secrets:
        lines.append("### Detected Secrets\n\n")
        lines.append(
            "Locations only — the secret value itself is never captured anywhere in this tool.\n\n"
        )
        lines.append("| File | Line | Detector | Verified |\n|---|---|---|---|\n")
        for _sid, secret in sorted(secrets, key=lambda item: (item[1].path, item[1].line)):
            lines.append(
                f"| {secret.path} | {secret.line} | {secret.detector} | "
                f"{'yes' if secret.verified else 'no'} |\n"
            )
        lines.append("\n")

    return "".join(lines)
