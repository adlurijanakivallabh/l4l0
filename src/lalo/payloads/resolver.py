"""Payload selection, OAST substitution, and context-aware mutation."""

from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import quote

from .corpus import CORPUS, OAST_DOMAIN, OAST_URL, Payload


def select(
    vuln_class: str,
    *,
    context: str | None = None,
    include_oob: bool = True,
    corpus: Sequence[Payload] = CORPUS,
) -> list[Payload]:
    """Pick payloads for a class, optionally narrowed by injection context."""
    out = []
    for p in corpus:
        if p.vuln_class != vuln_class:
            continue
        if context is not None and p.context != context:
            continue
        if p.oob and not include_oob:
            continue
        out.append(p)
    return out


def resolve_value(
    payload: Payload, *, oast_url: str | None = None, oast_domain: str | None = None
) -> str:
    """Return the concrete payload string with OAST placeholders substituted.

    An OOB payload with no OAST target resolves to an empty string (caller should
    skip it) so a live callback URL is never faked.
    """
    value = payload.value
    if payload.oob and oast_url is None and oast_domain is None:
        return ""
    if oast_url is not None:
        value = value.replace(OAST_URL, oast_url)
    if oast_domain is not None:
        value = value.replace(OAST_DOMAIN, oast_domain)
    return value


# --- mutation (encoding + WAF-parsing-bypass variants) --------------------
def _url(value: str) -> str:
    return quote(value, safe="")


def _double_url(value: str) -> str:
    return quote(quote(value, safe=""), safe="")


def _html_entities(value: str) -> str:
    return "".join(f"&#{ord(c)};" for c in value)


def _sql_comment(value: str) -> str:
    return re.sub(r"\s+", "/**/", value)


def _case_toggle(value: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(value))


_MUTATORS = {
    "url": _url,
    "double_url": _double_url,
    "html_entities": _html_entities,
    "sql_comment": _sql_comment,
    "case_toggle": _case_toggle,
}


def mutate(value: str, techniques: Sequence[str] | None = None) -> list[tuple[str, str]]:
    """Return (technique, variant) pairs. Defaults to all mutators."""
    names = list(techniques) if techniques is not None else list(_MUTATORS)
    variants: list[tuple[str, str]] = []
    for name in names:
        mutator = _MUTATORS.get(name)
        if mutator is not None:
            variants.append((name, mutator(value)))
    return variants
