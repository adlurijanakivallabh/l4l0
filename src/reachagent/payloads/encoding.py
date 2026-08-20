"""Bounded encoding-variant expansion — tag-preserving, no new family (plan §9).

D3 deferred honest: path_traversal/sqli/xss payloads may be WAF-filtered in one
encoding but not another. Variants preserve source (vuln_class, sink, oracle,
graph_edge) so the oracle routing is unchanged — breadth, not a seventh family.
"""

from __future__ import annotations

import urllib.parse

from reachagent.payloads.library import PayloadEntry

_MAX_VARIANTS_PER_ENTRY = 2
_VARIANT_CLASSES = frozenset({"sqli", "sqli_blind", "xss_reflected", "command_injection"})

_VARIANT_CACHE: dict[str, str] = {}


def variant_value(payload_ref: str) -> str | None:
    """Fireable value for a synthetic variant ref, or None if not a variant."""
    return _VARIANT_CACHE.get(payload_ref)


def _url_encode(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def _double_url_encode(value: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(value, safe=""), safe="")


def _variants_for(value: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    url = _url_encode(value)
    if url != value:
        out.append(("url", url))
    dbl = _double_url_encode(value)
    if dbl != value and dbl != url:
        out.append(("double-url", dbl))
    return out[:_MAX_VARIANTS_PER_ENTRY]


def expand_encoding_variants(entries: list[PayloadEntry]) -> list[PayloadEntry]:
    """Bounded variant expansion — synthetic refs via _VARIANT_CACHE.

    Only _VARIANT_CLASSES are expanded. Values come from resolve_entry so
    template/line-locator are already fireable. Each variant reuses source tags.
    """
    from reachagent.payloads.payload_resolver import resolve_entry

    expanded: list[PayloadEntry] = []
    for entry in entries:
        expanded.append(entry)
        if entry.vuln_class not in _VARIANT_CLASSES:
            continue
        try:
            raw = resolve_entry(entry)
        except Exception:  # noqa: BLE001, S112 — broken entry skipped
            continue
        for suffix, vval in _variants_for(raw):
            vref = f"{entry.payload_ref}#{suffix}"
            _VARIANT_CACHE[vref] = vval
            expanded.append(
                PayloadEntry(
                    vuln_class=entry.vuln_class,
                    context=f"{entry.context} [{suffix}]",
                    inferred_sink_type=entry.inferred_sink_type,
                    oracle_type=entry.oracle_type,
                    payload_ref=vref,
                    graph_edge_on_success=entry.graph_edge_on_success,
                )
            )
    return expanded
