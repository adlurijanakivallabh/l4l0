"""Bounded encoding-variant expansion — tag-preserving, no new family (plan §9).

D3 deferred honest: path_traversal/sqli/xss payloads may be WAF-filtered in one
encoding but not another. Variants preserve source (vuln_class, sink, oracle,
graph_edge) so the oracle routing is unchanged — breadth, not a seventh family.
"""

from __future__ import annotations

import hashlib
import logging
import re
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import replace

from reachagent.graph.nodes import SinkType
from reachagent.oracles import OracleMechanism
from reachagent.payloads.library import PayloadEntry

_log = logging.getLogger(__name__)

_MAX_VARIANTS_PER_ENTRY = 2
MAX_MUTATIONS_PER_PARENT = 4
_VARIANT_CLASSES = frozenset({"sqli", "sqli_blind", "xss_reflected", "command_injection"})
_MUTATION_KINDS = frozenset({"url", "double-url", "delimiter", "casing", "wrapper"})

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


class MutationCompatibilityError(ValueError):
    """Raised when a child no longer preserves its parent routing contract."""


def _semantic_compatible(entry: PayloadEntry, value: str) -> bool:
    """Cheap decoded-shape guard; deterministic oracle remains the confirmer."""
    decoded = urllib.parse.unquote(value)
    sink = entry.inferred_sink_type
    if sink is SinkType.SQL:
        return bool(
            re.search(
                r"['\"]|union|select|sleep|benchmark|waitfor|\bor\b|\band\b|--|#|;|=|\|\|",
                decoded,
                re.I,
            )
        )
    if sink is SinkType.NOSQL:
        return "$" in decoded or "{" in decoded or "sleep(" in decoded.lower()
    if sink is SinkType.HTML_REFLECTION:
        return "<" in decoded or bool(
            re.search(r"alert|prompt|confirm|onerror|onload|javascript:", decoded, re.I)
        )
    if sink is SinkType.SHELL:
        return bool(re.search(r"[;&|`]|\$\(|sleep|nslookup|ping|\bid\b", decoded, re.I))
    if sink is SinkType.FILE_PATH:
        return bool(re.search(r"\.\./|%2e%2e|/etc/|win\.ini|boot\.ini|^/", decoded, re.I))
    if sink is SinkType.LDAP:
        return bool(re.search(r"[()|*&!/]|%[0-9a-f]{2}", decoded, re.I))
    if sink is SinkType.TEMPLATE:
        from reachagent.payloads.payload_resolver import expected_execution_output

        return expected_execution_output(decoded) is not None
    if sink is None:
        # A small number of OOB stimuli are intentionally sink-less because
        # their deterministic oracle is the callback itself, not a reflected
        # injection sink.  Keep the family/oracle fixed and require its marker.
        if entry.oracle_type is not OracleMechanism.OOB_CALLBACK:
            return False
        if entry.vuln_class == "sqli_blind":
            return "." in decoded and ("http" in decoded.lower() or "system" in decoded.lower())
        if entry.vuln_class == "command_injection":
            return "jndi:" in decoded.lower() or "nslookup" in decoded.lower()
        return False
    return False


def validate_mutation(parent: PayloadEntry, child: PayloadEntry, value: str) -> bool:
    """Enforce parent, sink, oracle, graph-edge, and semantic preservation."""
    if child.parent_ref != parent.payload_ref:
        raise MutationCompatibilityError("mutation parent_ref does not match the parent")
    if child.vuln_class != parent.vuln_class:
        raise MutationCompatibilityError("mutation changed vulnerability class")
    if child.inferred_sink_type != parent.inferred_sink_type:
        raise MutationCompatibilityError("mutation changed inferred sink")
    if child.oracle_type != parent.oracle_type:
        raise MutationCompatibilityError("mutation changed oracle family")
    if child.graph_edge_on_success != parent.graph_edge_on_success:
        raise MutationCompatibilityError("mutation changed graph edge")
    if child.mutation_kind not in _MUTATION_KINDS:
        raise MutationCompatibilityError("unknown mutation kind")
    if child.mutation_index is None or not 1 <= child.mutation_index <= MAX_MUTATIONS_PER_PARENT:
        raise MutationCompatibilityError("mutation exceeds per-parent limit")
    if not _semantic_compatible(parent, value):
        raise MutationCompatibilityError("mutation value is incompatible with the parent sink")
    return True


def _mutation_values(entry: PayloadEntry, value: str) -> list[tuple[str, str]]:
    """Return conservative, class-aware transformations (never arbitrary text)."""
    out = _variants_for(value)
    sink = entry.inferred_sink_type
    if sink is SinkType.SQL and " " in value:
        delimiter = value.replace(" ", "/**/")
        if delimiter != value:
            out.append(("delimiter", delimiter))
    if sink in {SinkType.SQL, SinkType.HTML_REFLECTION}:
        if sink is SinkType.HTML_REFLECTION:
            cased = re.sub(
                r"(?i)(script|svg|img|iframe|onerror|onload|onfocus)",
                lambda match: match.group(0).swapcase(),
                value,
            )
        else:
            cased = "".join(
                char.upper() if index % 2 == 0 else char.lower() for index, char in enumerate(value)
            )
        if cased != value:
            out.append(("casing", cased))
    if sink is SinkType.HTML_REFLECTION and value:
        wrapped = f"<svg data-reachagent='{value}'>"
        out.append(("wrapper", wrapped))
    unique: list[tuple[str, str]] = []
    seen: set[str] = {value}
    for kind, candidate in out:
        if kind not in _MUTATION_KINDS or candidate in seen:
            continue
        seen.add(candidate)
        unique.append((kind, candidate))
    return unique[:MAX_MUTATIONS_PER_PARENT]


def expand_payload_mutations(
    entries: Sequence[PayloadEntry],
    *,
    max_per_parent: int = MAX_MUTATIONS_PER_PARENT,
    requested: Mapping[str, Sequence[str]] | None = None,
    slot_kit: Mapping[str, object] | None = None,
) -> list[PayloadEntry]:
    """Expand entries with bounded parent-preserving mutations.

    ``requested`` is an optional LLM proposal keyed by parent reference.  The
    fixed validator still intersects kinds with the local allowlist and the
    semantic checks below; an unknown parent or kind produces no child.
    """
    if not 0 <= max_per_parent <= MAX_MUTATIONS_PER_PARENT:
        raise ValueError("max_per_parent must be between 0 and the hard mutation limit")
    expanded: list[PayloadEntry] = []
    seen_refs: set[str] = set()
    for entry in entries:
        if entry.payload_ref in seen_refs:
            continue
        seen_refs.add(entry.payload_ref)
        expanded.append(entry)
        if max_per_parent == 0 or entry.parent_ref is not None:
            continue
        if entry.vuln_class not in _VARIANT_CLASSES:
            continue
        try:
            from reachagent.payloads.payload_resolver import resolve_entry

            raw = resolve_entry(entry, **dict(slot_kit or {}))
        except Exception as exc:  # noqa: BLE001 - an unresolved parent cannot mutate
            _log.debug("payload mutation parent unresolved: %s", exc)
            continue
        values = _mutation_values(entry, raw)
        wanted = None if requested is None else requested.get(entry.payload_ref)
        if wanted is not None:
            wanted_set = {str(kind).strip().lower() for kind in wanted}
            values = [item for item in values if item[0] in wanted_set]
        parent_limit = min(max_per_parent, MAX_MUTATIONS_PER_PARENT)
        for index, (kind, candidate) in enumerate(values[:parent_limit], start=1):
            digest = hashlib.sha256(candidate.encode("utf-8", errors="replace")).hexdigest()[:8]
            child_ref = f"{entry.payload_ref}#mut-{kind}-{index}-{digest}"
            child = replace(
                entry,
                context=f"{entry.context} [{kind}]",
                payload_ref=child_ref,
                parent_ref=entry.payload_ref,
                mutation_kind=kind,
                mutation_index=index,
            )
            try:
                validate_mutation(entry, child, candidate)
            except MutationCompatibilityError:
                continue
            _VARIANT_CACHE[child_ref] = candidate
            expanded.append(child)
    return expanded


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
        for index, (suffix, vval) in enumerate(_variants_for(raw), start=1):
            vref = f"{entry.payload_ref}#{suffix}"
            child = PayloadEntry(
                vuln_class=entry.vuln_class,
                context=f"{entry.context} [{suffix}]",
                inferred_sink_type=entry.inferred_sink_type,
                oracle_type=entry.oracle_type,
                payload_ref=vref,
                graph_edge_on_success=entry.graph_edge_on_success,
                content_type=entry.content_type,
                method=entry.method,
                framework=entry.framework,
                auth_state=entry.auth_state,
                location=entry.location,
                parent_ref=entry.payload_ref,
                mutation_kind=suffix,
                mutation_index=index,
            )
            try:
                validate_mutation(entry, child, vval)
            except MutationCompatibilityError:
                continue
            _VARIANT_CACHE[vref] = vval
            expanded.append(child)
    return expanded
