"""payload_ref resolution — template override + vendored line-locator (§9; v1.6+).

Asserts the reconciled resolver DoD (network-free; reads the checked-in
``third_party/`` snapshot, never a live fetch):

  1. A template-override ref (base slice) still slot-fills by targeted replacement,
     literal payload braces surviving.
  2. A line-locator ref ``source/relpath#Ln`` reads the correct vendored line.
  3. **Sync guard** — no dead handle (every catalog ref resolves) and no orphan
     template (every hand-authored template maps to a real catalog ref). Expressed
     against the resolvable set, not a hardcoded 1:1.
  4. **Semantic-validity** per sink over the FULL ingested set: a file_path payload
     has a traversal marker and is not a URL; a sql payload has a SQL token; an
     html_reflection payload has markup; etc. A folder-mapped line that fails its
     sink's check is a mis-ingest and is surfaced.
  5. Value/location decoupling (resolver returns the value only) and determinism.
"""

from __future__ import annotations

import re

import pytest

from reachagent.graph.nodes import SinkType
from reachagent.payloads import (
    MissingSlotError,
    PayloadLibrary,
    UnknownPayloadRefError,
    build_library,
    expected_execution_output,
    load_corpus_entries,
    required_slots,
    resolve,
    resolve_entry,
    resolves,
    template_refs,
)

# A context kit covering every template slot, so any override ref resolves.
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


def _catalog_entries() -> list:
    """Base slice + every vendored corpus entry — the full resolvable catalog."""
    return list(PayloadLibrary.from_file().all_entries()) + load_corpus_entries()


def test_expected_execution_output_accepts_simple_arithmetic() -> None:
    assert expected_execution_output("{{7*7}}") == "49"
    assert expected_execution_output("<%= 7 * 7 %>") == "49"
    assert expected_execution_output("@(1+2)") == "3"


def test_expected_execution_output_rejects_reflection_and_commands() -> None:
    assert expected_execution_output("{{7*'7'}}") is None
    assert expected_execution_output("{{config.items()}}") is None
    assert expected_execution_output("{{ self.__class__ }}") is None


def test_line_locator_rejects_snapshot_escape() -> None:
    with pytest.raises(UnknownPayloadRefError, match="escapes vendored snapshot"):
        resolve("PayloadsAllTheThings/../seclists-snapshot/SOURCE.txt#L1")
    with pytest.raises(UnknownPayloadRefError, match="escapes vendored snapshot"):
        resolve("PayloadsAllTheThings//etc/passwd#L1")


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("sqli/blind/timing-sleep-paired", "' AND SLEEP(5)-- -"),
        ("xss/reflected/script-tag-canary", "<script>CANARY42</script>"),
        ("mass-assignment/admin-flag-injection", '{"isAdmin":true}'),
        ("bola/object-id-substitution", "2"),
    ],
)
def test_template_override_slot_fills(ref, expected) -> None:
    assert resolve(ref, **_KIT) == expected


def test_template_literal_braces_survive() -> None:
    # The OOB template carries UNC backslashes + literal text; slot-fill leaves the
    # non-slot characters intact (targeted replacement, not str.format).
    out = resolve("sqli/blind/oob-dns-exfil", **_KIT)
    assert "n1.c.example" in out
    assert out.startswith("'; EXEC master..xp_dirtree")


def test_missing_required_slot_raises() -> None:
    with pytest.raises(MissingSlotError):
        resolve("sqli/blind/timing-sleep-paired")  # {sleep} required, not supplied


def test_required_slots_of_template_and_locator() -> None:
    assert required_slots("sqli/blind/timing-sleep-paired") == {"sleep"}
    # A line-locator ref is static — no slots required.
    locator = next(e.payload_ref for e in load_corpus_entries())
    assert required_slots(locator) == frozenset()


# -- 2. line-locator reads the correct vendored line --------------------------


def test_line_locator_reads_the_exact_source_line() -> None:
    # Build a locator for a known file+line and assert resolve() returns that exact
    # vendored line — read straight off disk, network-free.
    from pathlib import Path

    root = Path(__file__).parent.parent.parent / "third_party" / "seclists-snapshot"
    rel = "Fuzzing/Databases/SQLi/quick-SQLi.txt"
    lines = (root / rel).read_text(encoding="utf-8").splitlines()
    ref = f"SecLists/{rel}#L1"
    assert resolve(ref) == lines[0]
    # A mid-file line, too.
    ref5 = f"SecLists/{rel}#L5"
    assert resolve(ref5) == lines[4]


def test_line_locator_out_of_range_is_dead_handle() -> None:
    with pytest.raises(UnknownPayloadRefError, match="out of range"):
        resolve("SecLists/Fuzzing/Databases/SQLi/quick-SQLi.txt#L999999")


def test_line_locator_unknown_source_is_dead_handle() -> None:
    with pytest.raises(UnknownPayloadRefError, match="unknown source"):
        resolve("NotASource/foo/bar.txt#L1")


def test_line_locator_missing_file_is_dead_handle() -> None:
    with pytest.raises(UnknownPayloadRefError, match="no vendored file"):
        resolve("SecLists/Fuzzing/does-not-exist.txt#L1")


def test_unknown_ref_neither_template_nor_locator_raises() -> None:
    with pytest.raises(UnknownPayloadRefError):
        resolve("just-a-bare-handle-no-line")


# -- 3. sync guard: no dead handle, no orphan template ------------------------


def test_no_dead_handle_every_catalog_ref_resolves() -> None:
    # Every ref in the merged catalog resolves — via a template override OR a
    # vendored line-locator read. No dead handles under bulk ingest.
    unresolved = [e.payload_ref for e in _catalog_entries() if not resolves(e.payload_ref)]
    assert unresolved == [], f"{len(unresolved)} dead handle(s), e.g. {unresolved[:3]}"


def test_no_orphan_template_every_template_maps_to_a_real_ref() -> None:
    # Every hand-authored template ref is a real catalog ref (no orphan template
    # left pointing at a deleted entry). Expressed against the resolvable set.
    catalog = {e.payload_ref for e in _catalog_entries()}
    orphans = [ref for ref in template_refs() if ref not in catalog]
    assert orphans == [], f"orphan template(s): {orphans}"


# -- 4. semantic validity per sink over the FULL ingested set -----------------


def _has_url(value: str) -> bool:
    return "http://" in value.lower() or "https://" in value.lower()


def test_ingested_payload_is_semantically_valid_for_its_sink() -> None:
    # Resolve every corpus entry to its value and assert it is plausible for its
    # sink. A folder-mapped line that fails its sink's check is a mis-ingest — this
    # is the guard that surfaces one (the same spirit as the 2b {target} fix).
    offenders: list[str] = []
    for entry in load_corpus_entries():
        value = resolve_entry(entry, **_KIT)
        sink = entry.inferred_sink_type
        ok = True
        if sink is SinkType.FILE_PATH:
            ok = bool(
                re.search(r"\.\./|\.\.\\|\.\.%2f|%2e%2e|/etc/|win\.ini|boot\.ini|^/", value, re.I)
            )
            ok = ok and not _has_url(value)
        elif sink is SinkType.SQL:
            # Real SQLi tautologies include bare "or 1=1" / "|| 1==1" (no quote), so
            # a comparison/boolean operator counts alongside quotes/keywords/comments.
            ok = bool(
                re.search(
                    r"['\"]|union|select|sleep|benchmark|waitfor|randomblob|\bor\b|\band\b|--|#|;|=|\|\|",
                    value,
                    re.I,
                )
            )
        elif sink is SinkType.HTML_REFLECTION:
            ok = "<" in value or bool(
                re.search(r"alert|prompt|confirm|onerror|onload|javascript:", value, re.I)
            )
        elif sink is SinkType.NOSQL:
            ok = "$" in value or "{" in value or "sleep(" in value.lower()
        elif sink is SinkType.SHELL:
            # A command separator, a substitution, a newline injector, or a bare
            # command token (``id`` may be newline-wrapped as ``\nid\n``).
            ok = bool(re.search(r"[;&|`]|\$\(|%0a|\\n|sleep|nslookup|ping|cat|\bid\b", value, re.I))
        if not ok:
            offenders.append(f"{entry.payload_ref} → {value!r}")
    assert offenders == [], f"{len(offenders)} mis-ingested payload(s), e.g. {offenders[:5]}"


# -- 5. value/location decoupling + determinism -------------------------------


def test_resolver_adds_no_framing_returns_the_raw_value() -> None:
    # Value/location decoupling: the resolver returns the payload VALUE verbatim —
    # it never wraps a line in a location (no "key=" prefix, no query/header
    # framing it added). Proven at the source: a line-locator resolves to EXACTLY
    # the vendored file line, byte-for-byte. (A payload's own content may embed a
    # ':' or '='; that is the payload, not framing the resolver introduced.)
    from pathlib import Path

    tp = Path(__file__).parent.parent.parent / "third_party"
    for entry in load_corpus_entries()[:2000]:  # representative fast slice
        value = resolve_entry(entry)  # no kit — locator lines are static
        source, rest = entry.payload_ref.split("/", 1)
        relpath, line_no = rest.rsplit("#L", 1)
        root = tp / (
            "seclists-snapshot" if source == "SecLists" else "payloadsallthethings-snapshot"
        )
        raw = (root / relpath).read_text(encoding="utf-8").splitlines()[int(line_no) - 1]
        assert value == raw  # resolver added nothing — value is the raw line


def test_resolution_is_deterministic() -> None:
    entries = load_corpus_entries()[:200]
    first = [resolve_entry(e, **_KIT) for e in entries]
    second = [resolve_entry(e, **_KIT) for e in entries]
    assert first == second


def test_base_slice_and_locator_both_resolve_via_build_library() -> None:
    lib = build_library()
    # A base-slice sql template ref and a corpus sql locator both resolve.
    sql_entries = lib.get_payloads("sqli", SinkType.SQL)
    assert sql_entries
    for e in sql_entries[:50]:
        assert resolve_entry(e, **_KIT)
