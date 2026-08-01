"""Tagged corpus ingest from vendored PayloadsAllTheThings + SecLists (§9/§12; v1.6+).

**Source shape: pinned snapshot of real upstream payload files**, vendored under
``third_party/{source}-snapshot/`` (see ``docs/vendored-corpora.md`` and each
snapshot's ``SOURCE.txt``). Only the machine-readable one-per-line payload files
under the mapped folders are vendored — never the full multi-GB repos. Fetching /
re-pinning is dev setup; **detection is network-free** (§9): this loader only ever
reads the checked-in files off disk.

**What gets ingested.** Real upstream payload lines, one ``PayloadEntry`` per
acceptable line:

  * **vuln_class + inferred_sink_type** — from the file's folder path via
    ``_FOLDER_MAP`` (SQLi→sqli/sql, XSS→xss_reflected/html_reflection,
    Command-Injection→command_injection/shell, LFI→path_traversal/file_path,
    NoSQL→nosqli/nosql). A file in a folder no token maps is **skipped and logged**,
    never guessed.
  * **oracle_type** — the tag the upstream repos do NOT carry; this is ReachAgent's
    value-add. Assigned by an ordered regex table (``_ORACLE_RULES``) over the
    payload line, first match wins: ``SLEEP(``/``WAITFOR``/``pg_sleep``/
    ``BENCHMARK``→timing_statistical; DNS/callback markers (``nslookup``/
    ``interactsh``/``burpcollab``/``dnslog``/``oastify``)→oob_callback; execution
    markup (``<script``/``onerror=``/SSTI ``{{…}}``)→execution_confirmation;
    traversal (``../``/``..%2f``)→structural; else the folder's default
    (differential for SQLi/NoSQL).
  * **graph_edge_on_success** — the folder's class default (auth-bypass classes →
    derived_credential, else enables).
  * **payload_ref** — ``source/relpath#Ln``, a stable line locator. The resolver
    reads the actual string from the vendored line on demand; raw exploit strings
    never live in the catalog (§9).

A line whose tags map to an unknown sink / unknown §7 oracle / non-§6 edge raises
``PayloadLibraryError`` — the same strictness as the hand-authored slice: a
mis-tag fails loudly, never silently misroutes. Blank / comment / junk lines
(and lines that fail a per-sink acceptance predicate) are **skipped and counted**,
not rejected.

**Best-effort tagging, but never a false finding.** The regex oracle-tagging is a
heuristic — a payload could be mis-tagged to the wrong §7 family. That cannot
produce a false finding: a corpus payload is only ever *stimulus*; every one still
routes through ``run_oracle``, and a ``Finding`` is written only on an independent
``is_violation`` verdict (the same safety net that governs the signal-gated tools,
§9). Corpora expand the payload *set*; they never expand what counts as confirmed.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from reachagent.graph.edges import FindingEdge, StructuralEdge
from reachagent.graph.nodes import SinkType
from reachagent.oracles import OracleMechanism
from reachagent.payloads.library import (
    PayloadEntry,
    PayloadLibrary,
    PayloadLibraryError,
)

_log = logging.getLogger(__name__)

# Vendored snapshot roots, keyed by upstream source name. Each must carry a
# SOURCE.txt (pinned commit SHA + provenance). Detection reads these off disk;
# fetching them is dev setup only (§9 — network-free detection).
_SNAPSHOT_ROOT = Path(__file__).parent.parent.parent.parent / "third_party"
_SNAPSHOTS: dict[str, Path] = {
    "PayloadsAllTheThings": _SNAPSHOT_ROOT / "payloadsallthethings-snapshot",
    "SecLists": _SNAPSHOT_ROOT / "seclists-snapshot",
}

# Real §6 graph edges an entry may declare. A folder default that isn't a real
# edge is a wiring bug — caught loudly at ingest, never a phantom edge on confirm.
_KNOWN_EDGES: frozenset[str] = frozenset(
    {*(e.value for e in StructuralEdge), *(e.value for e in FindingEdge)}
)


@dataclass(frozen=True)
class _FolderClass:
    """Folder token → the class/sink/oracle-default/success-edge it ingests as."""

    vuln_class: str
    sink: SinkType
    default_oracle: OracleMechanism
    success_edge: str


# Folder path token → class mapping. A vendored file is ingested under the FIRST
# (most specific) token that appears as a path component of its relpath, so both
# ``SQL Injection`` (PayloadsAllTheThings) and ``Databases/SQLi`` (SecLists) map to
# the sqli class. A file whose relpath matches no token is skipped and logged.
#
# auth-bypass-capable classes (sqli/nosqli) default their success edge to
# ``derived_credential`` (a confirmed bypass yields a principal, §8); the others
# to ``enables`` (a confirmed injection is a chainable finding).
_FOLDER_MAP: dict[str, _FolderClass] = {
    "SQLi": _FolderClass("sqli", SinkType.SQL, OracleMechanism.DIFFERENTIAL, "derived_credential"),
    "SQL Injection": _FolderClass(
        "sqli", SinkType.SQL, OracleMechanism.DIFFERENTIAL, "derived_credential"
    ),
    "NoSQL": _FolderClass(
        "nosqli", SinkType.NOSQL, OracleMechanism.DIFFERENTIAL, "derived_credential"
    ),
    "NoSQL Injection": _FolderClass(
        "nosqli", SinkType.NOSQL, OracleMechanism.DIFFERENTIAL, "derived_credential"
    ),
    "XSS": _FolderClass(
        "xss_reflected",
        SinkType.HTML_REFLECTION,
        OracleMechanism.EXECUTION_CONFIRMATION,
        "enables",
    ),
    "XSS Injection": _FolderClass(
        "xss_reflected",
        SinkType.HTML_REFLECTION,
        OracleMechanism.EXECUTION_CONFIRMATION,
        "enables",
    ),
    "Command-Injection": _FolderClass(
        "command_injection", SinkType.SHELL, OracleMechanism.OOB_CALLBACK, "enables"
    ),
    "Command Injection": _FolderClass(
        "command_injection", SinkType.SHELL, OracleMechanism.OOB_CALLBACK, "enables"
    ),
    "LFI": _FolderClass(
        "path_traversal", SinkType.FILE_PATH, OracleMechanism.STRUCTURAL, "enables"
    ),
    "File Inclusion": _FolderClass(
        "path_traversal", SinkType.FILE_PATH, OracleMechanism.STRUCTURAL, "enables"
    ),
}

# The SecLists command-injection list is a single top-level file, not under a
# folder token; map it by filename substring so it still ingests as shell/cmdi.
_FILENAME_MAP: dict[str, _FolderClass] = {
    "command-injection": _FOLDER_MAP["Command Injection"],
}

# Ordered oracle-tagging rules — first match wins over the payload line. This is
# the tag upstream corpora don't carry; ReachAgent's value-add. Small and ordered
# on purpose; each pattern is unit-tested against a representative line.
_ORACLE_RULES: tuple[tuple[re.Pattern[str], OracleMechanism], ...] = (
    # time-based: a conditional/blocking delay is a timing-oracle payload.
    (
        re.compile(r"(?i)\bsleep\s*\(|\bwaitfor\b|\bpg_sleep\b|\bbenchmark\s*\(|\[SLEEPTIME\]"),
        OracleMechanism.TIMING_STATISTICAL,
    ),
    # out-of-band: a DNS/HTTP callback marker exfils to a collaborator.
    (
        re.compile(
            r"(?i)\bnslookup\b|\bdig\b|\binteractsh\b|\bburpcollab|\bdnslog\b|\boastify\b"
            r"|\bcurl\s+http|\bwget\s+http|load_file\s*\(|xp_dirtree"
        ),
        OracleMechanism.OOB_CALLBACK,
    ),
    # execution confirmation: XSS/SSTI markup that runs when rendered/evaluated.
    (
        re.compile(
            r"(?i)<script|<svg|<img|<iframe|onerror\s*=|onload\s*=|onfocus\s*=|javascript:"
            r"|alert\s*\(|prompt\s*\(|confirm\s*\(|\{\{.*\}\}"
        ),
        OracleMechanism.EXECUTION_CONFIRMATION,
    ),
    # structural: a path-traversal sequence is retrieval-confirmed structurally.
    (
        re.compile(r"\.\./|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e", re.IGNORECASE),
        OracleMechanism.STRUCTURAL,
    ),
)


def _classify_oracle(line: str, folder_default: OracleMechanism) -> OracleMechanism:
    """Assign an oracle_type to a payload line — first matching rule, else default."""
    for pattern, oracle in _ORACLE_RULES:
        if pattern.search(line):
            return oracle
    return folder_default


def _folder_class_for(relpath: Path) -> _FolderClass | None:
    """The class a vendored file ingests as, from its relpath tokens / filename.

    Matches a ``_FOLDER_MAP`` token against the relpath's path components first
    (longest, most specific token wins so ``SQL Injection`` beats a bare token),
    then falls back to a filename-substring match (``_FILENAME_MAP``) for the
    top-level SecLists command-injection list. ``None`` → unmapped (skip + log).
    """
    parts = set(relpath.parts)
    for token in sorted(_FOLDER_MAP, key=len, reverse=True):
        if token in parts:
            return _FOLDER_MAP[token]
    name = relpath.name.lower()
    for needle, folder_class in _FILENAME_MAP.items():
        if needle in name:
            return folder_class
    return None


def _is_acceptable_line(line: str, sink: SinkType) -> bool:
    """Per-sink acceptance predicate: keep real payloads, skip blank/comment/junk.

    A line is skipped (and counted) when it is blank, a ``#`` comment, or fails a
    cheap sink-shaped sanity check — so the ingested set is real payloads, not
    wordlist headers or prose. Deliberately permissive: it rejects obvious
    non-payloads, not borderline ones (the resolver's semantic-validity guard is
    the stricter, per-entry check).
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    if sink is SinkType.SQL:
        return bool(re.search(r"['\"();=]|union|select|sleep|or |and |--|#", stripped, re.I))
    if sink is SinkType.NOSQL:
        return "$" in stripped or "{" in stripped or "sleep(" in stripped.lower()
    if sink is SinkType.HTML_REFLECTION:
        return "<" in stripped or bool(
            re.search(r"alert|prompt|confirm|onerror|onload|javascript:", stripped, re.I)
        )
    if sink is SinkType.FILE_PATH:
        return bool(
            re.search(r"\.\./|\.\.\\|\.\.%2f|%2e%2e|/etc/|boot\.ini|win\.ini|^/", stripped, re.I)
        )
    if sink is SinkType.SHELL:
        return bool(re.search(r"[;&|`]|\$\(|%0a|sleep|nslookup|ping|cat |id\b", stripped, re.I))
    return True


def _entries_from_file(
    source: str, file_path: Path, folder_class: _FolderClass
) -> tuple[list[PayloadEntry], int]:
    """Ingest one vendored file → (entries, skipped_count). Un-mappable tag → error."""
    if folder_class.success_edge not in _KNOWN_EDGES:
        raise PayloadLibraryError(
            f"folder class for {file_path.name} declares unknown graph_edge_on_success "
            f"{folder_class.success_edge!r}; not a §6 edge {sorted(_KNOWN_EDGES)}"
        )
    relpath = file_path.relative_to(_SNAPSHOTS[source])
    entries: list[PayloadEntry] = []
    skipped = 0
    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line_num, line in enumerate(lines, start=1):
        if not _is_acceptable_line(line, folder_class.sink):
            skipped += 1
            continue
        oracle = _classify_oracle(line, folder_class.default_oracle)
        entry = PayloadEntry(
            vuln_class=folder_class.vuln_class,
            context=f"{source} {relpath.as_posix()} line {line_num}",
            inferred_sink_type=folder_class.sink,
            oracle_type=oracle,
            payload_ref=f"{source}/{relpath.as_posix()}#L{line_num}",
            graph_edge_on_success=folder_class.success_edge,
        )
        entries.append(entry)
    return entries, skipped


def load_corpus_entries(sources: Iterable[str] | None = None) -> list[PayloadEntry]:
    """Ingest tagged entries from the vendored snapshots (default: all sources).

    Walks each source's snapshot dir, maps each ``.txt`` file to a class via its
    folder tokens (unmapped → skipped + logged), and ingests each acceptable line
    as a fully-tagged ``PayloadEntry`` with a ``source/relpath#Ln`` locator ref. An
    unknown source name is an error (a typo must not silently ingest nothing); a
    missing snapshot dir is warned and skipped (a dev who hasn't fetched it yet).
    """
    names = list(sources) if sources is not None else list(_SNAPSHOTS)
    all_entries: list[PayloadEntry] = []
    total_skipped = 0
    for source in names:
        root = _SNAPSHOTS.get(source)
        if root is None:
            raise PayloadLibraryError(
                f"unknown corpus source {source!r}; known: {sorted(_SNAPSHOTS)}"
            )
        if not root.exists():
            _log.warning("corpus snapshot for %s missing at %s; skipping", source, root)
            continue
        for txt in sorted(root.rglob("*.txt")):
            if txt.name == "SOURCE.txt":
                continue
            relpath = txt.relative_to(root)
            folder_class = _folder_class_for(relpath)
            if folder_class is None:
                _log.info("skipping unmapped corpus file: %s/%s", source, relpath.as_posix())
                continue
            entries, skipped = _entries_from_file(source, txt, folder_class)
            all_entries.extend(entries)
            total_skipped += skipped
    _log.info(
        "corpus ingest: %d entries from %d source(s); %d lines skipped (blank/comment/junk)",
        len(all_entries),
        len(names),
        total_skipped,
    )
    return all_entries


def build_library(
    base_path: str | Path | None = None,
    *,
    corpus_sources: Iterable[str] | None = None,
    include_corpus: bool = True,
) -> PayloadLibrary:
    """Build a library from the base slice plus (optionally) the vendored corpora.

    The base hand slice (``from_file``) loads unchanged, then vendored corpus
    entries are appended. Lookup semantics are identical — corpus entries are
    ordinary ``PayloadEntry`` rows sharing the sink-matched, confidence-ordered
    ``get_payloads`` contract. ``include_corpus=False`` reproduces the bare slice.
    """
    entries = list(PayloadLibrary.from_file(base_path).all_entries())
    if include_corpus:
        entries.extend(load_corpus_entries(corpus_sources))
    return PayloadLibrary(entries)
