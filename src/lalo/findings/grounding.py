"""Evidence-provenance grounding — is the claimed proof actually in the capture?

A reference agent's execution-validation layer (``execution.py``, read in
full) rejects an Executor's completion claim unless its ``evidence_excerpt``
is a real, byte-for-byte substring of an actually-observed trace event —
including the "laundering" case, where a claim partially overlaps genuine
output but the rest is fabricated. Its full implementation also widens
exact-line spans and projects a claim across multiple receipts to recover a
true span from a lease/attempt/episode bookkeeping model L4L0 has no
equivalent of (a single ``record_finding`` call, not a concurrent
task-lease system) — that machinery is deliberately not ported. What *is*
adopted is the core, load-bearing check underneath all of it: a claimed
excerpt must literally appear in real captured output, never trusted from
prose alone. An excerpt that fails this check is not dropped (CLAUDE.md:
nothing is withheld) — it is flagged, and :mod:`~lalo.findings.confidence`
scores it lower for the gap.

Normalization is whitespace-only (CRLF/LF plus any run of whitespace
collapsed to one space, plus whitespace immediately touching JSON structural
punctuation collapsed away entirely), extended twice now after two separate
real live runs against VAmPI each surfaced a genuine false negative of a
different shape:

1. The model's own ``evidence_excerpt`` was pretty-printed multi-line JSON
   quoting the same object a captured HTTP response's ``evidence`` blob also
   contained as compact single-line JSON — identical content, differing only
   in how many newlines/spaces separated tokens. General whitespace-run
   collapsing (not just CRLF) closed this one.
2. A LATER run surfaced a narrower gap that same fix couldn't reach: the
   excerpt used JSON's conventional ``"key": value`` spacing, but the
   model's OWN ``evidence`` blob (also its own words, not a raw capture)
   quoted the identical object as fully compact JSON with NO space after
   the colon at all (``"admin":true``, not ``"admin": true``). Collapsing a
   whitespace *run* to one space cannot bridge "one space exists here" vs
   "zero spaces exist here" — there is no run to collapse on the zero-space
   side. Closed by also stripping whitespace immediately adjacent to JSON
   structural punctuation (``{ } [ ] : ,``) on both sides before comparing.

Neither extension weakens the anti-fabrication property this check exists
for: each can only make two strings compare equal where every actual
character *token* still appears in the same order in both — never let a
claim contain a character sequence (a value, a field name, a status code)
that never occurred in the real evidence. The existing "partially laundered
claim" test below is the concrete guard this must never break: a genuinely
fabricated tail appended to real text stays un-groundable regardless of how
its whitespace is arranged.
"""

from __future__ import annotations

import re

_WHITESPACE_RUN = re.compile(r"\s+")
# Whitespace touching a JSON structural character, either side - stripped
# to NOTHING (not collapsed to one space) since the two conventions this
# closes the gap between are "one space here" and "no space here", not
# "one space" vs "several".
_JSON_PUNCTUATION_WHITESPACE = re.compile(r"\s*([{}\[\]:,])\s*")


def _normalize_whitespace(value: str) -> str:
    collapsed = _WHITESPACE_RUN.sub(" ", value).strip()
    return _JSON_PUNCTUATION_WHITESPACE.sub(r"\1", collapsed)


def is_grounded(excerpt: str, evidence: list[str]) -> bool:
    """Whether ``excerpt`` is a real substring of at least one evidence blob,
    up to whitespace formatting differences."""
    normalized_excerpt = _normalize_whitespace(excerpt)
    if not normalized_excerpt:
        return False
    return any(normalized_excerpt in _normalize_whitespace(blob) for blob in evidence)
