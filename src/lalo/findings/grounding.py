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
collapsed to one space), extended from an original CRLF-only version after a
real live run against a local target surfaced a genuine false negative: the
model's own ``evidence_excerpt`` was pretty-printed multi-line JSON quoting
the same object a captured HTTP response's ``evidence`` blob also contained
as compact single-line JSON — identical content, different formatting, and
the excerpt-only-differs-in-whitespace case is exactly what CRLF-normalization
already existed to handle for a narrower cause (transport line endings).
Collapsing whitespace runs generally does not weaken the anti-fabrication
property this check exists for: it can only make two strings compare equal
where every actual character *token* still appears in the same order in
both — it can never let a claim contain a character sequence (a value, a
field name, a status code) that never occurred in the real evidence. The
existing "partially laundered claim" test below is the concrete guard this
must never break: a genuinely fabricated tail appended to real text stays
un-groundable regardless of how its whitespace is arranged.
"""

from __future__ import annotations

import re

_WHITESPACE_RUN = re.compile(r"\s+")


def _normalize_whitespace(value: str) -> str:
    return _WHITESPACE_RUN.sub(" ", value).strip()


def is_grounded(excerpt: str, evidence: list[str]) -> bool:
    """Whether ``excerpt`` is a real substring of at least one evidence blob,
    up to whitespace formatting differences."""
    normalized_excerpt = _normalize_whitespace(excerpt)
    if not normalized_excerpt:
        return False
    return any(normalized_excerpt in _normalize_whitespace(blob) for blob in evidence)
