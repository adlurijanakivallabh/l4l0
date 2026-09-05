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
excerpt must literally appear in real captured output, normalized only for
CRLF/LF so a transport-level line-ending difference cannot defeat the match,
never trusted from prose alone. An excerpt that fails this check is not
dropped (CLAUDE.md: nothing is withheld) — it is flagged, and
:mod:`~lalo.findings.confidence` scores it lower for the gap.
"""

from __future__ import annotations


def _normalize_newlines(value: str) -> str:
    return value.replace("\r\n", "\n")


def is_grounded(excerpt: str, evidence: list[str]) -> bool:
    """Whether ``excerpt`` is a real substring of at least one evidence blob."""
    if not excerpt.strip():
        return False
    normalized_excerpt = _normalize_newlines(excerpt)
    return any(normalized_excerpt in _normalize_newlines(blob) for blob in evidence)
