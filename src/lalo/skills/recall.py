"""Keyword-overlap retrieval over the skill library — recall() the right playbook for a query.

A reference skill library resolves skills by bare name or ``category/name``
— no semantic search at all. This module generalizes only slightly: an exact
name or keyword match still wins outright (matching that reference's own
resolution order), with a token-overlap ranking as a fallback for a genuinely
free-text query ("how do I test for blind injection") that doesn't name a
skill directly.

A different reference platform was also checked for this concern (grepping
all five comparison docs, not just the one already informing the file-format
side of this package) and does have real, substantially more sophisticated
prior art: a pgvector-backed embedding retrieval subsystem over its own
long-term "memory"/knowledge-document store (guide/answer/code documents,
described in its own docs as retrieval-augmented context, with a dedicated
dev CLI to index/inspect/search it). Deliberately not adopted: that
subsystem solves retrieval over an open-ended, growing knowledge base of
documents nobody has fully read; this module's actual job is retrieval over
a few dozen fixed, hand-curated skill files, where exact/keyword matching
plus a cheap token-overlap score already gets the right file essentially
every time a query names its topic at all. Embedding infrastructure sized
for that reference's problem would be true over-engineering for this one —
noted here as a checked and deliberately rejected alternative, not a missed
option.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .loader import Skill

_TOKEN = re.compile(r"[a-z0-9]+")

_EXACT_NAME_SCORE = 100.0
_EXACT_KEYWORD_SCORE = 90.0


def _tokenize(text: str) -> set[str]:
    return set(_TOKEN.findall(text.lower()))


@dataclass(frozen=True)
class RecallResult:
    skill: Skill
    score: float


def _score(skill: Skill, normalized_query: str, query_tokens: set[str]) -> float:
    if skill.name.lower() == normalized_query:
        return _EXACT_NAME_SCORE
    if normalized_query in {k.lower() for k in skill.keywords}:
        return _EXACT_KEYWORD_SCORE

    name_tokens = _tokenize(skill.name)
    keyword_tokens = {t for k in skill.keywords for t in _tokenize(k)}
    description_tokens = _tokenize(skill.description)
    body_tokens = _tokenize(skill.body)

    return (
        10.0 * len(query_tokens & name_tokens)
        + 6.0 * len(query_tokens & keyword_tokens)
        + 3.0 * len(query_tokens & description_tokens)
        + 1.0 * len(query_tokens & body_tokens)
    )


def token_overlap_ratio(a: str, b: str) -> float:
    """Fraction of shared tokens between two plain strings - the same
    [a-z0-9]+ tokenizer recall() uses for query/skill scoring, reused here
    to compare two task descriptions instead of a query against a Skill."""
    tokens_a = set(_TOKEN.findall(a.lower()))
    tokens_b = set(_TOKEN.findall(b.lower()))
    if not tokens_a or not tokens_b:
        return 0.0
    return len(tokens_a & tokens_b) / len(tokens_a | tokens_b)


def recall(query: str, skills: list[Skill], *, top_k: int = 3) -> list[RecallResult]:
    """Return up to ``top_k`` skills best matching ``query``, highest score first."""
    normalized = query.strip().lower()
    query_tokens = _tokenize(query)
    scored = [
        RecallResult(skill=skill, score=score)
        for skill in skills
        if (score := _score(skill, normalized, query_tokens)) > 0
    ]
    scored.sort(key=lambda r: r.score, reverse=True)
    return scored[:top_k]
