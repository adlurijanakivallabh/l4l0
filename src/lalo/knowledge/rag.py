"""Dependency-free in-process retriever (RAG backend).

Term-overlap scoring with an idf-style weighting — deterministic and offline. An
embedding backend can replace :class:`Retriever` behind the same interface later.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

_TOKEN = re.compile(r"[a-z0-9]{2,}")


def _tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


@dataclass
class Doc:
    id: str
    text: str
    metadata: dict[str, object] = field(default_factory=dict)


class Retriever:
    def __init__(self, docs: list[Doc]) -> None:
        self._docs = docs
        self._tokens: dict[str, Counter[str]] = {d.id: Counter(_tokenize(d.text)) for d in docs}
        n = max(len(docs), 1)
        df: Counter[str] = Counter()
        for counts in self._tokens.values():
            df.update(counts.keys())
        self._idf = {term: math.log(1 + n / (1 + freq)) for term, freq in df.items()}

    def recall(self, query: str, k: int = 3) -> list[tuple[Doc, float]]:
        q_terms = set(_tokenize(query))
        scored: list[tuple[Doc, float]] = []
        for doc in self._docs:
            counts = self._tokens[doc.id]
            score = sum(counts[t] * self._idf.get(t, 0.0) for t in q_terms)
            if score > 0:
                scored.append((doc, round(score, 4)))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:k]
