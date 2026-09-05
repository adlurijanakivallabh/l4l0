"""Cross-scan knowledge store + the recall entry point.

Persists past findings (as lightweight docs) so a later scan can retrieve prior
results ("new since last run" / regression) and so ``recall`` can search across
the skill library AND accumulated findings.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..models import Finding
from .rag import Doc, Retriever
from .skills import SkillLibrary


class KnowledgeStore:
    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self._findings: list[dict[str, object]] = []
        if self.path is not None and self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    self._findings = loaded
            except (json.JSONDecodeError, ValueError, OSError):
                self._findings = []

    def add_finding(self, finding: Finding) -> None:
        self._findings.append(
            {
                "id": finding.id,
                "title": finding.title,
                "vuln_class": finding.vuln_class,
                "target": finding.target,
                "confidence": finding.confidence,
            }
        )
        self._persist()

    def _persist(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._findings, sort_keys=True), encoding="utf-8")

    def findings(self) -> list[dict[str, object]]:
        return list(self._findings)

    def as_docs(self) -> list[Doc]:
        return [
            Doc(
                id=f"finding:{f['id']}",
                text=f"{f.get('vuln_class', '')} {f.get('title', '')} {f.get('target', '')}",
                metadata=dict(f),
            )
            for f in self._findings
        ]


def recall(
    query: str,
    *,
    library: SkillLibrary | None = None,
    store: KnowledgeStore | None = None,
    k: int = 3,
) -> str:
    """Retrieve relevant skills + past findings for a query, as agent-ready text."""
    lib = library or SkillLibrary()
    docs = [Doc(id=f"skill:{s.name}", text=s.text, metadata={"kind": "skill"}) for s in lib.all()]
    if store is not None:
        docs.extend(store.as_docs())
    hits = Retriever(docs).recall(query, k=k)
    if not hits:
        return f"no knowledge found for: {query}"
    return "\n\n".join(f"[{doc.id} score={score}]\n{doc.text[:800]}" for doc, score in hits)
