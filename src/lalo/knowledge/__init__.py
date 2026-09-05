"""Knowledge — per-class methodology skill library + RAG retrieval + cross-scan store.

The agent's ``recall`` tool retrieves relevant skills and past findings on demand.
Skills are markdown-with-frontmatter files (overridable dirs, precedence); RAG is a
dependency-free in-process retriever so it works offline.
"""

from .rag import Doc, Retriever
from .skills import Skill, SkillLibrary
from .store import KnowledgeStore, recall

__all__ = ["Doc", "KnowledgeStore", "Retriever", "Skill", "SkillLibrary", "recall"]
