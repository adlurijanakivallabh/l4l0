"""Tests for the skill library, RAG retriever, knowledge store, and recall."""

from __future__ import annotations

from lalo.knowledge import KnowledgeStore, Retriever, SkillLibrary, recall
from lalo.knowledge.rag import Doc
from lalo.models import Finding, Severity


def test_skill_library_loads_builtins() -> None:
    lib = SkillLibrary()
    sqli = lib.get("sqli")
    assert sqli is not None
    assert sqli.vuln_class == "sqli"
    assert "boolean" in sqli.body.lower()
    assert lib.for_class("xss")


def test_extra_root_overrides_builtin(tmp_path) -> None:
    override = tmp_path / "sqli.md"
    override.write_text("---\nname: sqli\nclass: sqli\nsummary: custom\n---\nOVERRIDDEN BODY")
    lib = SkillLibrary(roots=[tmp_path])
    assert lib.get("sqli").summary == "custom"  # type: ignore[union-attr]
    assert "OVERRIDDEN" in lib.get("sqli").body  # type: ignore[union-attr]


def test_retriever_ranks_relevant_doc_first() -> None:
    docs = [
        Doc("a", "cross site scripting reflected payload in html"),
        Doc("b", "sql injection database error boolean time based"),
        Doc("c", "open redirect location header"),
    ]
    hits = Retriever(docs).recall("sql injection time based blind", k=2)
    assert hits[0][0].id == "b"


def test_knowledge_store_persists_across_instances(tmp_path) -> None:
    path = tmp_path / "k.json"
    store = KnowledgeStore(path)
    store.add_finding(Finding.create("sqli in id", "sqli", Severity.HIGH, "https://app/item"))
    reloaded = KnowledgeStore(path)
    assert len(reloaded.findings()) == 1
    assert reloaded.as_docs()[0].metadata["vuln_class"] == "sqli"


def test_recall_returns_relevant_skill() -> None:
    out = recall("how do I test for command injection and prove rce")
    assert "cmdi" in out or "command" in out.lower()
