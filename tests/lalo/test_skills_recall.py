"""Tests for keyword-overlap retrieval over the skill library."""

from __future__ import annotations

from lalo.skills import SkillCategory, recall
from lalo.skills.loader import Skill


def _skill(name: str, description: str, body: str = "", keywords: tuple[str, ...] = ()) -> Skill:
    return Skill(
        name=name,
        category=SkillCategory.VULNERABILITY,
        description=description,
        keywords=keywords,
        body=body,
        path=None,  # type: ignore[arg-type]
    )


_SQLI = _skill(
    "sql-injection", "SQL injection union and blind techniques", keywords=("sqli", "sql injection")
)
_XSS = _skill(
    "xss", "Cross-site scripting reflected stored dom", keywords=("xss", "cross-site scripting")
)
_SSRF = _skill("ssrf", "Server-side request forgery metadata internal network", keywords=("ssrf",))


def test_recall_exact_name_match_wins_outright() -> None:
    results = recall("xss", [_SQLI, _XSS, _SSRF])
    assert results[0].skill.name == "xss"
    assert results[0].score > 0


def test_recall_exact_keyword_match() -> None:
    results = recall("sqli", [_SQLI, _XSS, _SSRF])
    assert results[0].skill.name == "sql-injection"


def test_recall_free_text_query_ranks_by_token_overlap() -> None:
    results = recall("how do I test for cross-site scripting", [_SQLI, _XSS, _SSRF])
    assert results[0].skill.name == "xss"


def test_recall_returns_empty_list_for_no_match() -> None:
    assert recall("completely unrelated query about pastry recipes", [_SQLI, _XSS, _SSRF]) == []


def test_recall_respects_top_k() -> None:
    generic = _skill("generic", "server request forgery network metadata internal")
    results = recall("server request metadata network", [_SQLI, _XSS, _SSRF, generic], top_k=2)
    assert len(results) <= 2


def test_recall_results_are_sorted_highest_score_first() -> None:
    results = recall("injection scripting forgery", [_SQLI, _XSS, _SSRF])
    scores = [r.score for r in results]
    assert scores == sorted(scores, reverse=True)
