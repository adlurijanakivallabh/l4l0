"""Tests for keyword-overlap retrieval over the skill library."""

from __future__ import annotations

from lalo.skills import SkillCategory, load_skills, recall
from lalo.skills.loader import Skill
from lalo.skills.recall import token_overlap_ratio


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


def test_token_overlap_ratio_near_identical_strings_scores_high() -> None:
    ratio = token_overlap_ratio(
        "enumerate S3 buckets for public read access",
        "enumerate S3 buckets for public write access",
    )
    assert ratio > 0.5


def test_token_overlap_ratio_unrelated_strings_scores_low() -> None:
    ratio = token_overlap_ratio(
        "enumerate S3 buckets for public read access",
        "fuzz the login form for SQL injection",
    )
    assert ratio < 0.2


def test_token_overlap_ratio_empty_string_is_zero_not_a_zero_division() -> None:
    assert token_overlap_ratio("", "anything") == 0.0
    assert token_overlap_ratio("anything", "") == 0.0
    assert token_overlap_ratio("", "") == 0.0


def test_recall_surfaces_the_cors_playbook_for_a_relevant_query() -> None:
    skills = load_skills()
    results = recall("reflected origin ACAO wildcard credentials", skills, top_k=3)
    assert any(r.skill.name == "cors-misconfiguration" for r in results)


def test_recall_surfaces_the_prototype_pollution_playbook_for_a_relevant_query() -> None:
    skills = load_skills()
    results = recall("__proto__ constructor prototype gadget merge", skills, top_k=3)
    assert any(r.skill.name == "prototype-pollution" for r in results)


def test_recall_surfaces_the_cache_poisoning_playbook_for_a_relevant_query() -> None:
    skills = load_skills()
    results = recall("unkeyed header X-Forwarded-Host cache poisoning", skills, top_k=3)
    assert any(r.skill.name == "cache-poisoning" for r in results)
