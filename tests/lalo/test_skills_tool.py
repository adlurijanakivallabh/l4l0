"""Tests for the recall agent-tool wrapper."""

from __future__ import annotations

from lalo.agent.tools import ToolRegistry
from lalo.skills import SkillCategory, build_recall_tool
from lalo.skills.loader import Skill


def _skill(name: str, description: str, body: str, keywords: tuple[str, ...] = ()) -> Skill:
    return Skill(
        name=name,
        category=SkillCategory.VULNERABILITY,
        description=description,
        keywords=keywords,
        body=body,
        path=None,  # type: ignore[arg-type]
    )


def test_recall_tool_returns_the_top_matching_skills_body() -> None:
    xss = _skill("xss", "cross-site scripting", "the full xss playbook body", keywords=("xss",))
    tool = build_recall_tool([xss])
    registry = ToolRegistry([tool])
    result = registry.dispatch("recall", {"query": "xss"})
    assert result.ok is True
    assert "the full xss playbook body" in result.observation


def test_recall_tool_requires_a_query() -> None:
    tool = build_recall_tool([])
    registry = ToolRegistry([tool])
    result = registry.dispatch("recall", {"query": ""})
    assert result.ok is False


def test_recall_tool_reports_no_match_as_a_failed_result_not_an_exception() -> None:
    tool = build_recall_tool([])
    registry = ToolRegistry([tool])
    result = registry.dispatch("recall", {"query": "something with no skill at all"})
    assert result.ok is False


def test_recall_tool_lists_other_related_skills() -> None:
    sqli = _skill("sql-injection", "sql injection", "sqli body", keywords=("sqli", "injection"))
    cmdi = _skill("cmdi", "command injection", "cmdi body", keywords=("cmdi", "injection"))
    tool = build_recall_tool([sqli, cmdi])
    registry = ToolRegistry([tool])
    result = registry.dispatch("recall", {"query": "injection"})
    assert result.ok is True
    assert "other related skills" in result.observation
