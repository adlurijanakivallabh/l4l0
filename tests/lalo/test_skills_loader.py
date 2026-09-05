"""Tests for the skill markdown loader (YAML frontmatter + body)."""

from __future__ import annotations

from pathlib import Path

import pytest

from lalo.skills import Skill, SkillCategory, SkillLoadError, load_skills


def test_every_built_in_skill_loads_without_error() -> None:
    skills = load_skills()
    assert len(skills) >= 6  # 2 cross-cutting methodology + 4 core vuln classes, so far
    for skill in skills:
        assert skill.name
        assert skill.description
        assert skill.body


def test_every_vulnerability_skill_states_a_proof_ladder() -> None:
    skills = load_skills()
    vuln_skills = [s for s in skills if s.category is SkillCategory.VULNERABILITY]
    assert vuln_skills  # sanity: there actually are some
    for skill in vuln_skills:
        assert "Proof Ladder" in skill.body, f"{skill.name} has no Proof Ladder section"


def test_every_vulnerability_skill_cites_closure_discipline() -> None:
    # Every per-class skill defers to the cross-cutting methodology rather
    # than restating it — confirms the cross-reference is actually present.
    skills = load_skills()
    vuln_skills = [s for s in skills if s.category is SkillCategory.VULNERABILITY]
    for skill in vuln_skills:
        assert "closure-discipline" in skill.body, f"{skill.name} never cites closure-discipline"


def test_skill_names_are_unique_across_the_library() -> None:
    skills = load_skills()
    names = [s.name for s in skills]
    assert len(names) == len(set(names))


def test_load_skills_rejects_a_file_with_no_frontmatter(tmp_path: Path) -> None:
    bad = tmp_path / "broken.md"
    bad.write_text("# Just a heading, no frontmatter\n", encoding="utf-8")
    with pytest.raises(SkillLoadError, match="frontmatter"):
        load_skills(tmp_path)


def test_load_skills_rejects_an_invalid_category(tmp_path: Path) -> None:
    bad = tmp_path / "bad-category.md"
    bad.write_text(
        "---\nname: x\ncategory: not-a-real-category\ndescription: d\n---\nbody\n",
        encoding="utf-8",
    )
    with pytest.raises(SkillLoadError, match="category"):
        load_skills(tmp_path)


def test_load_skills_rejects_duplicate_names(tmp_path: Path) -> None:
    for filename in ("a.md", "b.md"):
        (tmp_path / filename).write_text(
            "---\nname: dup\ncategory: methodology\ndescription: d\n---\nbody\n",
            encoding="utf-8",
        )
    with pytest.raises(SkillLoadError, match="duplicate"):
        load_skills(tmp_path)


def test_load_skills_defaults_keywords_to_empty_tuple(tmp_path: Path) -> None:
    (tmp_path / "no-keywords.md").write_text(
        "---\nname: x\ncategory: methodology\ndescription: d\n---\nbody\n", encoding="utf-8"
    )
    skills = load_skills(tmp_path)
    assert skills[0].keywords == ()


def test_loaded_skill_is_a_skill_instance() -> None:
    skills = load_skills()
    assert all(isinstance(s, Skill) for s in skills)
