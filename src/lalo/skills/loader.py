"""Loads skill markdown files (YAML frontmatter + body) from the skill content directory.

Reference reads for this phase (all five, via each project's own
comparison documentation, plus real source). A reference agent's own
`skills/__init__.py` (read directly) confirms its skills are "plain markdown
files with YAML frontmatter (name/description)" resolved by name — the
file format this module adopts, generalized with an explicit `category`
(this project separates cross-cutting methodology skills, always relevant,
from per-vulnerability-class skills, requested by topic) and optional
`keywords` (free-text aliases so :func:`~lalo.skills.recall.recall` can
match a query that doesn't use the skill's exact name).

That same reference's real per-vulnerability-class skill files and its
counterevidence/severity-calibration files were the primary, heavily-drawn-
upon methodology source for this library's actual content, not just its
file format — direct comparison of real source across most of the shipped
skill files (matching invariant taxonomies, ordered false-positive lists,
section headings, and worked examples) confirms this. L4L0's synthesis work
on top of that source is real but should be stated honestly rather than
undersold: restructuring every skill around this project's own Attack
Surface → Recon → Techniques → Proof Ladder → Validation shape, adding the
explicit [[closure-discipline]]/[[severity-calibration]] cross-references
every skill cites instead of repeating that content per-class, and folding
in the current 2025-2026 web-sourced classes. A second reference's per-class
exploit prompts and a third reference's per-domain agent docs were also read
for methodology content. Deliberately not cited inside the skill markdown
files themselves — an agent-facing methodology document is exactly the
wrong place to name a reference project, given this project's own generic-
naming discipline; the full reference-reading record for each class lives
in this project's commit history instead. Two other reference platforms
were confirmed, via their own real source, to have no comparable per-topic
skill library at all (methodology lives in a single orchestrator persona
template and generic task-formation prompts, not addressable knowledge
packs).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import yaml

from ..core.errors import LaloError

SKILLS_DIR = Path(__file__).parent / "content"

_FRONTMATTER = re.compile(r"\A---\n(.*?)\n---\n(.*)\Z", re.DOTALL)


class SkillCategory(StrEnum):
    METHODOLOGY = "methodology"
    VULNERABILITY = "vulnerability"


class SkillLoadError(LaloError):
    """A skill markdown file is missing or has malformed frontmatter."""

    code = "skill_load_error"


@dataclass(frozen=True)
class Skill:
    name: str
    category: SkillCategory
    description: str
    keywords: tuple[str, ...]
    body: str
    path: Path


def _parse_skill_file(path: Path) -> Skill:
    text = path.read_text(encoding="utf-8")
    match = _FRONTMATTER.match(text)
    if match is None:
        raise SkillLoadError(f"{path}: missing YAML frontmatter (expected --- ... --- header)")
    front_raw, body = match.group(1), match.group(2)
    front = yaml.safe_load(front_raw)
    if not isinstance(front, dict):
        raise SkillLoadError(f"{path}: frontmatter must be a YAML mapping")
    try:
        name = str(front["name"])
        category = SkillCategory(str(front["category"]))
        description = str(front["description"])
    except KeyError as exc:
        raise SkillLoadError(f"{path}: missing required frontmatter field {exc}") from exc
    except ValueError as exc:
        raise SkillLoadError(f"{path}: invalid category: {exc}") from exc
    raw_keywords = front.get("keywords", [])
    keywords = tuple(str(k) for k in raw_keywords) if isinstance(raw_keywords, list) else ()
    return Skill(
        name=name,
        category=category,
        description=description,
        keywords=keywords,
        body=body.strip(),
        path=path,
    )


def _check_unique_names(skills: list[Skill]) -> None:
    seen: dict[str, Path] = {}
    for skill in skills:
        if skill.name in seen:
            raise SkillLoadError(
                f"duplicate skill name {skill.name!r}: {seen[skill.name]} and {skill.path}"
            )
        seen[skill.name] = skill.path


def load_skills(directory: Path | None = None) -> list[Skill]:
    """Load every ``*.md`` skill file under ``directory`` (default: the built-in library)."""
    base = directory or SKILLS_DIR
    skills = [_parse_skill_file(p) for p in sorted(base.glob("**/*.md"))]
    _check_unique_names(skills)
    return skills
