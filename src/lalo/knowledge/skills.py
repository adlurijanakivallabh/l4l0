"""Skill library — markdown methodology files with YAML frontmatter.

Layout: ``<root>/<name>.md`` with a ``---`` frontmatter block (name/class/summary).
Extra roots (operator-provided) shadow the built-ins by name, highest precedence
first — so the operator can add or override skills without editing the package.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_FRONTMATTER = re.compile(r"^---\s*\n(?P<meta>.*?)\n---\s*\n(?P<body>.*)$", re.DOTALL)
_BUILTIN_DIR = Path(__file__).parent / "skills"


@dataclass
class Skill:
    name: str
    vuln_class: str
    summary: str
    body: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def text(self) -> str:
        return f"{self.summary}\n\n{self.body}"


def _parse(path: Path) -> Skill:
    raw = path.read_text(encoding="utf-8")
    match = _FRONTMATTER.match(raw)
    meta: dict[str, Any] = {}
    body = raw
    if match:
        parsed = yaml.safe_load(match.group("meta"))
        if isinstance(parsed, dict):
            meta = parsed
        body = match.group("body").strip()
    return Skill(
        name=str(meta.get("name", path.stem)),
        vuln_class=str(meta.get("class", path.stem)),
        summary=str(meta.get("summary", "")),
        body=body,
        metadata=meta,
    )


class SkillLibrary:
    def __init__(self, roots: list[Path] | None = None) -> None:
        # Highest precedence first; built-ins last.
        self._roots = [*(roots or []), _BUILTIN_DIR]
        self._skills: dict[str, Skill] = {}
        self._load()

    def _load(self) -> None:
        for root in self._roots:
            if not root.is_dir():
                continue
            for path in sorted(root.glob("*.md")):
                if path.name.startswith("__") or path.name == "README.md":
                    continue
                skill = _parse(path)
                self._skills.setdefault(skill.name, skill)  # first (highest precedence) wins

    def get(self, name: str) -> Skill | None:
        return self._skills.get(name)

    def for_class(self, vuln_class: str) -> list[Skill]:
        return [s for s in self._skills.values() if s.vuln_class == vuln_class]

    def all(self) -> list[Skill]:
        return list(self._skills.values())
