"""Merge values into a local .env file - owner-only, preserving unrelated
lines, never a blind overwrite. Shared by lalo-setup and the GUI's own
settings endpoint so both use the identical, single-tested implementation.
"""

from __future__ import annotations

from pathlib import Path

from .atomic_io import atomic_write_verified


def merge_env_file(path: Path, values: dict[str, str]) -> None:
    """Update ``path`` with ``values``, replacing matching keys in place and
    preserving every other line untouched - the file may already hold
    unrelated content, so this never blindly overwrites it."""
    remaining = dict(values)
    out_lines: list[str] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            key = stripped.split("=", 1)[0].strip() if "=" in stripped else None
            if key and not stripped.startswith("#") and key in remaining:
                out_lines.append(f"{key}={remaining.pop(key)}")
            else:
                out_lines.append(line)
    out_lines.extend(f"{key}={value}" for key, value in remaining.items())
    atomic_write_verified(path, ("\n".join(out_lines) + "\n").encode("utf-8"))
