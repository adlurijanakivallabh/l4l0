"""A finalization manifest for a run's report artifacts - per-format path,
SHA-256 digest, and write time - so a later resumed or re-run scan can
detect whether its own prior report is still byte-identical (adopt it)
or has drifted (rewrite it), instead of always rewriting unconditionally.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from ..core.atomic_io import atomic_write_verified

_MANIFEST_FILENAME = "report_manifest.json"


def _sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_report_manifest(run_dir: Path, report_paths: dict[str, Path]) -> Path:
    manifest = {
        "written_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "artifacts": {
            fmt: {"path": path.name, "sha256": _sha256_of(path)}
            for fmt, path in report_paths.items()
        },
    }
    manifest_path = run_dir / _MANIFEST_FILENAME
    atomic_write_verified(
        manifest_path, json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    )
    return manifest_path


# A torn/tampered/hand-edited manifest is treated as "can't be trusted, don't
# adopt" (both functions below), never a crash -- a caller resuming a scan or
# listing run history must never hard-fail because of a corrupted artifact
# `atomic_write_verified`'s own write path shouldn't produce, but external
# corruption/tampering can still create.
_MALFORMED_MANIFEST_ERRORS = (json.JSONDecodeError, KeyError, TypeError, OSError)


def read_report_manifest_paths(run_dir: Path) -> dict[str, Path] | None:
    """The per-format report path recorded in this run's own manifest, keyed
    the same way :func:`~lalo.report.writer.write_report`'s own return value
    is -- for a caller that wants to ADOPT an already-verified-intact prior
    report instead of regenerating it (see :func:`verify_report_manifest`,
    which should be checked first). ``None`` if no manifest exists yet, OR if
    it exists but is malformed -- both mean "nothing safe to adopt here."
    """
    manifest_path = run_dir / _MANIFEST_FILENAME
    if not manifest_path.exists():
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        return {
            fmt: run_dir / entry["path"] for fmt, entry in manifest.get("artifacts", {}).items()
        }
    except _MALFORMED_MANIFEST_ERRORS:
        return None


def verify_report_manifest(run_dir: Path) -> list[str]:
    """Every drift between the recorded manifest and the artifacts on disk
    right now - a missing file, or one whose digest no longer matches.
    Empty list means everything is still exactly as recorded. A manifest that
    can't even be parsed counts as total drift (never a raised exception) --
    a caller checking this before adopting a report must never crash on a
    corrupted manifest, only correctly decide not to adopt."""
    manifest_path = run_dir / _MANIFEST_FILENAME
    if not manifest_path.exists():
        return ["no report_manifest.json exists in this run directory"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        drift: list[str] = []
        for fmt, entry in manifest.get("artifacts", {}).items():
            artifact_path = run_dir / entry["path"]
            if not artifact_path.exists():
                drift.append(f"{fmt}: {entry['path']} is missing")
                continue
            actual = _sha256_of(artifact_path)
            if actual != entry["sha256"]:
                drift.append(f"{fmt}: {entry['path']} digest changed")
        return drift
    except _MALFORMED_MANIFEST_ERRORS as exc:
        return [f"report_manifest.json is malformed: {exc}"]
