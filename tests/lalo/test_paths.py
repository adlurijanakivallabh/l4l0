"""Tests for the centralized run-artifact filename constants."""

from __future__ import annotations


def test_paths_module_exports_every_run_artifact_filename() -> None:
    from lalo.paths import (
        EVENTS_FILENAME,
        NARRATIVE_LOG_FILENAME,
        RESUME_MANIFEST_FILENAME,
        USAGE_FILENAME,
    )

    assert EVENTS_FILENAME == "events.jsonl"
    assert RESUME_MANIFEST_FILENAME == "resume_manifest.json"
    assert NARRATIVE_LOG_FILENAME == "narrative.log"
    assert USAGE_FILENAME == "usage.json"
