"""Centralized run-artifact filenames — every module that reads or writes
one of these joins it onto a run_dir itself; this module only owns the
literal string, closing the rename/drift risk of having the same filename
duplicated across 2-4 separate files (scan.py, orchestrator/narrative.py,
gui/app.py, core/usage.py all referenced at least one of these as a bare
literal) with no single source of truth.
"""

from __future__ import annotations

EVENTS_FILENAME = "events.jsonl"
RESUME_MANIFEST_FILENAME = "resume_manifest.json"
NARRATIVE_LOG_FILENAME = "narrative.log"
USAGE_FILENAME = "usage.json"
