"""Tests for the per-run report finalization manifest (path + sha256 per format)."""

from __future__ import annotations

import json
from pathlib import Path


def test_write_report_manifest_records_path_and_digest_per_format(tmp_path: Path) -> None:
    from lalo.report.manifest import write_report_manifest

    (tmp_path / "report.md").write_text("hello", encoding="utf-8")
    (tmp_path / "report.json").write_text('{"a": 1}', encoding="utf-8")
    report_paths = {"md": tmp_path / "report.md", "json": tmp_path / "report.json"}

    manifest_path = write_report_manifest(tmp_path, report_paths)

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert set(data["artifacts"]) == {"md", "json"}
    assert data["artifacts"]["md"]["path"] == "report.md"
    assert len(data["artifacts"]["md"]["sha256"]) == 64
    assert "written_at" in data


def test_verify_report_manifest_reports_no_drift_when_unchanged(tmp_path: Path) -> None:
    from lalo.report.manifest import verify_report_manifest, write_report_manifest

    (tmp_path / "report.md").write_text("hello", encoding="utf-8")
    write_report_manifest(tmp_path, {"md": tmp_path / "report.md"})

    assert verify_report_manifest(tmp_path) == []


def test_verify_report_manifest_reports_drift_when_a_file_changed(tmp_path: Path) -> None:
    from lalo.report.manifest import verify_report_manifest, write_report_manifest

    (tmp_path / "report.md").write_text("hello", encoding="utf-8")
    write_report_manifest(tmp_path, {"md": tmp_path / "report.md"})
    (tmp_path / "report.md").write_text("changed", encoding="utf-8")

    drift = verify_report_manifest(tmp_path)
    assert len(drift) == 1
    assert "md" in drift[0]


def test_verify_report_manifest_reports_drift_when_a_file_is_missing(tmp_path: Path) -> None:
    from lalo.report.manifest import verify_report_manifest, write_report_manifest

    (tmp_path / "report.md").write_text("hello", encoding="utf-8")
    write_report_manifest(tmp_path, {"md": tmp_path / "report.md"})
    (tmp_path / "report.md").unlink()

    drift = verify_report_manifest(tmp_path)
    assert len(drift) == 1


def test_verify_report_manifest_reports_missing_manifest_itself(tmp_path: Path) -> None:
    from lalo.report.manifest import verify_report_manifest

    drift = verify_report_manifest(tmp_path)
    assert len(drift) == 1


def test_read_report_manifest_paths_reconstructs_the_written_paths(tmp_path: Path) -> None:
    from lalo.report.manifest import read_report_manifest_paths, write_report_manifest

    (tmp_path / "report.md").write_text("hello", encoding="utf-8")
    (tmp_path / "report.json").write_text('{"a": 1}', encoding="utf-8")
    report_paths = {"md": tmp_path / "report.md", "json": tmp_path / "report.json"}
    write_report_manifest(tmp_path, report_paths)

    assert read_report_manifest_paths(tmp_path) == report_paths


def test_read_report_manifest_paths_on_a_run_with_no_manifest_is_none(tmp_path: Path) -> None:
    from lalo.report.manifest import read_report_manifest_paths

    assert read_report_manifest_paths(tmp_path) is None
