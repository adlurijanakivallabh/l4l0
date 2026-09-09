"""Unit coverage for the per-agent-attributed narrative renderer."""

from __future__ import annotations

from pathlib import Path

from lalo.orchestrator.narrative import (
    render_narrative,
    render_narrative_line,
    write_narrative_log,
    write_per_agent_narrative_logs,
)


def test_tool_call_renders_as_agent_attributed_method_and_url() -> None:
    line = render_narrative_line(
        "log",
        {
            "agent_id": "agent-3",
            "event": "tool_call",
            "tool": "http",
            "args": {"method": "GET", "url": "https://example.com/api"},
        },
    )
    assert line == "[agent-3] tool_call: http GET https://example.com/api"


def test_embedded_newline_and_control_char_collapse_to_one_line() -> None:
    line = render_narrative_line(
        "log",
        {
            "agent_id": "agent-1",
            "event": "tool_result",
            "tool": "run_command",
            "ok": True,
            "observation": "line1\nline2\x07",
        },
    )
    assert "\n" not in line
    assert "\x07" not in line
    assert "line1" in line
    assert "line2" in line


def test_a_secret_shaped_observation_is_redacted() -> None:
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    line = render_narrative_line(
        "log",
        {
            "agent_id": "agent-2",
            "event": "tool_result",
            "tool": "http",
            "ok": True,
            "observation": f"set-cookie session={jwt}",
        },
    )
    assert jwt not in line
    # JWTs are a structured, high-entropy token shape, so redaction.py
    # fingerprints them (a distinguishable, still-non-reversible
    # "«REDACTED:<digest>»" rather than the bare literal) so two different
    # tokens don't collapse to the same redacted text - see
    # core/redaction.py's _fingerprinted_placeholder.
    assert "«REDACTED:" in line


def test_a_finding_event_has_no_fabricated_agent_id() -> None:
    line = render_narrative_line(
        "finding",
        {
            "finding_id": "finding-1",
            "title": "SQLi in /login",
            "severity": "high",
            "confidence": 82,
            "verdict": "confirmed",
        },
    )
    assert line.startswith("[system] finding:")
    assert "finding-1" in line
    assert "SQLi in /login" in line


def test_render_narrative_on_a_missing_events_file_is_empty(tmp_path: Path) -> None:
    assert render_narrative(tmp_path / "no-such-run") == ""


def test_render_narrative_replays_real_events_jsonl_in_order(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "events.jsonl").write_text(
        '{"category": "status", "payload": {"event": "scan_started", "targets": ["x"]}}\n'
        '{"category": "log", "payload": {"agent_id": "root", "event": "tool_call", '
        '"tool": "http", "args": {"method": "GET", "url": "https://x/"}}}\n',
        encoding="utf-8",
    )
    rendered = render_narrative(run_dir)
    lines = rendered.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("[system] scan_started:")
    assert lines[1] == "[root] tool_call: http GET https://x/"


def test_write_narrative_log_persists_owner_only_to_the_run_dir(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "events.jsonl").write_text(
        '{"category": "status", "payload": {"event": "scan_started", "targets": ["x"]}}\n',
        encoding="utf-8",
    )
    path = write_narrative_log(run_dir)
    assert path == run_dir / "narrative.log"
    assert path.exists()
    assert oct(path.stat().st_mode)[-3:] == "600"
    assert "scan_started" in path.read_text(encoding="utf-8")


def test_write_per_agent_narrative_logs_splits_by_real_agent_id(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "events.jsonl").write_text(
        '{"category": "log", "payload": {"agent_id": "agent-1", "event": "tool_call", '
        '"tool": "http", "args": {"method": "GET", "url": "https://x/"}}}\n'
        '{"category": "log", "payload": {"agent_id": "agent-2", "event": "tool_call", '
        '"tool": "http", "args": {"method": "GET", "url": "https://y/"}}}\n',
        encoding="utf-8",
    )
    paths = write_per_agent_narrative_logs(run_dir)
    assert set(paths) == {"agent-1", "agent-2"}
    assert "https://x/" in paths["agent-1"].read_text(encoding="utf-8")
    assert "https://y/" not in paths["agent-1"].read_text(encoding="utf-8")
    assert oct(paths["agent-1"].stat().st_mode)[-3:] == "600"


def test_write_per_agent_narrative_logs_skips_a_single_agent_run(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "events.jsonl").write_text(
        '{"category": "log", "payload": {"agent_id": "agent-1", "event": "tool_call", '
        '"tool": "http", "args": {"method": "GET", "url": "https://x/"}}}\n',
        encoding="utf-8",
    )
    assert write_per_agent_narrative_logs(run_dir) == {}


def test_write_per_agent_narrative_logs_on_a_missing_events_file_is_empty(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    assert write_per_agent_narrative_logs(run_dir) == {}


def test_write_per_agent_narrative_logs_excludes_system_scoped_events(tmp_path: Path) -> None:
    """finding/chain events have no real per-agent author (see this module's
    own docstring) - they must never spuriously create a third "system"
    per-agent file alongside the two real agents' own."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "events.jsonl").write_text(
        '{"category": "log", "payload": {"agent_id": "agent-1", "event": "tool_call", '
        '"tool": "http", "args": {"method": "GET", "url": "https://x/"}}}\n'
        '{"category": "log", "payload": {"agent_id": "agent-2", "event": "tool_call", '
        '"tool": "http", "args": {"method": "GET", "url": "https://y/"}}}\n'
        '{"category": "finding", "payload": {"finding_id": "f1", "title": "SQLi"}}\n',
        encoding="utf-8",
    )
    paths = write_per_agent_narrative_logs(run_dir)
    assert set(paths) == {"agent-1", "agent-2"}
