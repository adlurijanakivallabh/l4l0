"""Hermetic tests for SourceToolRunner (Build Order 7) — the white-box
parallel to recon/tools/base.py's ReconToolRunner, adapted for a local repo
path input instead of a live URL/host.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from reachagent.graph.nodes import SourceFile
from reachagent.graph.store import ReachabilityGraph
from reachagent.whitebox.tools.base import SourceToolRunner, WhiteboxOutcome


class _FakeRunner(SourceToolRunner):
    name = "fake"
    binary = "fake-static-tool"

    def command(self, repo_path: str) -> list[str]:
        return ["fake-static-tool", repo_path]

    def parse(self, repo_path: str, raw_output: str) -> tuple[str, ...]:
        if not raw_output.strip():
            return ()
        node = self.graph.add_source_file(
            SourceFile(path="app.py", rule_id="fake-rule", line=1, message=raw_output.strip())
        )
        return (node,)


def test_ingest_parses_fixture_output_into_a_source_file_node() -> None:
    graph = ReachabilityGraph()
    runner = _FakeRunner(graph=graph)

    result = runner.ingest("/some/repo", "tainted query")

    assert result.outcome is WhiteboxOutcome.INGESTED
    assert len(result.nodes) == 1
    assert len(graph.source_files()) == 1


def test_ingest_parse_error_is_errored_not_a_crash() -> None:
    class _BoomRunner(SourceToolRunner):
        name = "boom"
        binary = "boom-tool"

        def command(self, repo_path: str) -> list[str]:
            return ["boom-tool", repo_path]

        def parse(self, repo_path: str, raw_output: str) -> tuple[str, ...]:
            raise ValueError("malformed output")

    graph = ReachabilityGraph()
    runner = _BoomRunner(graph=graph)

    result = runner.ingest("/some/repo", "garbage")

    assert result.outcome is WhiteboxOutcome.ERRORED
    assert result.detail == "ValueError"


def test_run_is_skipped_when_not_live() -> None:
    graph = ReachabilityGraph()
    runner = _FakeRunner(graph=graph)

    result = runner.run("/some/repo", environ={})

    assert result.outcome is WhiteboxOutcome.SKIPPED_NOT_LIVE
    assert graph.node_count() == 0


def test_run_refuses_a_path_that_does_not_exist(tmp_path) -> None:  # noqa: ANN001
    graph = ReachabilityGraph()
    runner = _FakeRunner(graph=graph)
    missing = str(tmp_path / "does-not-exist")

    result = runner.run(missing, environ={"REACHAGENT_RECON_LIVE": "1"})

    assert result.outcome is WhiteboxOutcome.REFUSED_PATH_NOT_FOUND
    assert graph.node_count() == 0
    assert runner.audit.entries[-1].outcome == WhiteboxOutcome.REFUSED_PATH_NOT_FOUND


def test_run_refuses_a_path_that_is_a_file_not_a_directory(tmp_path) -> None:  # noqa: ANN001
    graph = ReachabilityGraph()
    runner = _FakeRunner(graph=graph)
    a_file = tmp_path / "not-a-dir.txt"
    a_file.write_text("x")

    result = runner.run(str(a_file), environ={"REACHAGENT_RECON_LIVE": "1"})

    assert result.outcome is WhiteboxOutcome.REFUSED_PATH_NOT_FOUND


def test_run_skips_cleanly_when_binary_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,  # noqa: ANN001
) -> None:
    import reachagent.whitebox.tools.base as base

    monkeypatch.setattr(base.shutil, "which", lambda _b: None)
    monkeypatch.setattr(
        base.subprocess,
        "run",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("must not spawn when binary is missing")
        ),
    )
    graph = ReachabilityGraph()
    runner = _FakeRunner(graph=graph)

    result = runner.run(str(tmp_path), environ={"REACHAGENT_RECON_LIVE": "1"})

    assert result.outcome is WhiteboxOutcome.SKIPPED_MISSING_BINARY
    assert graph.node_count() == 0


def test_run_skips_cleanly_when_memory_is_critically_low(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,  # noqa: ANN001
) -> None:
    import reachagent.whitebox.tools.base as base

    monkeypatch.setattr(base, "_available_memory_mb", lambda: 50.0)
    monkeypatch.setattr(base.shutil, "which", lambda _b: "/usr/bin/fake-static-tool")
    monkeypatch.setattr(
        base.subprocess,
        "run",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("must not spawn when memory is critically low")
        ),
    )
    graph = ReachabilityGraph()
    runner = _FakeRunner(graph=graph)

    result = runner.run(str(tmp_path), environ={"REACHAGENT_RECON_LIVE": "1"})

    assert result.outcome is WhiteboxOutcome.SKIPPED_LOW_MEMORY
    assert graph.node_count() == 0


def test_live_spawn_uses_shell_false_and_an_argument_array(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,  # noqa: ANN001
) -> None:
    import reachagent.whitebox.tools.base as base

    @dataclass
    class _Completed:
        stdout: str = "tainted query"

    captured: dict = {}

    def _fake_run(argv, **kwargs):  # noqa: ANN001, ANN003
        captured["argv"] = argv
        captured["shell"] = kwargs.get("shell")
        captured["preexec_fn"] = kwargs.get("preexec_fn")
        return _Completed()

    monkeypatch.setattr(base.shutil, "which", lambda _b: "/usr/bin/fake-static-tool")
    monkeypatch.setattr(base.subprocess, "run", _fake_run)
    graph = ReachabilityGraph()
    runner = _FakeRunner(graph=graph)

    result = runner.run(str(tmp_path), environ={"REACHAGENT_RECON_LIVE": "1"})

    assert result.outcome is WhiteboxOutcome.INGESTED
    assert isinstance(captured["argv"], list)
    assert str(tmp_path) in captured["argv"]
    assert captured["shell"] is False
    assert captured["preexec_fn"] is base._limit_child_memory


def test_live_spawn_truncates_output_before_parse_not_just_the_preview(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,  # noqa: ANN001
) -> None:
    """Adversarial review: ingest() used to receive the FULL, untruncated
    stdout -- subprocess.run's capture_output buffers the whole thing into
    THIS (parent) process, not the RLIMIT_AS-capped child, so an unbounded
    string here was an unbounded parent-memory cost. run() must truncate
    before ever calling ingest()/parse(), mirroring the recon tier."""
    import reachagent.whitebox.tools.base as base

    huge = "x" * (base._OUTPUT_MAX_CHARS + 5_000)
    seen_lengths: list[int] = []

    class _RecordingRunner(SourceToolRunner):
        name = "recording"
        binary = "recording-tool"

        def command(self, repo_path: str) -> list[str]:
            return ["recording-tool", repo_path]

        def parse(self, repo_path: str, raw_output: str) -> tuple[str, ...]:
            seen_lengths.append(len(raw_output))
            return ()

    @dataclass
    class _Completed:
        stdout: str = huge

    monkeypatch.setattr(base.shutil, "which", lambda _b: "/usr/bin/recording-tool")
    monkeypatch.setattr(base.subprocess, "run", lambda *_a, **_k: _Completed())
    runner = _RecordingRunner(graph=ReachabilityGraph())

    runner.run(str(tmp_path), environ={"REACHAGENT_RECON_LIVE": "1"})

    assert len(seen_lengths) == 1
    assert seen_lengths[0] <= base._OUTPUT_MAX_CHARS + 100  # truncation marker overhead only


def test_missing_binary_at_spawn_time_race_is_still_a_clean_skip(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,  # noqa: ANN001
) -> None:
    import reachagent.whitebox.tools.base as base

    monkeypatch.setattr(base.shutil, "which", lambda _b: "/usr/bin/fake-static-tool")

    def _raise_not_found(*_a, **_k):  # noqa: ANN001, ANN002, ANN003
        raise FileNotFoundError

    monkeypatch.setattr(base.subprocess, "run", _raise_not_found)
    graph = ReachabilityGraph()
    runner = _FakeRunner(graph=graph)

    result = runner.run(str(tmp_path), environ={"REACHAGENT_RECON_LIVE": "1"})

    assert result.outcome is WhiteboxOutcome.SKIPPED_MISSING_BINARY
