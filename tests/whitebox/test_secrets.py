"""Hermetic tests for TruffleHogRunner (Build Order 7).

Fixture follows TruffleHog v3's publicly documented JSON-lines output shape
(disclosed in secrets.py's docstring as not independently live-verified in
this session's sandbox, which has an older/incompatible CLI installed).
"""

from __future__ import annotations

import json

from reachagent.graph.store import ReachabilityGraph
from reachagent.whitebox.tools.base import WhiteboxOutcome
from reachagent.whitebox.tools.secrets import TruffleHogRunner


def _line(detector: str, path: str, line: int, verified: bool, raw: str) -> str:
    return json.dumps(
        {
            "SourceMetadata": {"Data": {"Filesystem": {"file": path, "line": line}}},
            "DetectorName": detector,
            "Verified": verified,
            "Raw": raw,
            "Redacted": raw[:4] + "...",
        }
    )


def test_ingest_parses_json_lines_into_secret_nodes() -> None:
    graph = ReachabilityGraph()
    runner = TruffleHogRunner(graph=graph)
    raw_output = "\n".join(
        [
            _line("AWS", "config/.env", 3, True, "AKIAABCDEFGHIJKLMNOP"),
            _line("GitHub", "src/deploy.sh", 12, False, "ghp_abcdef1234567890"),
        ]
    )

    result = runner.ingest("/some/repo", raw_output)

    assert result.outcome is WhiteboxOutcome.INGESTED
    assert len(result.nodes) == 2
    secrets = {s.detector: s for _sid, s in graph.secrets()}
    assert secrets["AWS"].path == "config/.env"
    assert secrets["AWS"].line == 3
    assert secrets["AWS"].verified is True
    assert secrets["GitHub"].verified is False


def test_secret_value_never_reaches_the_graph() -> None:
    graph = ReachabilityGraph()
    runner = TruffleHogRunner(graph=graph)
    raw_output = _line("AWS", "config/.env", 3, True, "AKIAABCDEFGHIJKLMNOP")

    runner.ingest("/some/repo", raw_output)

    _sid, secret = graph.secrets()[0]
    dumped = str(secret)
    assert "AKIAABCDEFGHIJKLMNOP" not in dumped
    assert not hasattr(secret, "value")
    assert not hasattr(secret, "raw")


def test_blank_lines_and_malformed_json_lines_are_skipped_not_fatal() -> None:
    graph = ReachabilityGraph()
    runner = TruffleHogRunner(graph=graph)
    raw_output = "\n".join(["", "not json {{{", _line("AWS", "config/.env", 3, True, "AKIA...")])

    result = runner.ingest("/some/repo", raw_output)

    assert result.outcome is WhiteboxOutcome.INGESTED
    assert len(result.nodes) == 1


def test_record_missing_detector_or_location_is_skipped() -> None:
    graph = ReachabilityGraph()
    runner = TruffleHogRunner(graph=graph)
    raw_output = json.dumps({"Verified": True})  # no DetectorName, no SourceMetadata

    result = runner.ingest("/some/repo", raw_output)

    assert result.nodes == ()


def test_repeated_ingest_of_the_same_hit_is_idempotent() -> None:
    graph = ReachabilityGraph()
    runner = TruffleHogRunner(graph=graph)
    raw_output = _line("AWS", "config/.env", 3, True, "AKIA...")

    runner.ingest("/some/repo", raw_output)
    runner.ingest("/some/repo", raw_output)

    assert len(graph.secrets()) == 1
