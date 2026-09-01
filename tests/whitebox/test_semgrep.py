"""Hermetic tests for SemgrepRunner (Build Order 7).

The fixture below is the EXACT shape verified live against a real semgrep
1.172.0 run this session (see whitebox/tools/semgrep.py's docstring) — not
guessed.
"""

from __future__ import annotations

import json

from reachagent.graph.store import ReachabilityGraph
from reachagent.whitebox.tools.base import WhiteboxOutcome
from reachagent.whitebox.tools.semgrep import SemgrepRunner

_REAL_SHAPE_OUTPUT = json.dumps(
    {
        "version": "1.172.0",
        "results": [
            {
                "check_id": "test-sql-concat",
                "path": "app.py",
                "start": {"line": 6, "col": 13, "offset": 116},
                "end": {"line": 6, "col": 64, "offset": 167},
                "extra": {
                    "message": "possible sql injection via string concat",
                    "metadata": {},
                    "severity": "ERROR",
                    "fingerprint": "requires login",
                },
            }
        ],
        "errors": [],
    }
)


def test_command_disables_metrics_telemetry() -> None:
    """Adversarial review: --config=auto alone phones scan telemetry home to
    semgrep.dev by default. --metrics=off must always be present."""
    runner = SemgrepRunner(graph=ReachabilityGraph())
    assert "--metrics=off" in runner.command("/some/repo")


def test_ingest_parses_a_real_shaped_semgrep_result() -> None:
    graph = ReachabilityGraph()
    runner = SemgrepRunner(graph=graph)

    result = runner.ingest("/some/repo", _REAL_SHAPE_OUTPUT)

    assert result.outcome is WhiteboxOutcome.INGESTED
    assert len(result.nodes) == 1
    files = graph.source_files()
    assert len(files) == 1
    _fid, sf = files[0]
    assert sf.path == "app.py"
    assert sf.rule_id == "test-sql-concat"
    assert sf.line == 6
    assert sf.severity == "error"
    assert "sql injection" in sf.message


def test_empty_results_yields_no_nodes() -> None:
    graph = ReachabilityGraph()
    runner = SemgrepRunner(graph=graph)

    result = runner.ingest("/some/repo", json.dumps({"results": [], "errors": []}))

    assert result.outcome is WhiteboxOutcome.INGESTED
    assert result.nodes == ()


def test_malformed_json_is_errored_not_a_crash() -> None:
    graph = ReachabilityGraph()
    runner = SemgrepRunner(graph=graph)

    result = runner.ingest("/some/repo", "not json at all {{{")

    assert result.outcome is WhiteboxOutcome.INGESTED  # parse() itself never raises
    assert result.nodes == ()


def test_result_missing_required_fields_is_skipped_not_fatal() -> None:
    graph = ReachabilityGraph()
    runner = SemgrepRunner(graph=graph)
    raw = json.dumps(
        {
            "results": [
                {"check_id": "x"},  # missing path/start entirely
                {
                    "check_id": "y",
                    "path": "b.py",
                    "start": {"line": 1},
                    "extra": {"message": "ok", "severity": "WARNING"},
                },
            ]
        }
    )

    result = runner.ingest("/some/repo", raw)

    assert len(result.nodes) == 1
    _fid, sf = graph.source_files()[0]
    assert sf.rule_id == "y"


def test_repeated_ingest_of_the_same_hit_is_idempotent() -> None:
    graph = ReachabilityGraph()
    runner = SemgrepRunner(graph=graph)

    runner.ingest("/some/repo", _REAL_SHAPE_OUTPUT)
    runner.ingest("/some/repo", _REAL_SHAPE_OUTPUT)

    assert len(graph.source_files()) == 1
