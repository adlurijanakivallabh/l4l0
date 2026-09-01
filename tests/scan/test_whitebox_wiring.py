"""scan_all_classes(repo_path=...) -> whitebox.analysis wiring (Build Order 7).

run_whitebox_analysis itself is fully covered by tests/whitebox/; this file
only proves the orchestrator wiring: called only when repo_path is given,
its facts land in the scan's own graph, and a failure never aborts the scan.
"""

from __future__ import annotations

import httpx

import reachagent.scan.orchestrator as _orchestrator
from reachagent.scan.orchestrator import scan_all_classes


def _clean_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(404, text="not found")


def test_repo_path_none_never_calls_whitebox_analysis(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    from reachagent.payloads import PayloadLibrary

    calls: list[str] = []
    monkeypatch.setattr(
        "reachagent.whitebox.analysis.run_whitebox_analysis",
        lambda **kw: calls.append(kw.get("repo_path")),
    )

    scan_all_classes(
        base_url="https://safe.example",
        in_scope="safe.example",
        transport=httpx.MockTransport(_clean_handler),
        library=PayloadLibrary.from_file(),
    )

    assert calls == []


def test_repo_path_given_calls_whitebox_analysis_and_merges_its_facts(
    tmp_path,
    monkeypatch,  # noqa: ANN001
) -> None:
    from reachagent.graph.nodes import SourceFile
    from reachagent.payloads import PayloadLibrary

    def fake_run_whitebox_analysis(*, repo_path, graph, audit=None):  # noqa: ANN001
        graph.add_source_file(
            SourceFile(path="app/db.py", rule_id="python.sql-injection", line=42, message="x")
        )
        return {
            "source_files": 1,
            "secrets": 0,
            "package_dependencies": 0,
            "static_advisories": 0,
        }

    monkeypatch.setattr(
        "reachagent.whitebox.analysis.run_whitebox_analysis", fake_run_whitebox_analysis
    )

    result = scan_all_classes(
        base_url="https://safe.example",
        in_scope="safe.example",
        transport=httpx.MockTransport(_clean_handler),
        library=PayloadLibrary.from_file(),
        repo_path=str(tmp_path),
    )

    assert len(result["graph"].source_files()) == 1
    assert result["graph"].findings() == []  # never a Finding either way


def test_whitebox_analysis_failure_never_aborts_the_scan(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    from reachagent.payloads import PayloadLibrary

    def _boom(**kwargs):  # noqa: ANN003
        raise RuntimeError("semgrep crashed")

    monkeypatch.setattr("reachagent.whitebox.analysis.run_whitebox_analysis", _boom)

    events: list = []
    result = scan_all_classes(
        base_url="https://safe.example",
        in_scope="safe.example",
        transport=httpx.MockTransport(_clean_handler),
        library=PayloadLibrary.from_file(),
        repo_path=str(tmp_path),
        events=events,
    )

    assert result["graph"].findings() == []
    assert any(e.kind == "error" and "white-box analysis failed" in e.message for e in events)


def test_static_facts_reach_the_class_priority_signals(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    """End-to-end proof that a white-box fact written during scan_all_classes
    actually reaches rank_vuln_classes's prompt, not just the graph."""
    from reachagent.graph.nodes import SourceFile
    from reachagent.llm import runtime as _runtime
    from reachagent.payloads import PayloadLibrary

    monkeypatch.setattr(_runtime, "flag_enabled", lambda _name: True)

    def fake_run_whitebox_analysis(*, repo_path, graph, audit=None):  # noqa: ANN001
        graph.add_source_file(
            SourceFile(path="app/db.py", rule_id="python.sql-injection", line=42, message="x")
        )
        return {
            "source_files": 1,
            "secrets": 0,
            "package_dependencies": 0,
            "static_advisories": 0,
        }

    monkeypatch.setattr(
        "reachagent.whitebox.analysis.run_whitebox_analysis", fake_run_whitebox_analysis
    )

    captured_prompts: list[str] = []
    real_rank = _orchestrator.rank_vuln_classes

    def _spy_rank(class_names, graph, *, operator_prompt=None, client=None):  # noqa: ANN001
        signals = _orchestrator._class_priority_signals(graph, operator_prompt)
        if "static_analysis_hits" in signals:
            captured_prompts.append(signals["static_analysis_hits"])
        return real_rank(class_names, graph, operator_prompt=operator_prompt, client=client)

    monkeypatch.setattr(_orchestrator, "rank_vuln_classes", _spy_rank)

    scan_all_classes(
        base_url="https://safe.example",
        in_scope="safe.example",
        transport=httpx.MockTransport(_clean_handler),
        library=PayloadLibrary.from_file(),
        repo_path=str(tmp_path),
    )

    assert any("python.sql-injection" in p for p in captured_prompts)
