"""Hermetic test for run_whitebox_analysis (Build Order 7) -- proves it wires
all three tools together safely with no live binaries/network available
(the default, gated-off state every unit test runs under)."""

from __future__ import annotations

from reachagent.graph.store import ReachabilityGraph
from reachagent.whitebox.analysis import run_whitebox_analysis


def test_run_whitebox_analysis_never_touches_finding(tmp_path) -> None:  # noqa: ANN001
    graph = ReachabilityGraph()

    summary = run_whitebox_analysis(repo_path=str(tmp_path), graph=graph)

    assert isinstance(summary, dict)
    assert set(summary) == {"source_files", "secrets", "package_dependencies", "static_advisories"}
    # Not live-gated (REACHAGENT_RECON_LIVE unset) and no manifests present --
    # zero facts, but never an exception, and never anything Finding-shaped.
    assert graph.findings() == []


def test_run_whitebox_analysis_still_runs_sca_even_without_live_tools(
    tmp_path,
    monkeypatch,  # noqa: ANN001
) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.6.0\n")

    import reachagent.whitebox.analysis as analysis_module

    class _FailingClient:
        def get(self, url, *, params):  # noqa: ANN001, ANN201
            raise AssertionError("no real network call expected in a hermetic test")

    real_scan_dependencies = analysis_module.scan_dependencies
    monkeypatch.setattr(
        analysis_module,
        "scan_dependencies",
        lambda repo_path, graph, **_kw: real_scan_dependencies(
            repo_path, graph, client=_FailingClient()
        ),
    )

    graph = ReachabilityGraph()
    run_whitebox_analysis(repo_path=str(tmp_path), graph=graph)

    # Manifest parsing + dependency-node writing is pure Python (no external
    # binary, no live-gate) -- it runs even when semgrep/trufflehog are
    # skipped for being un-gated, and even when CVE lookup itself fails open.
    deps = graph.package_dependencies()
    assert len(deps) == 1
    assert deps[0][1].name == "requests"
    assert graph.static_advisories() == []
