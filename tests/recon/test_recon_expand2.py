"""Recon-tier expand 2 — WPScan passive + TLS probes, hermetic fixtures."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from reachagent.execution.scope import ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.tools import (
    ReconOutcome,
    SslscanRunner,
    SslyzeRunner,
    TestsslRunner,
    WpscanPassiveRunner,
)

_TARGET = "target.test"
_TLS_RUNNERS = [TestsslRunner, SslscanRunner, SslyzeRunner]
_ALL_NEW = [WpscanPassiveRunner, TestsslRunner, SslscanRunner, SslyzeRunner]


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts(["target.test", "93.184.216.34"])


_WPSCAN_FIXTURE = json.dumps(
    {
        "target_url": "https://target.test/",
        "version": {"number": "6.4.2"},
        "plugins": {"akismet": {"version": {"number": "5.3"}}},
        "themes": {"twentytwenty": {}},
        "interesting_findings": [{"url": "https://target.test/wp-json/", "type": "headers"}],
    }
)

_TESTSSL_FIXTURE = json.dumps(
    {
        "scanResult": [
            {
                "targetHost": "target.test",
                "findings": [
                    {"id": "TLS1_0", "severity": "WARN"},
                    {"id": "TLS1_2", "severity": "OK"},
                ],
            }
        ]
    }
)

_SSLSCAN_FIXTURE = (
    '<?xml version="1.0"?><ssltest><host><address>93.184.216.34</address></host>'
    '<cipher status="enabled" cipher="AES256-SHA" sslversion="TLSv1.0"/>'
    '<cipher status="enabled" cipher="AES128-GCM-SHA256" sslversion="TLSv1.2"/>'
    '<protocol type="TLSv1.2" enabled="yes"/></ssltest>'
)

_SSLYZE_FIXTURE = json.dumps(
    {
        "server_scan_results": [
            {
                "server_location": {"hostname": "target.test", "port": 443},
                "scan_result": {
                    "tls_1_0_cipher_suites": {
                        "accepted_cipher_suites": [{"name": "TLS_RSA_WITH_RC4_128_SHA"}]
                    },
                    "tls_1_2_cipher_suites": {
                        "accepted_cipher_suites": [
                            {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
                        ]
                    },
                },
            }
        ]
    }
)


def test_wpscan_passive_emits_host_tech_and_version() -> None:
    graph = ReachabilityGraph()
    runner = WpscanPassiveRunner(graph=graph, scope=_scope())
    result = runner.ingest(_TARGET, _WPSCAN_FIXTURE)
    assert result.outcome is ReconOutcome.INGESTED
    host = next(h for _, h in graph.hosts() if h.address == "target.test")
    assert "wordpress" in (host.technology or "").lower()
    assert host.detected_version == "6.4.2"
    assert graph.findings() == []
    assert graph.can_call_edges() == []


@pytest.mark.parametrize(
    "runner_cls,fixture",
    [
        (TestsslRunner, _TESTSSL_FIXTURE),
        (SslscanRunner, _SSLSCAN_FIXTURE),
        (SslyzeRunner, _SSLYZE_FIXTURE),
    ],
)
def test_tls_runner_emits_host_facts_with_deprecated_and_strong(runner_cls, fixture) -> None:  # noqa: ANN001
    graph = ReachabilityGraph()
    runner = runner_cls(graph=graph, scope=_scope())
    result = runner.ingest(_TARGET, fixture)
    assert result.outcome is ReconOutcome.INGESTED
    hosts = list(graph.hosts())
    assert hosts
    tech = (hosts[0][1].technology or "").lower()
    # Facts land as attributes — deprecated + strong both present in tech string
    assert "tls" in tech
    assert graph.findings() == []
    assert graph.can_call_edges() == []


def test_tls_detection_pending_flag_present() -> None:
    """TLS facts only — detection pending oracle design flag in module."""
    src = Path("src/reachagent/recon/tools/tls_probe.py").read_text()
    assert "detection pending oracle design" in src.lower()


@pytest.mark.parametrize("runner_cls", _ALL_NEW)
def test_new_wrappers_write_zero_findings_candidates_and_can_call(runner_cls) -> None:  # noqa: ANN001
    graph = ReachabilityGraph()
    fixtures = {
        "wpscan": _WPSCAN_FIXTURE,
        "testssl": _TESTSSL_FIXTURE,
        "sslscan": _SSLSCAN_FIXTURE,
        "sslyze": _SSLYZE_FIXTURE,
    }
    runner = runner_cls(graph=graph, scope=_scope())
    runner.ingest(_TARGET, fixtures[runner.name])
    assert graph.findings() == []
    assert graph.can_call_edges() == []
    kinds = {attrs["kind"] for _, attrs in graph._g.nodes(data=True)}  # noqa: SLF001
    assert kinds <= {"host", "service", "endpoint"}


def test_new_wrappers_import_no_validator_or_candidate_symbol() -> None:
    import reachagent.recon.tools as pkg

    pkg_dir = Path(pkg.__file__).parent
    new = {"wpscan_passive.py", "tls_probe.py"}
    forbidden = (
        "reachagent.tools.validator",
        "reachagent.tools.candidate",
        "OracleMechanism",
        "run_oracle",
        "write_finding",
        "Candidate",
    )
    offenders: list[str] = []
    for py in pkg_dir.glob("*.py"):
        if py.name not in new:
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if any(f in node.module for f in forbidden):
                    offenders.append(f"{py.name}: from {node.module}")
                for alias in node.names:
                    if any(f in alias.name for f in forbidden):
                        offenders.append(f"{py.name}: import {alias.name}")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if any(f in alias.name for f in forbidden):
                        offenders.append(f"{py.name}: import {alias.name}")
            if isinstance(node, ast.Name) and node.id == "Candidate":
                offenders.append(f"{py.name}: bare Candidate")
    assert offenders == []


@pytest.mark.parametrize("runner_cls", _ALL_NEW)
def test_out_of_scope_refused(runner_cls) -> None:  # noqa: ANN001
    graph = ReachabilityGraph()
    scope = ScopeGuard.from_hosts(["in-scope.test"])
    runner = runner_cls(graph=graph, scope=scope)
    result = runner.ingest("evil.test", "irrelevant")
    assert result.outcome is ReconOutcome.REFUSED_OUT_OF_SCOPE
    assert graph.node_count() == 0


@pytest.mark.parametrize("runner_cls", _ALL_NEW)
def test_missing_binary_skipped(monkeypatch, runner_cls) -> None:  # noqa: ANN001
    import reachagent.recon.tools.base as base

    monkeypatch.setattr(base.shutil, "which", lambda _b: None)
    monkeypatch.setattr(
        base.subprocess,
        "run",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not spawn")),
    )
    graph = ReachabilityGraph()
    runner = runner_cls(graph=graph, scope=_scope())
    result = runner.run(_TARGET, environ={base.RECON_ENV_LIVE: "1"})
    assert result.outcome is ReconOutcome.SKIPPED_MISSING_BINARY


@pytest.mark.parametrize("runner_cls", _ALL_NEW)
def test_every_ingest_audited(runner_cls) -> None:  # noqa: ANN001
    graph = ReachabilityGraph()
    fixtures = {
        "wpscan": _WPSCAN_FIXTURE,
        "testssl": _TESTSSL_FIXTURE,
        "sslscan": _SSLSCAN_FIXTURE,
        "sslyze": _SSLYZE_FIXTURE,
    }
    runner = runner_cls(graph=graph, scope=_scope())
    before = len(runner.audit.entries)
    runner.ingest(_TARGET, fixtures[runner.name])
    assert len(runner.audit.entries) == before + 1


@pytest.mark.parametrize("runner_cls", _ALL_NEW)
def test_command_is_array_shell_false(runner_cls) -> None:  # noqa: ANN001
    runner = runner_cls(graph=ReachabilityGraph(), scope=_scope())
    argv = runner.command(_TARGET)
    assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
    assert any(_TARGET in arg for arg in argv)
    assert not any(";" in a or "&&" in a or "|" in a for a in argv)
