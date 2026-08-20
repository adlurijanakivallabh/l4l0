"""Recon-tier expansion — 8 fact-emitters, hermetic fixtures (no network)."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from reachagent.execution.scope import ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.tools import (
    DirbRunner,
    FeroxbusterRunner,
    FfufRunner,
    HttpxRunner,
    KatanaRunner,
    MasscanRunner,
    ReconOutcome,
    RustscanRunner,
    TheHarvesterRunner,
)

_TARGET = "target.test"
_EXPANDED_RUNNERS = [
    KatanaRunner,
    HttpxRunner,
    RustscanRunner,
    MasscanRunner,
    TheHarvesterRunner,
    FfufRunner,
    FeroxbusterRunner,
    DirbRunner,
]


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts(["target.test", "93.184.216.34"])


# -- Fixtures (real-shaped, hermetic) --------------------------------------


_KATANA = "https://target.test/api\nhttps://target.test/admin\nhttps://target.test/login\n"
_HTTPX_LINE = '{"url":"https://target.test/api","status_code":200,"tech":["nginx"],"webserver":"nginx","title":"ok"}\n'
_RUSTSCAN = "Open 80\nOpen 443\n80/tcp open http\n"
_MASSCAN_GREP = (
    "Discovered open port 80/tcp on 93.184.216.34\nDiscovered open port 443/tcp on 93.184.216.34\n"
)
_MASSCAN_XML = (
    '<?xml version="1.0"?><nmaprun><host><address addr="93.184.216.34"'
    ' addrtype="ipv4"/><ports><port protocol="tcp" portid="80">'
    '<state state="open"/><service name="http"/></port></ports></host></nmaprun>'
)
_HARVESTER = "api.target.test\nmail.target.test\nadmin@test.com\n# comment\nmail.target.test\n"
_FFUF_JSON = json.dumps(
    {
        "results": [
            {"url": "https://target.test/admin", "status": 200},
            {"url": "https://target.test/api", "status": 301},
        ]
    }
)
_FEROX_JSON = (
    '{"url":"https://target.test/secret","status":200}\n'
    '{"url":"https://target.test/hidden","status":302}\n'
)
_DIRB = (
    "+ https://target.test/admin (CODE:200|SIZE:1234)\n"
    "+ https://target.test/backup (CODE:301|SIZE:0)\n"
)

_FIXTURES = {
    "katana": _KATANA,
    "httpx": _HTTPX_LINE,
    "rustscan": _RUSTSCAN,
    "masscan": _MASSCAN_GREP,
    "theHarvester": _HARVESTER,
    "ffuf": _FFUF_JSON,
    "feroxbuster": _FEROX_JSON,
    "dirb": _DIRB,
}


@pytest.mark.parametrize("runner_cls", _EXPANDED_RUNNERS)
def test_expanded_runner_ingest_creates_facts(runner_cls) -> None:  # noqa: ANN001
    graph = ReachabilityGraph()
    runner = runner_cls(graph=graph, scope=_scope())
    fixture = _FIXTURES[runner.name]
    result = runner.ingest(_TARGET, fixture)
    assert result.outcome is ReconOutcome.INGESTED
    assert graph.hosts() or graph.endpoints() or graph.services()


def test_katana_emits_endpoints() -> None:
    graph = ReachabilityGraph()
    KatanaRunner(graph=graph, scope=_scope()).ingest(_TARGET, _KATANA)
    paths = {ep.path for _, ep in graph.endpoints()}
    assert "/api" in paths and "/admin" in paths
    assert graph.resolves_to_edges()


def test_httpx_emits_host_tech() -> None:
    graph = ReachabilityGraph()
    HttpxRunner(graph=graph, scope=_scope()).ingest(_TARGET, _HTTPX_LINE)
    assert any("nginx" in (h.technology or "").lower() for _, h in graph.hosts())


def test_rustscan_emits_services() -> None:
    graph = ReachabilityGraph()
    RustscanRunner(graph=graph, scope=_scope()).ingest(_TARGET, _RUSTSCAN)
    ports = {s.port for _, s in graph.services()}
    assert 80 in ports and 443 in ports


def test_masscan_grep_emits_services() -> None:
    graph = ReachabilityGraph()
    MasscanRunner(graph=graph, scope=_scope()).ingest(_TARGET, _MASSCAN_GREP)
    assert graph.services()


def test_masscan_xml_emits_services() -> None:
    graph = ReachabilityGraph()
    MasscanRunner(graph=graph, scope=_scope()).ingest(_TARGET, _MASSCAN_XML)
    assert graph.services()


def test_theharvester_emits_hosts_deduped() -> None:
    graph = ReachabilityGraph()
    TheHarvesterRunner(graph=graph, scope=_scope()).ingest(_TARGET, _HARVESTER)
    hosts = {h.hostname for _, h in graph.hosts()}
    assert "api.target.test" in hosts and "mail.target.test" in hosts
    assert "admin@test.com" not in hosts
    # dedup: mail appears twice → one host
    assert len([h for _, h in graph.hosts() if h.hostname == "mail.target.test"]) == 1


def test_ffuf_emits_endpoints() -> None:
    graph = ReachabilityGraph()
    FfufRunner(graph=graph, scope=_scope()).ingest(_TARGET, _FFUF_JSON)
    paths = {ep.path for _, ep in graph.endpoints()}
    assert "/admin" in paths


def test_feroxbuster_emits_endpoints() -> None:
    graph = ReachabilityGraph()
    FeroxbusterRunner(graph=graph, scope=_scope()).ingest(_TARGET, _FEROX_JSON)
    paths = {ep.path for _, ep in graph.endpoints()}
    assert "/secret" in paths


def test_dirb_emits_endpoints() -> None:
    graph = ReachabilityGraph()
    DirbRunner(graph=graph, scope=_scope()).ingest(_TARGET, _DIRB)
    paths = {ep.path for _, ep in graph.endpoints()}
    assert "/admin" in paths


# -- Zero findings/candidate/can_call --------------------------------------


@pytest.mark.parametrize("runner_cls", _EXPANDED_RUNNERS)
def test_expanded_wrappers_write_zero_findings_candidates_and_can_call(runner_cls) -> None:  # noqa: ANN001
    graph = ReachabilityGraph()
    runner = runner_cls(graph=graph, scope=_scope())
    runner.ingest(_TARGET, _FIXTURES[runner.name])
    assert graph.findings() == []
    assert graph.can_call_edges() == []
    kinds = {attrs["kind"] for _, attrs in graph._g.nodes(data=True)}  # noqa: SLF001
    assert kinds <= {"host", "service", "endpoint"}


# -- AST: no validator / OracleMechanism / Candidate --------------------------


def test_expanded_wrappers_import_no_validator_or_candidate_symbol() -> None:
    import reachagent.recon.tools as pkg

    pkg_dir = Path(pkg.__file__).parent
    expanded = {
        "katana.py",
        "httpx_runner.py",
        "rustscan.py",
        "masscan.py",
        "theharvester.py",
        "ffuf.py",
        "feroxbuster.py",
        "dirb.py",
    }
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
        if py.name not in expanded:
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if any(f in node.module for f in forbidden):
                    offenders.append(f"{py.name}: from {node.module}")
                for alias in node.names:
                    if any(f in alias.name for f in forbidden):
                        offenders.append(f"{py.name}: from {node.module} import {alias.name}")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if any(f in alias.name for f in forbidden):
                        offenders.append(f"{py.name}: import {alias.name}")
            if isinstance(node, ast.Name) and node.id == "Candidate":
                offenders.append(f"{py.name}: bare Candidate symbol")
    assert offenders == []


# -- Scope + audit + missing-binary (Big Task 1 pattern) --------------------


@pytest.mark.parametrize("runner_cls", _EXPANDED_RUNNERS)
def test_out_of_scope_refused(runner_cls) -> None:  # noqa: ANN001
    graph = ReachabilityGraph()
    scope = ScopeGuard.from_hosts(["in-scope.test"])
    runner = runner_cls(graph=graph, scope=scope)
    result = runner.ingest("evil.test", "irrelevant")
    assert result.outcome is ReconOutcome.REFUSED_OUT_OF_SCOPE
    assert graph.node_count() == 0


@pytest.mark.parametrize("runner_cls", _EXPANDED_RUNNERS)
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


@pytest.mark.parametrize("runner_cls", _EXPANDED_RUNNERS)
def test_every_ingest_audited(runner_cls) -> None:  # noqa: ANN001
    graph = ReachabilityGraph()
    runner = runner_cls(graph=graph, scope=_scope())
    before = len(runner.audit.entries)
    runner.ingest(_TARGET, _FIXTURES[runner.name])
    assert len(runner.audit.entries) == before + 1


@pytest.mark.parametrize("runner_cls", _EXPANDED_RUNNERS)
def test_command_is_array_shell_false(runner_cls) -> None:  # noqa: ANN001
    runner = runner_cls(graph=ReachabilityGraph(), scope=_scope())
    argv = runner.command(_TARGET)
    assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
    assert any(_TARGET in arg for arg in argv)
    assert not any(";" in a or "&&" in a or "|" in a for a in argv)
