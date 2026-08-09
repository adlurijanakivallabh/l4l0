"""Tier-explicit recon + signal-gated wrappers — hermetic fixtures."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import Endpoint, Parameter, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.recon.tools import ReconOutcome, SignalGatedOutcome
from reachagent.recon.tools.arjun import ArjunRunner
from reachagent.recon.tools.commix import CommixRunner
from reachagent.recon.tools.dalfox import DalfoxRunner
from reachagent.recon.tools.jwt_tool import JwtToolRunner
from reachagent.recon.tools.paramspider import ParamSpiderRunner
from reachagent.recon.tools.signal_gated import reconfirm_candidate
from reachagent.recon.tools.x8 import X8Runner

_TARGET = "target.test"

_RECON_RUNNERS = [ArjunRunner, ParamSpiderRunner, X8Runner]
_SIGNALED = [DalfoxRunner, CommixRunner, JwtToolRunner]

_ARJUN_FIX = '{"parameters":["foo","bar"]}'
_PARAMSPIDER_FIX = "https://target.test/search?foo=1&bar=2\nhttps://target.test/api?baz=3\n"
_X8_FIX = "param 'foo' reflected\nparam 'bar' reflected\n"


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts(["target.test"])


def _graph_with_signal(kind: str) -> ReachabilityGraph:
    g = ReachabilityGraph()
    ep = g.add_endpoint(Endpoint(method="GET", path="/search"))
    if kind == "xss":
        g.add_parameter(
            ep, Parameter(name="q", location="query", inferred_sink_type=SinkType.HTML_REFLECTION)
        )
    elif kind == "shell":
        g.add_parameter(
            ep, Parameter(name="cmd", location="query", inferred_sink_type=SinkType.SHELL)
        )
    elif kind == "jwt":
        g.add_endpoint(Endpoint(method="GET", path="/api/auth/login"))
    return g


# -- Recon-tier: facts only (Arjun/ParamSpider/X8) --------------------------


@pytest.mark.parametrize(
    "runner_cls,fixture",
    [
        (ArjunRunner, _ARJUN_FIX),
        (ParamSpiderRunner, _PARAMSPIDER_FIX),
        (X8Runner, _X8_FIX),
    ],
)
def test_param_discovery_adds_parameters(runner_cls, fixture) -> None:  # noqa: ANN001
    g = ReachabilityGraph()
    runner = runner_cls(graph=g, scope=_scope())
    result = runner.ingest(_TARGET, fixture)
    assert result.outcome is ReconOutcome.INGESTED
    # Parameters must exist somewhere
    found = any(list(g.parameters_of(ep)) for ep, _ in g.endpoints())
    assert found
    assert g.findings() == []
    assert g.can_call_edges() == []
    kinds = {attrs["kind"] for _, attrs in g._g.nodes(data=True)}  # noqa: SLF001
    assert kinds <= {"host", "endpoint", "parameter"}


def test_recon_tier_imports_no_validator_or_candidate() -> None:
    import reachagent.recon.tools as pkg

    pkg_dir = Path(pkg.__file__).parent
    names = {"arjun.py", "paramspider.py", "x8.py"}
    forbidden = (
        "reachagent.tools.validator",
        "reachagent.tools.candidate",
        "OracleMechanism",
        "run_oracle",
        "write_finding",
    )
    offenders: list[str] = []
    for py in pkg_dir.glob("*.py"):
        if py.name not in names:
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if any(f in node.module for f in forbidden):
                    offenders.append(f"{py.name}: from {node.module}")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if any(f in alias.name for f in forbidden):
                        offenders.append(f"{py.name}: import {alias.name}")
    assert offenders == []


# -- Signal-gated: gating + candidate emission -------------------------------


def test_dalfox_gated_no_signal() -> None:
    g = ReachabilityGraph()
    runner = DalfoxRunner(graph=g, scope=_scope())
    result = runner.ingest(_TARGET, '{"url":"https://target.test/q?x=1","payload":"<svg>"}')
    assert result.outcome is SignalGatedOutcome.REFUSED_NO_SIGNAL
    assert result.candidates == ()


def test_dalfox_with_signal_emits_candidate() -> None:
    g = _graph_with_signal("xss")
    runner = DalfoxRunner(graph=g, scope=_scope())
    result = runner.ingest(
        _TARGET, '{"url":"https://target.test/q?x=1","payload":"<svg onload=1>"}'
    )
    assert result.outcome is SignalGatedOutcome.EMITTED_CANDIDATES
    assert len(result.candidates) == 1
    cand = result.candidates[0]
    assert cand.vuln_class == "xss_reflected"
    assert cand.suggested_oracle is OracleMechanism.EXECUTION_CONFIRMATION
    assert "CLAIM (unverified)" in cand.notes[0]


def test_commix_gated_and_emits() -> None:
    g = _graph_with_signal("shell")
    runner = CommixRunner(graph=g, scope=_scope())
    result = runner.ingest(_TARGET, "parameter 'cmd' seems to be vulnerable")
    assert result.outcome is SignalGatedOutcome.EMITTED_CANDIDATES
    assert result.candidates[0].vuln_class == "command_injection"
    assert result.candidates[0].suggested_oracle is OracleMechanism.OOB_CALLBACK


def test_jwt_tool_gated_and_emits() -> None:
    g = _graph_with_signal("jwt")
    runner = JwtToolRunner(graph=g, scope=_scope())
    result = runner.ingest(_TARGET, 'JWT alg "none" accepted — key confusion')
    assert result.outcome is SignalGatedOutcome.EMITTED_CANDIDATES
    assert result.candidates[0].vuln_class == "jwt_forgery"
    assert result.candidates[0].suggested_oracle is OracleMechanism.STRUCTURAL


def test_signal_gated_anti_fp_never_becomes_finding() -> None:
    """Unverified claim → inconclusive oracle → reconfirm returns None, no finding."""
    g = _graph_with_signal("xss")
    runner = DalfoxRunner(graph=g, scope=_scope())
    cands = runner.ingest(_TARGET, '{"url":"https://target.test/q","payload":"<svg>"}').candidates
    assert cands

    from reachagent.graph.nodes import FindingStatus
    from reachagent.oracles.base import OracleVerdict

    def stub_run_oracle(oracle, evidence):  # noqa: ANN001
        return OracleVerdict(
            mechanism=oracle, status=FindingStatus.INCONCLUSIVE, evidence_ref="test"
        )

    def fake_write(*_a, **_k):  # noqa: ANN002
        raise AssertionError("write_finding must not be called on inconclusive")

    def fake_factory(cand, verdict):  # noqa: ANN001
        return None

    result = reconfirm_candidate(
        cands[0],
        object(),
        run_oracle=stub_run_oracle,
        write_finding=fake_write,
        graph=g,
        finding_factory=fake_factory,
    )
    assert result is None
    assert g.findings() == []


# -- Shared safety: scope/audit/missing-binary/command -----------------------


@pytest.mark.parametrize("runner_cls", _RECON_RUNNERS)
def test_recon_out_of_scope_refused(runner_cls) -> None:  # noqa: ANN001
    g = ReachabilityGraph()
    scope = ScopeGuard.from_hosts(["in-scope.test"])
    runner = runner_cls(graph=g, scope=scope)
    result = runner.ingest("evil.test", "irrelevant")
    assert result.outcome is ReconOutcome.REFUSED_OUT_OF_SCOPE


@pytest.mark.parametrize("runner_cls", _SIGNALED)
def test_signaled_out_of_scope_refused(runner_cls) -> None:  # noqa: ANN001
    g = _graph_with_signal(
        "xss" if runner_cls is DalfoxRunner else "shell" if runner_cls is CommixRunner else "jwt"
    )
    scope = ScopeGuard.from_hosts(["in-scope.test"])
    runner = runner_cls(graph=g, scope=scope)
    # Even with valid signal, out-of-scope target is refused before spawn
    # Give a fixture that would otherwise emit; scope gate must win
    fixture = (
        '{"url":"https://evil.test/q","payload":"<svg>"}'
        if runner_cls is DalfoxRunner
        else "parameter 'cmd' seems to be vulnerable"
        if runner_cls is CommixRunner
        else 'alg "none" accepted'
    )
    result = runner.ingest("https://evil.test/q", fixture)
    assert result.outcome is SignalGatedOutcome.REFUSED_OUT_OF_SCOPE


@pytest.mark.parametrize("runner_cls", _RECON_RUNNERS + _SIGNALED)
def test_missing_binary_skipped(monkeypatch, runner_cls) -> None:  # noqa: ANN001
    import reachagent.recon.tools.base as base
    import reachagent.recon.tools.signal_gated as sg_base

    monkeypatch.setattr(base.shutil, "which", lambda _b: None)
    monkeypatch.setattr(
        base.subprocess,
        "run",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not spawn")),
    )
    monkeypatch.setattr(sg_base.shutil, "which", lambda _b: None)
    monkeypatch.setattr(
        sg_base.subprocess,
        "run",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not spawn")),
    )
    graph = ReachabilityGraph()
    if runner_cls in _SIGNALED:
        if runner_cls is DalfoxRunner:
            graph = _graph_with_signal("xss")
        elif runner_cls is CommixRunner:
            graph = _graph_with_signal("shell")
        else:
            graph = _graph_with_signal("jwt")
    runner = runner_cls(graph=graph, scope=_scope())
    if runner_cls in _RECON_RUNNERS:
        result = runner.run(_TARGET, environ={base.RECON_ENV_LIVE: "1"})
    else:
        result = runner.run(_TARGET, "out", environ={base.RECON_ENV_LIVE: "1"})
    assert result.outcome.name == "SKIPPED_MISSING_BINARY"


@pytest.mark.parametrize("runner_cls", _RECON_RUNNERS + _SIGNALED)
def test_command_is_array_shell_false(runner_cls) -> None:  # noqa: ANN001
    runner = runner_cls(graph=ReachabilityGraph(), scope=_scope())
    argv = (
        runner.command(_TARGET, "/tmp/out")  # noqa: S108 — test fixture path, not real file use
        if runner_cls in _SIGNALED
        else runner.command(_TARGET)
    )
    assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
    assert any(_TARGET in arg for arg in argv)
    assert not any(";" in a or "&&" in a or "|" in a for a in argv)
