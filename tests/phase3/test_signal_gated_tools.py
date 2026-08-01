"""Signal-gated exploitation-tool wrappers — candidate emitters (plan §7, §9, §13; v1.8).

Asserts the Big-Task-2 core invariant, all network-free (recorded fixtures, no real
binaries): **a signal-gated tool's output is an unverified candidate, never a
confirmation.** The §9 flow proven here end to end:

    existing graph signal for the class
      → invoke tool (gated; ungated → refused + audited, no spawn)
      → parse tool CLAIM into an inert Explorer ``Candidate`` (class + suggested_oracle)
      → ``run_oracle`` re-confirms INDEPENDENTLY
      → ``write_finding`` only on that independent ``is_violation`` verdict

Covered: per-tool claim-parse → correct candidate; signal-gate refusal with no class
signal (per tool); scope refusal before spawn; missing-binary skip; command-array /
``shell=False`` / hostile-target-one-element; a tool candidate whose oracle re-check
is inconclusive/denied → ZERO findings; a tool candidate independently
confirmed_violation → one finding whose ``oracle_used`` is the real §7 mechanism, not
the tool; an AST scan proving the emitters import no ``write_finding``/``run_oracle``;
and the env-gated live path skipped by default.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from reachagent.execution.scope import ScopeGuard
from reachagent.graph.nodes import (
    Endpoint,
    Finding,
    FindingStatus,
    Host,
    Parameter,
    Service,
    SinkType,
)
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.oracles.differential import (
    DiffAxis,
    DifferentialEvidence,
    DiffExpectation,
    Observation,
)
from reachagent.recon.tools import (
    NiktoRunner,
    NucleiRunner,
    SignalGatedOutcome,
    SqlmapRunner,
    reconfirm_candidate,
)
from reachagent.tools.candidate import Candidate
from reachagent.tools.validator import run_oracle, write_finding

_FIXTURES = Path(__file__).parent / "fixtures" / "recon"
_TARGET = "target.test"


def _fixture(name: str) -> str:
    return (_FIXTURES / name).read_text(encoding="utf-8")


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts(["target.test"])


# ---------------------------------------------------------------------------
# graph-signal builders: put a REACHAGENT-owned signal in the graph so a tool
# is gated ON. Each mirrors the §9 named activation for one tool.
# ---------------------------------------------------------------------------


def _graph_with_sql_signal() -> ReachabilityGraph:
    """A Parameter fingerprinted inferred_sink_type == sql — sqlmap's gate (§9)."""
    g = ReachabilityGraph()
    ep = g.add_endpoint(Endpoint(method="GET", path="/item.php"))
    g.add_parameter(ep, Parameter(name="id", location="query", inferred_sink_type=SinkType.SQL))
    return g


def _graph_with_tech_signal() -> ReachabilityGraph:
    """A Host technology/version fingerprint — nuclei's gate (§9)."""
    g = ReachabilityGraph()
    g.add_host(
        Host(
            address="target.test",
            source="whatweb",
            technology="WordPress",
            detected_version="6.4.2",
        )
    )
    return g


def _graph_with_service_signal() -> ReachabilityGraph:
    """A scanned Service — nikto's server/tech gate (§9)."""
    g = ReachabilityGraph()
    host = g.add_host(Host(address="target.test", source="nmap"))
    g.add_service(
        host, Service(port=80, protocol="tcp", service_name="http", detected_version="nginx/1.24.0")
    )
    return g


# ===========================================================================
# 1. Per-tool claim-parse → correct candidate (class + suggested_oracle)
# ===========================================================================


def test_sqlmap_parses_confirmed_rows_only_into_sqli_candidates() -> None:
    runner = SqlmapRunner(graph=_graph_with_sql_signal(), scope=_scope())
    result = runner.ingest(_TARGET, _fixture("sqlmap-results.csv"))
    assert result.outcome is SignalGatedOutcome.EMITTED_CANDIDATES
    # 5 CSV rows; only 3 have Parameter+Technique populated (2 empty rows skipped).
    assert len(result.candidates) == 3
    assert all(c.vuln_class == "sqli" for c in result.candidates)
    # Technique → §7 oracle routing: BEU→differential, T→timing, S→oob.
    oracles = [c.suggested_oracle for c in result.candidates]
    assert oracles == [
        OracleMechanism.DIFFERENTIAL,
        OracleMechanism.TIMING_STATISTICAL,
        OracleMechanism.OOB_CALLBACK,
    ]


def test_nuclei_parses_jsonl_into_class_tagged_candidates() -> None:
    runner = NucleiRunner(graph=_graph_with_tech_signal(), scope=_scope())
    result = runner.ingest(_TARGET, _fixture("nuclei-results.jsonl"))
    assert result.outcome is SignalGatedOutcome.EMITTED_CANDIDATES
    assert len(result.candidates) == 4
    by_class = {c.vuln_class: c.suggested_oracle for c in result.candidates}
    # template-id keyword → class + §7 oracle it routes to for re-confirmation.
    assert by_class["path_traversal"] is OracleMechanism.STRUCTURAL  # CVE traversal template
    assert by_class["sqli"] is OracleMechanism.DIFFERENTIAL
    assert by_class["xss_reflected"] is OracleMechanism.EXECUTION_CONFIRMATION
    assert by_class["cve_match"] is OracleMechanism.STRUCTURAL  # unmapped tech-detect → default


def test_nikto_parses_vulnerabilities_into_candidates() -> None:
    runner = NiktoRunner(graph=_graph_with_service_signal(), scope=_scope())
    result = runner.ingest(_TARGET, _fixture("nikto-results.json"))
    assert result.outcome is SignalGatedOutcome.EMITTED_CANDIDATES
    assert len(result.candidates) == 3
    by_class = {c.vuln_class: c.suggested_oracle for c in result.candidates}
    assert by_class["path_traversal"] is OracleMechanism.STRUCTURAL
    assert by_class["xss_reflected"] is OracleMechanism.EXECUTION_CONFIRMATION
    assert by_class["server_misconfiguration"] is OracleMechanism.STRUCTURAL  # ETag msg → default


def test_candidates_carry_unverified_claim_provenance() -> None:
    runner = SqlmapRunner(graph=_graph_with_sql_signal(), scope=_scope())
    result = runner.ingest(_TARGET, _fixture("sqlmap-results.csv"))
    first = result.candidates[0]
    assert any("unverified" in note.lower() for note in first.notes)
    assert any("run_oracle" in note for note in first.notes)


# ===========================================================================
# 2. Signal-gate refusal when no class signal present (per tool)
# ===========================================================================


def test_sqlmap_not_invoked_without_sql_signal() -> None:
    # Empty graph — no Parameter with inferred_sink_type == sql.
    runner = SqlmapRunner(graph=ReachabilityGraph(), scope=_scope())
    result = runner.ingest(_TARGET, _fixture("sqlmap-results.csv"))
    assert result.outcome is SignalGatedOutcome.REFUSED_NO_SIGNAL
    assert result.candidates == ()


def test_nuclei_not_invoked_without_tech_signal() -> None:
    runner = NucleiRunner(graph=ReachabilityGraph(), scope=_scope())
    result = runner.ingest(_TARGET, _fixture("nuclei-results.jsonl"))
    assert result.outcome is SignalGatedOutcome.REFUSED_NO_SIGNAL
    assert result.candidates == ()


def test_nikto_not_invoked_without_server_signal() -> None:
    runner = NiktoRunner(graph=ReachabilityGraph(), scope=_scope())
    result = runner.ingest(_TARGET, _fixture("nikto-results.json"))
    assert result.outcome is SignalGatedOutcome.REFUSED_NO_SIGNAL
    assert result.candidates == ()


def test_signal_gate_refusal_is_audited() -> None:
    runner = SqlmapRunner(graph=ReachabilityGraph(), scope=_scope())
    runner.ingest(_TARGET, _fixture("sqlmap-results.csv"))
    outcomes = [e.outcome for e in runner.audit.entries]
    assert str(SignalGatedOutcome.REFUSED_NO_SIGNAL) in outcomes


def test_sql_signal_only_from_reachagent_probe_not_the_tool_output() -> None:
    # The gate reads a graph Parameter sink — NOT sqlmap's CSV. A populated CSV
    # against an unsignalled graph is still refused: the tool's own claim never
    # gates itself.
    runner = SqlmapRunner(graph=ReachabilityGraph(), scope=_scope())
    result = runner.ingest(_TARGET, _fixture("sqlmap-results.csv"))
    assert result.outcome is SignalGatedOutcome.REFUSED_NO_SIGNAL


# ===========================================================================
# 3. Independent re-confirmation is mandatory (the anti-false-positive gate)
# ===========================================================================


def _finding_factory(candidate: Candidate, verdict: object) -> Finding:
    """Build the Finding the Validator commits from a re-confirmed candidate.

    oracle_used is left blank so write_finding stamps it from the verdict's own
    mechanism — the real §7 family, never the tool name.
    """
    return Finding(
        vuln_class=candidate.vuln_class,
        severity="high",
        oracle_used="",  # write_finding stamps the real oracle mechanism
        evidence_ref="",
    )


def _differential_evidence(*, granted: bool) -> DifferentialEvidence:
    """A refused→(granted|refused) auth-bypass diff — violation iff granted."""
    return DifferentialEvidence(
        axis=DiffAxis.CROSS_CONDITION,
        expectation=DiffExpectation.AUTH_BYPASS,
        baseline=Observation("benign", 401, "unauthorized"),
        probe=Observation("injected", 200 if granted else 401, "ok" if granted else "no"),
        evidence_ref="sqli/independent-recheck",
    )


def test_tool_candidate_not_confirmed_writes_zero_findings() -> None:
    # THE anti-false-positive test: sqlmap CLAIMED SQLi, but ReachAgent's own
    # differential oracle, run over independent evidence, does NOT confirm
    # (refused→refused = confirmed_denied, not a violation). No Finding is written.
    graph = _graph_with_sql_signal()
    runner = SqlmapRunner(graph=graph, scope=_scope())
    candidate = runner.ingest(_TARGET, _fixture("sqlmap-results.csv")).candidates[0]

    node = reconfirm_candidate(
        candidate,
        _differential_evidence(granted=False),  # oracle disagrees with the tool
        run_oracle=run_oracle,
        write_finding=write_finding,
        graph=graph,
        finding_factory=_finding_factory,
    )
    assert node is None  # claim dropped — not confirmed
    assert graph.findings() == []  # zero findings written


def test_tool_candidate_independently_confirmed_writes_one_finding_with_real_oracle() -> None:
    # Independent confirmation path: the same candidate, but ReachAgent's own
    # differential oracle DOES confirm (refused→granted = confirmed_violation).
    # Exactly one Finding is written, and oracle_used is the real §7 mechanism.
    graph = _graph_with_sql_signal()
    runner = SqlmapRunner(graph=graph, scope=_scope())
    candidate = runner.ingest(_TARGET, _fixture("sqlmap-results.csv")).candidates[0]
    assert candidate.suggested_oracle is OracleMechanism.DIFFERENTIAL

    node = reconfirm_candidate(
        candidate,
        _differential_evidence(granted=True),  # oracle independently confirms
        run_oracle=run_oracle,
        write_finding=write_finding,
        graph=graph,
        finding_factory=_finding_factory,
    )
    assert node is not None
    findings = graph.findings()
    assert len(findings) == 1
    _fnode, finding = findings[0]
    assert finding.status is FindingStatus.CONFIRMED_VIOLATION
    # oracle_used records the real §7 family that re-confirmed it — NOT "sqlmap".
    assert finding.oracle_used == OracleMechanism.DIFFERENTIAL.value
    assert "sqlmap" not in finding.oracle_used


def test_reconfirm_uses_the_candidates_suggested_oracle() -> None:
    # The oracle run is the candidate's suggested_oracle, chosen by ReachAgent's
    # technique→family routing, not by the tool. Proven by capturing the mechanism
    # passed to a spy run_oracle.
    graph = _graph_with_sql_signal()
    runner = SqlmapRunner(graph=graph, scope=_scope())
    candidate = runner.ingest(_TARGET, _fixture("sqlmap-results.csv")).candidates[1]  # T → timing
    assert candidate.suggested_oracle is OracleMechanism.TIMING_STATISTICAL

    seen: list[object] = []

    def spy_run_oracle(mechanism: object, evidence: object) -> object:
        seen.append(mechanism)

        class _V:
            is_violation = False

        return _V()

    node = reconfirm_candidate(
        candidate,
        object(),
        run_oracle=spy_run_oracle,
        write_finding=write_finding,
        graph=graph,
        finding_factory=_finding_factory,
    )
    assert node is None
    assert seen == [OracleMechanism.TIMING_STATISTICAL]


# ===========================================================================
# 4. Safety: scope-before-spawn, missing-binary skip, command-array, env-gate
# ===========================================================================


@pytest.mark.parametrize(
    ("runner_cls", "graph_fn", "fixture"),
    [
        (SqlmapRunner, _graph_with_sql_signal, "sqlmap-results.csv"),
        (NucleiRunner, _graph_with_tech_signal, "nuclei-results.jsonl"),
        (NiktoRunner, _graph_with_service_signal, "nikto-results.json"),
    ],
)
def test_out_of_scope_target_refused_and_audited_no_candidates(
    runner_cls, graph_fn, fixture
) -> None:
    runner = runner_cls(graph=graph_fn(), scope=_scope())
    result = runner.ingest("evil.example.com", _fixture(fixture))
    assert result.outcome is SignalGatedOutcome.REFUSED_OUT_OF_SCOPE
    assert result.candidates == ()
    assert str(SignalGatedOutcome.REFUSED_OUT_OF_SCOPE) in [e.outcome for e in runner.audit.entries]


def test_live_run_refuses_out_of_scope_before_spawning(monkeypatch) -> None:
    # The live path must scope-check before any spawn. If subprocess.run is reached
    # for an out-of-scope target, this test fails loudly.
    import reachagent.recon.tools.signal_gated as sg

    def _boom(*a, **k):
        raise AssertionError("subprocess.run must not be called for an out-of-scope target")

    monkeypatch.setattr(sg.subprocess, "run", _boom)
    runner = SqlmapRunner(graph=_graph_with_sql_signal(), scope=_scope())
    result = runner.run("evil.example.com", "out.txt", environ={"REACHAGENT_RECON_LIVE": "1"})
    assert result.outcome is SignalGatedOutcome.REFUSED_OUT_OF_SCOPE


def test_live_run_refuses_ungated_before_spawning(monkeypatch) -> None:
    # Even live + in-scope + binary present: no class signal → no spawn.
    import reachagent.recon.tools.signal_gated as sg

    def _boom(*a, **k):
        raise AssertionError("subprocess.run must not be called without a class signal")

    monkeypatch.setattr(sg.subprocess, "run", _boom)
    monkeypatch.setattr(sg.shutil, "which", lambda _b: "/usr/bin/sqlmap")
    runner = SqlmapRunner(graph=ReachabilityGraph(), scope=_scope())  # no signal
    result = runner.run(_TARGET, "out.txt", environ={"REACHAGENT_RECON_LIVE": "1"})
    assert result.outcome is SignalGatedOutcome.REFUSED_NO_SIGNAL


def test_missing_binary_skips_cleanly(monkeypatch) -> None:
    import reachagent.recon.tools.signal_gated as sg

    monkeypatch.setattr(sg.shutil, "which", lambda _b: None)  # binary absent
    runner = NucleiRunner(graph=_graph_with_tech_signal(), scope=_scope())
    result = runner.run(_TARGET, "out.txt", environ={"REACHAGENT_RECON_LIVE": "1"})
    assert result.outcome is SignalGatedOutcome.SKIPPED_MISSING_BINARY
    assert str(SignalGatedOutcome.SKIPPED_MISSING_BINARY) in [
        e.outcome for e in runner.audit.entries
    ]


@pytest.mark.parametrize(
    ("runner_cls", "graph_fn"),
    [
        (SqlmapRunner, _graph_with_sql_signal),
        (NucleiRunner, _graph_with_tech_signal),
        (NiktoRunner, _graph_with_service_signal),
    ],
)
def test_command_is_array_with_target_as_distinct_element(runner_cls, graph_fn) -> None:
    runner = runner_cls(graph=graph_fn(), scope=_scope())
    argv = runner.command(_TARGET, "out.txt")
    assert isinstance(argv, list)
    assert all(isinstance(a, str) for a in argv)
    assert _TARGET in argv  # target is its own element, never interpolated


def test_hostile_target_stays_a_single_arg_element() -> None:
    runner = SqlmapRunner(graph=_graph_with_sql_signal(), scope=_scope())
    hostile = "target.test; rm -rf /"
    argv = runner.command(hostile, "out.txt")
    assert hostile in argv  # one inert element — not split, not interpolated
    assert "rm" not in argv  # never became its own token


def test_live_spawn_uses_shell_false_and_array(monkeypatch, tmp_path) -> None:
    import reachagent.recon.tools.signal_gated as sg

    captured: dict[str, object] = {}

    def _fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["shell"] = kwargs.get("shell")

        class _P:
            returncode = 0

        return _P()

    monkeypatch.setattr(sg.shutil, "which", lambda _b: "/usr/bin/sqlmap")
    monkeypatch.setattr(sg.subprocess, "run", _fake_run)
    # Pre-seed the output file the parser reads (pytest tmp_path — never /tmp literal).
    out = tmp_path / "sqlmap-out.csv"
    out.write_text(_fixture("sqlmap-results.csv"), encoding="utf-8")
    runner = SqlmapRunner(graph=_graph_with_sql_signal(), scope=_scope())
    runner.run(_TARGET, str(out), environ={"REACHAGENT_RECON_LIVE": "1"})
    assert isinstance(captured["argv"], list)
    assert captured["shell"] is False


def test_live_path_skipped_when_not_env_gated() -> None:
    runner = SqlmapRunner(graph=_graph_with_sql_signal(), scope=_scope())
    result = runner.run(_TARGET, "out.txt", environ={})  # env flag unset
    assert result.outcome is SignalGatedOutcome.SKIPPED_NOT_LIVE


# ===========================================================================
# 5. Emitters write nothing to the graph and import no confirmation path
# ===========================================================================


def test_emitters_write_zero_findings_candidates_and_can_call() -> None:
    # Run all three into one graph (each gated ON via a pre-seeded signal). After
    # every emission, the graph holds ZERO findings and ZERO can_call edges, and no
    # candidate is a graph node — candidates are returned, never written.
    graph = ReachabilityGraph()
    # Seed all three signals in one graph.
    ep = graph.add_endpoint(Endpoint(method="GET", path="/item.php"))
    graph.add_parameter(ep, Parameter(name="id", location="query", inferred_sink_type=SinkType.SQL))
    host = graph.add_host(Host(address="target.test", source="whatweb", technology="WordPress"))
    graph.add_service(host, Service(port=80, protocol="tcp", service_name="http"))

    node_count_before = len(list(graph._g.nodes()))  # noqa: SLF001
    SqlmapRunner(graph=graph, scope=_scope()).ingest(_TARGET, _fixture("sqlmap-results.csv"))
    NucleiRunner(graph=graph, scope=_scope()).ingest(_TARGET, _fixture("nuclei-results.jsonl"))
    NiktoRunner(graph=graph, scope=_scope()).ingest(_TARGET, _fixture("nikto-results.json"))

    assert graph.findings() == []
    assert graph.can_call_edges() == []
    # The emitters added no nodes at all — candidates are inert return values.
    assert len(list(graph._g.nodes())) == node_count_before  # noqa: SLF001


def test_signal_gated_emitters_import_no_validator_or_finding_writer() -> None:
    # AST scan (like the recon test): no emitter module imports run_oracle /
    # write_finding / mark_inconclusive or the validator module. The only path to a
    # Finding is reconfirm_candidate's injected callables — never a tool's own import.
    import reachagent.recon.tools.nikto as nikto_mod
    import reachagent.recon.tools.nuclei as nuclei_mod
    import reachagent.recon.tools.sqlmap as sqlmap_mod

    banned = {"run_oracle", "write_finding", "mark_inconclusive"}
    for mod in (sqlmap_mod, nuclei_mod, nikto_mod):
        src = Path(mod.__file__).read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert "validator" not in (node.module or ""), f"{mod.__name__} imports validator"
                for alias in node.names:
                    assert alias.name not in banned, f"{mod.__name__} imports {alias.name}"
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "validator" not in alias.name, f"{mod.__name__} imports {alias.name}"
