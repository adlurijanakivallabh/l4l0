"""Hermetic scope-driven entrypoint tests — no network."""

from __future__ import annotations

import ast
from pathlib import Path

import httpx
import pytest

from reachagent.execution import ScopeGuard
from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeRule  # noqa: F401
from reachagent.graph.nodes import Endpoint, Host
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.entrypoint import scan_target
from tests._oracle_test_support import CONFIRMS, FixedJudgmentClient

# -- ScopeGuard (canonical scope semantics — wildcard/case/deny precedence) --


def test_wildcard_matches_base_and_subdomain_not_partial() -> None:
    guard = ScopeGuard.from_hosts(["*.example.com"])
    assert guard.is_in_scope("https://example.com/") is True
    assert guard.is_in_scope("https://api.example.com/") is True
    assert guard.is_in_scope("https://evil-notexample.com/") is False
    assert guard.is_in_scope("https://example.com.evil.com/") is False


def test_exact_match_and_case_insensitive() -> None:
    rule = ScopeRule(host="Example.COM")
    parsed = httpx.URL("https://example.com/")
    assert rule.matches(parsed) is True
    rule2 = ScopeRule(host="EXAMPLE.COM")
    assert rule2.matches(httpx.URL("https://EXAMPLE.com/")) is True
    assert rule2.matches(httpx.URL("https://other.com/")) is False


def test_out_of_scope_always_wins() -> None:
    guard = ScopeGuard.from_hosts(
        ["*.example.com"],
        deny_hosts=["admin.example.com"],
    )
    assert guard.is_in_scope("https://api.example.com/") is True
    assert guard.is_in_scope("https://admin.example.com/") is False


def test_bare_host_isolation_via_rule() -> None:
    rule = ScopeRule(host="example.com")
    assert rule.matches(httpx.URL("https://example.com/path")) is True
    assert rule.matches(httpx.URL("https://sub.example.com/")) is False


# -- Checkpoint A: out-of-scope host never materializes --------------------


def test_checkpoint_a_wildcard_mixed_fixture() -> None:
    """In-scope *.example.com: api.example.com maps, evil.com never does."""
    se = ScopeGuard.from_hosts(["*.example.com"])
    g = ReachabilityGraph()
    a = AuditLog()
    from reachagent.recon.tools.subdomains import SubfinderRunner

    scope_guard = se
    runner = SubfinderRunner(graph=g, scope=scope_guard, audit=a)
    raw = "api.example.com\nevil.com\n"
    from reachagent.scan.entrypoint import _filter_fixture_by_scope

    allowed = _filter_fixture_by_scope(raw, se, runner.name)
    if allowed.strip():
        runner.ingest("example.com", allowed)
    for line in raw.splitlines():
        h = line.strip().split("/")[0]
        if h and not se.is_in_scope(h):
            a.record(runner.name, "RECON", h, "refused_out_of_scope")
    hosts = {host.address for _, host in g.hosts()}
    assert "api.example.com" in hosts
    assert "evil.com" not in hosts
    assert any(e.target == "evil.com" for e in a.entries if e.outcome == "refused_out_of_scope")


def test_gobuster_endpoints_not_host_filtered() -> None:
    """gobuster paths are endpoints on target_host, not host-per-line — both must persist."""
    g = ReachabilityGraph()
    a = AuditLog()
    result = scan_target(
        base_url="https://example.com",
        in_scope="example.com",
        dry_run=True,
        graph=g,
        audit=a,
        fixtures={"gobuster": "/items (Status: 200)\n/admin (Status: 200)\n"},
    )
    assert result["dry_run"] is True
    paths = {ep.path for _, ep in g.endpoints()}
    assert "/items" in paths
    assert "/admin" in paths


_NMAP_FIXTURE_XML = (
    '<?xml version="1.0"?><nmaprun><host><address addr="93.184.216.34"'
    ' addrtype="ipv4"/><ports><port protocol="tcp" portid="80">'
    '<state state="open"/><service name="http"/></port></ports></host></nmaprun>'
)


def test_skip_tools_excludes_a_named_recon_tool_entirely() -> None:
    """v3 V1: an operator-named tool to skip must never even be considered —
    not run initially, not offered to the adaptive selector."""
    g = ReachabilityGraph()
    a = AuditLog()
    events: list = []
    scan_target(
        base_url="https://example.com",
        in_scope="example.com",
        dry_run=True,
        graph=g,
        audit=a,
        events=events,
        recon_tools=["nmap", "gobuster"],
        skip_tools=["nmap"],
        fixtures={
            "nmap": _NMAP_FIXTURE_XML,
            "gobuster": "/items (Status: 200)\n",
        },
    )
    tool_names = {e.details.get("tool") for e in events if "tool" in e.details}
    assert "nmap" not in tool_names
    assert "gobuster" in tool_names
    # nmap's own fixture was never even parsed, so its host never materialized.
    assert "93.184.216.34" not in {host.address for _, host in g.hosts()}


def test_skip_tools_is_case_insensitive_and_a_noop_when_empty() -> None:
    g = ReachabilityGraph()
    a = AuditLog()
    events: list = []
    scan_target(
        base_url="https://example.com",
        in_scope="example.com",
        dry_run=True,
        graph=g,
        audit=a,
        events=events,
        recon_tools=["nmap"],
        skip_tools=["NMAP"],
        fixtures={"nmap": _NMAP_FIXTURE_XML},
    )
    tool_names = {e.details.get("tool") for e in events if "tool" in e.details}
    assert "nmap" not in tool_names

    g2 = ReachabilityGraph()
    events2: list = []
    scan_target(
        base_url="https://example.com",
        in_scope="example.com",
        dry_run=True,
        graph=g2,
        audit=AuditLog(),
        events=events2,
        recon_tools=["nmap"],
        skip_tools=None,
        fixtures={"nmap": _NMAP_FIXTURE_XML},
    )
    tool_names2 = {e.details.get("tool") for e in events2 if "tool" in e.details}
    assert "nmap" in tool_names2


# -- Defense-in-depth: both directions ------------------------------------


def test_defense_b_bypassing_a_still_caught_by_firer() -> None:
    """Bypass A (direct graph.add_host out-of-scope) → B (firer) still refuses."""
    guard = ScopeGuard.from_hosts(["example.com"])
    g = ReachabilityGraph()
    g.add_host(Host(address="evil.com", hostname="evil.com", source="test"))
    audit = AuditLog()
    firer = RequestFirer(httpx.Client(), guard, audit)
    from reachagent.execution.scope import OutOfScopeError

    with pytest.raises(OutOfScopeError):
        firer.fire("tester", "GET", "https://evil.com/secret", state_changing=False)


def test_defense_a_bypassing_b_still_caught_by_graph_gating() -> None:
    """Bypass B (firer bug) but A already filtered discovery → never selected."""
    g = ReachabilityGraph()
    a = AuditLog()
    from reachagent.recon.tools.subdomains import SubfinderRunner

    guard = ScopeGuard.from_hosts(["example.com"])
    runner = SubfinderRunner(graph=g, scope=guard, audit=a)
    runner.ingest("example.com", "api.example.com\n")
    assert not any(h.address == "evil.com" for _, h in g.hosts())
    g.add_endpoint(Endpoint(method="GET", path="/items"))
    assert not any("evil.com" in str(ep.path) for _, ep in g.endpoints())


def test_firer_wildcard_allows_subdomain() -> None:
    """B must honor *.example.com — api.example.com fires, evil.com refused."""
    from reachagent.execution.scope import OutOfScopeError

    wrapper = ScopeGuard.from_hosts(["*.example.com"])
    audit = AuditLog()

    def ok_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    firer = RequestFirer(
        httpx.Client(transport=httpx.MockTransport(ok_handler)),
        wrapper,
        audit,  # type: ignore[arg-type]
    )
    # In-scope subdomain must not raise — use MockTransport so no real DNS.
    firer.fire("t", "GET", "https://api.example.com/items", state_changing=False)
    # Out-of-scope must still be refused by B
    with pytest.raises(OutOfScopeError):
        firer.fire("t", "GET", "https://evil.com/items", state_changing=False)


# -- Full cold-start → finding → chain requery (hermetic) -----------------


def test_full_cold_start_to_finding_and_chain_requery() -> None:
    from reachagent.execution.audit import AuditLog
    from reachagent.graph.store import ReachabilityGraph

    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("id", "")
        if q.startswith("reachagent-canary-"):
            return httpx.Response(200, text=q, headers={"content-type": "text/plain"})
        if "../" in q or "..%2f" in q.lower():
            return httpx.Response(200, text="root:x:0:0:root:/root")
        if q == "baseline":
            return httpx.Response(200, text="ok")
        return httpx.Response(200, text="ok")

    g = ReachabilityGraph()
    a = AuditLog()
    result = scan_target(
        base_url="https://example.com",
        in_scope="example.com",
        dry_run=False,
        max_attempts=6,
        graph=g,
        audit=a,
        transport=httpx.MockTransport(handler),
        fixtures={
            "subfinder": "api.example.com\n",
            "gobuster": "/items (Status: 200)\n",
        },
    )
    assert result["dry_run"] is False
    assert len(list(g.endpoints())) >= 1
    assert len(list(g.hosts())) >= 1


# -- Dry-run: plan without firing -----------------------------------------


def test_dry_run_returns_plan_without_firing() -> None:
    from reachagent.execution.audit import AuditLog
    from reachagent.graph.store import ReachabilityGraph

    g = ReachabilityGraph()
    a = AuditLog()
    result = scan_target(
        base_url="https://example.com",
        in_scope="example.com",
        dry_run=True,
        graph=g,
        audit=a,
        fixtures={"subfinder": "api.example.com\n"},
    )
    assert result["dry_run"] is True
    assert isinstance(result["plan"], list)
    assert result["fired"] == 0
    assert not any(e.outcome.startswith("fired:") for e in a.entries)
    assert len(result["graph"].findings()) == 0
    assert len(list(result["graph"].endpoints())) >= 1


# -- Structural boundary: no validator import outside validator.py ----------


def test_scan_imports_do_not_pull_validator_outside_seam() -> None:
    src = Path("src/reachagent/scan/entrypoint.py").read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert "reachagent.tools.validator" not in node.module, (
                "scan/entrypoint.py must not import validator directly — use OracleRunner seam"
            )
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert "reachagent.tools.validator" not in alias.name


def test_scan_imports_no_external_scanner_dep() -> None:
    """No external scanner as a DEPENDENCY — an AST import check, not a raw text
    grep (§9, C5). A prose comment or docstring naming a signal-gated wrapper by
    way of explanation (e.g. describing what recon/tools/signal_gated.py
    dispatches) is not a dependency; only an actual import is. Scope is
    deliberately just these two core-orchestration files — recon/tools/ itself
    legitimately wraps these binaries as gated, never-authoritative candidate
    sources (§9 signal-gated tier), which is a different thing entirely.
    """
    scanners = ("sqlmap", "nuclei", "zap", "burp", "caido")
    for path in (
        Path("src/reachagent/scan/entrypoint.py"),
        Path("src/reachagent/scan/orchestrator.py"),
    ):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module, *(alias.name for alias in node.names)]
            elif isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            else:
                continue
            for name in names:
                lowered = name.lower()
                hit = next((s for s in scanners if s in lowered), None)
                assert hit is None, f"{path}: import {name!r} pulls in scanner dep {hit!r}"


# -- Live cold-start recon (prereq commit) --------------------------------------


def _ok_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"ok")

    return httpx.MockTransport(handler)


def test_live_cold_start_invokes_runner_run(monkeypatch) -> None:  # noqa: ANN001
    """fixtures=None + live → dispatched runners spawn via runner.run()."""
    import reachagent.recon.tools.base as base

    calls: list[tuple[str, str]] = []
    original_run = base.ReconToolRunner.run

    def spy_run(self, target: str, *, environ: dict[str, str] | None = None):
        calls.append((self.name, target))
        return original_run(self, target, environ=environ)

    monkeypatch.setattr(base.ReconToolRunner, "run", spy_run)
    scan_target(
        base_url="https://example.com",
        in_scope="*.example.com",
        dry_run=False,
        transport=_ok_transport(),
    )
    # Domain target dispatches to content-discovery runners and they are run live.
    assert any(name == "gobuster" for name, _t in calls)
    assert any(name == "subfinder" for name, _t in calls)


def test_live_recon_unset_env_skips_not_live(monkeypatch) -> None:  # noqa: ANN001
    """Without REACHAGENT_RECON_LIVE the live run() is a clean SKIPPED_NOT_LIVE."""
    import reachagent.recon.tools.base as base

    calls: list[tuple[str, str]] = []
    original_run = base.ReconToolRunner.run

    def spy_run(self, target: str, *, environ: dict[str, str] | None = None):
        calls.append((self.name, target))
        return original_run(self, target, environ=environ)

    monkeypatch.setattr(base.ReconToolRunner, "run", spy_run)
    g = ReachabilityGraph()
    a = AuditLog()
    scan_target(
        base_url="https://example.com",
        in_scope="*.example.com",
        dry_run=False,
        transport=_ok_transport(),
        graph=g,
        audit=a,
    )
    assert calls
    outcomes = [e.outcome for e in a.entries if e.identity in ("gobuster", "subfinder")]
    assert any(o == "skipped_not_live" for o in outcomes)


def test_fixtures_path_never_invokes_live_run(monkeypatch) -> None:  # noqa: ANN001
    """Fixtures present → ingest only; runner.run() must never be called."""
    import reachagent.recon.tools.base as base

    def boom(self, target: str, *, environ: dict[str, str] | None = None):
        raise AssertionError("live run must not be invoked on the fixtures path")

    monkeypatch.setattr(base.ReconToolRunner, "run", boom)
    result = scan_target(
        base_url="https://example.com",
        in_scope="*.example.com",
        dry_run=True,
        fixtures={"gobuster": "/items (Status: 200)\n"},
    )
    paths = {ep.path for _, ep in result["graph"].endpoints()}
    assert "/items" in paths


# -- Scheme-aware dispatch (live-run defect fix) --------------------------------


def test_scheme_bearing_host_port_is_url_not_tls() -> None:
    from reachagent.scan.entrypoint import detect_target_type

    assert detect_target_type("http://localhost:5000") == "url"  # regression
    assert detect_target_type("https://example.com:8443/path") == "url"
    # Bare host:port without a scheme stays TLS-probe territory.
    assert detect_target_type("localhost:5000") == "host_port"
    assert detect_target_type("10.0.0.5:8080") == "host_port"


def test_http_port_target_dispatches_http_discovery_not_tls() -> None:
    # http://localhost:5000 must select the domain/url runner set (subfinder etc),
    # NOT the TLS probes (sslscan/sslyze) — the live-run defect.
    g = ReachabilityGraph()
    a = AuditLog()
    scan_target(
        base_url="http://localhost:5000",
        in_scope="*.localhost",
        dry_run=True,
        graph=g,
        audit=a,
        fixtures={
            "subfinder": "api.localhost\n",
            "sslscan": "<ssltest><cipher status='enabled'/></ssltest>\n",
        },
    )
    assert any(h.hostname == "api.localhost" for _, h in g.hosts())
    # sslscan is NOT in the url runner set — its fixture is never ingested.
    assert not any(h.address == "localhost" and "sslscan" in (h.source or "") for _, h in g.hosts())


# -- Findings-list dedup (cosmetic alignment with graph node count) ---------------


_DUP_SURFACE = """\
endpoints:
  - method: GET
    path: /users/v1
  - method: GET
    path: /users/v1/{username}
    parameters:
      - name: username
        location: path
  - method: GET
    path: /products/v1
  - method: GET
    path: /products/v1/{product}
    parameters:
      - name: product
        location: path
"""


def _dup_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/users/v1":
        return httpx.Response(200, json={"users": [{"username": "name1"}]})
    if path == "/products/v1":
        return httpx.Response(200, json={"products": [{"name": "prod1"}]})
    if path in ("/users/v1/name1", "/products/v1/prod1"):
        return httpx.Response(200, json={"username": "name1"})
    if path.endswith("reachagent-canary-7f3a2b"):
        return httpx.Response(404, text="User not found")
    if path.endswith("'"):
        return httpx.Response(500, text="sqlalchemy.exc.OperationalError: unrecognized token")
    return httpx.Response(404, text="not found")


def test_findings_list_dedups_same_evidence(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    # v3 (CLAUDE.md): confirmation is now an LLM judgment, not the removed
    # decide() logic, and scan_target's full pipeline has no client= seam to
    # inject through. Fix the LLM provider factory that
    # reachagent.oracles.llm_judgment.judge() falls back to, so this test still
    # verifies its actual target: dedup of the returned findings list against
    # the graph's node count when both endpoints confirm the same evidence_ref.
    from pathlib import Path as _Path

    import reachagent.oracles.llm_judgment as _llm_judgment

    monkeypatch.setattr(
        _llm_judgment, "build_openai_compatible_client", lambda: FixedJudgmentClient(CONFIRMS.value)
    )
    surface = _Path(tmp_path) / "surface.yaml"
    surface.write_text(_DUP_SURFACE)
    result = scan_target(
        base_url="https://example.com",
        in_scope="*.example.com",
        dry_run=False,
        transport=httpx.MockTransport(_dup_handler),
        surface_path=str(surface),
    )
    # Both SQLi endpoints confirm the same evidence_ref → same finding node id.
    # The returned list must dedup to match the graph's node count.
    assert len(result["findings"]) == 1
    assert len(result["graph"].findings()) == 1
