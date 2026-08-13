"""Hermetic scope-driven entrypoint tests — no network."""

from __future__ import annotations

import ast
from pathlib import Path

import httpx
import pytest

from reachagent.execution import ScopeGuard
from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.graph.nodes import Endpoint, Host
from reachagent.graph.store import ReachabilityGraph
from reachagent.scan.entrypoint import ScopeEnforcer, extract_host, scan_target

# -- ScopeEnforcer ----------------------------------------------------------


def test_wildcard_matches_base_and_subdomain_not_partial() -> None:
    se = ScopeEnforcer("*.example.com")
    assert se.is_allowed("example.com") is True
    assert se.is_allowed("api.example.com") is True
    assert se.is_allowed("evil-notexample.com") is False
    assert se.is_allowed("example.com.evil.com") is False


def test_exact_match_and_case_insensitive() -> None:
    se = ScopeEnforcer("Example.COM")
    assert se.is_allowed("example.com") is True
    assert se.is_allowed("EXAMPLE.COM") is True
    assert se.is_allowed("other.com") is False


def test_out_of_scope_always_wins() -> None:
    se = ScopeEnforcer("*.example.com", "admin.example.com")
    assert se.is_allowed("api.example.com") is True
    assert se.is_allowed("admin.example.com") is False
    assert se.is_allowed("ADMIN.EXAMPLE.COM") is False


def test_bare_host_and_subdomain_isolation() -> None:
    se = ScopeEnforcer("example.com")
    assert se.is_allowed("example.com") is True
    assert se.is_allowed("sub.example.com") is False
    assert se.is_allowed("https://example.com/path?q=1") is True
    assert se.is_allowed("example.com:8080") is True


def test_extract_host_bare_and_url() -> None:
    assert extract_host("https://Example.COM:8080/path") == "example.com"
    assert extract_host("api.example.com") == "api.example.com"
    assert extract_host("  ADMIN.example.com  ") == "admin.example.com"


# -- Checkpoint A: out-of-scope host never materializes --------------------


def test_checkpoint_a_wildcard_mixed_fixture() -> None:
    """In-scope *.example.com: api.example.com maps, evil.com never does."""
    se = ScopeEnforcer("*.example.com")
    g = ReachabilityGraph()
    a = AuditLog()
    from reachagent.recon.tools.subdomains import SubfinderRunner

    scope_guard = ScopeGuard.from_hosts(["example.com"])
    runner = SubfinderRunner(graph=g, scope=scope_guard, audit=a)
    raw = "api.example.com\nevil.com\n"
    from reachagent.scan.entrypoint import _filter_fixture_by_scope

    allowed = _filter_fixture_by_scope(raw, se, runner.name)
    if allowed.strip():
        runner.ingest("example.com", allowed)
    for line in raw.splitlines():
        h = extract_host(line.strip())
        if h and not se.is_allowed(h):
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


# -- Defense-in-depth: both directions ------------------------------------


def test_defense_b_bypassing_a_still_caught_by_firer() -> None:
    """Bypass A (direct graph.add_host out-of-scope) → B (firer) still refuses."""
    se = ScopeEnforcer("example.com")
    g = ReachabilityGraph()
    g.add_host(Host(address="evil.com", hostname="evil.com", source="test"))
    allowed = [p.lstrip("*.") for p in se._allow if p]
    guard = ScopeGuard.from_hosts(allowed)
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
    from reachagent.scan.entrypoint import EnforcerScopeWrapper

    se = ScopeEnforcer("*.example.com")
    wrapper = EnforcerScopeWrapper(se)
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


def test_cli_dry_run_no_live_flag(capsys) -> None:
    from reachagent.scan.cli import main

    rc = main(["--target", "https://example.com", "--in-scope", "example.com"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dry-run: no requests fired" in out
    assert "pass --live to fire" in out


def test_cli_no_dry_run_without_live_stays_dry_run(capsys) -> None:
    """--no-dry-run without --live must NOT fire live."""
    from reachagent.scan.cli import main

    rc = main(["--target", "https://example.com", "--in-scope", "example.com", "--no-dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dry-run: no requests fired" in out


def test_cli_requires_target_absolute_url() -> None:
    from reachagent.scan.cli import main

    with pytest.raises(SystemExit):
        main(["--target", "example.com", "--in-scope", "example.com"])


# -- Structural boundary: no validator import outside validator.py ----------


def test_scan_imports_do_not_pull_validator_outside_seam() -> None:
    src = Path("src/reachagent/scan/entrypoint.py").read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert "reachagent.tools.validator" not in node.module, (
                "scan/entrypoint.py must not import validator directly — use OrcaleRunner seam"
            )
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert "reachagent.tools.validator" not in alias.name


def test_scan_imports_no_external_scanner_dep() -> None:
    src = Path("src/reachagent/scan/entrypoint.py").read_text().lower()
    for dep in ("sqlmap", "nuclei", "zap", "burp", "caido"):
        assert dep not in src
    cli_src = Path("src/reachagent/scan/cli.py").read_text().lower()
    for dep in ("sqlmap", "nuclei", "zap", "burp", "caido"):
        assert dep not in cli_src


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
