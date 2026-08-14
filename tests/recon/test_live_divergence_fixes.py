"""Live-divergence fixes: banner filter, slashless paths, probe seeding, no-reselect."""

from __future__ import annotations

import httpx

from reachagent.execution.audit import AuditLog
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.tools.gobuster import GobusterRunner
from reachagent.recon.tools.theharvester import TheHarvesterRunner
from reachagent.scan.entrypoint import scan_target

_TARGET = "target.test"


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts([_TARGET, "localhost"])


# -- 1. theHarvester banner noise -------------------------------------------------


def test_theharvester_banner_noise_filtered_real_hosts_kept() -> None:
    raw = "\n".join(
        [
            "!] Missing API key for Bitbucket.",
            "*] Searching CRTsh.",
            "* theHarvester 4.10.1",
            "api.target.test",
            "mail.target.test",
            "api.target.test",  # dup → one host
            "https://evil.com/path",  # path/query → noise
        ]
    )
    g = ReachabilityGraph()
    a = AuditLog()
    TheHarvesterRunner(graph=g, scope=_scope(), audit=a).ingest("target.test", raw)
    hosts = {h.hostname for _, h in g.hosts()}
    assert hosts == {"api.target.test", "mail.target.test"}
    # One audited skip summary, not per-line spam.
    noise = [e for e in a.entries if e.outcome.startswith("skipped_banner_noise")]
    assert len(noise) == 1
    assert noise[0].outcome == "skipped_banner_noise:4"


def test_theharvester_clean_lines_still_pass() -> None:
    g = ReachabilityGraph()
    a = AuditLog()
    TheHarvesterRunner(graph=g, scope=_scope(), audit=a).ingest(
        "target.test", "api.target.test\nmail.target.test\n"
    )
    assert any(h.hostname == "api.target.test" for _, h in g.hosts())
    assert not any(e.outcome.startswith("skipped_banner_noise") for e in a.entries)


# -- 2. gobuster slashless paths --------------------------------------------------


def test_gobuster_slashless_paths_materialize_with_leading_slash() -> None:
    raw = (
        "console              (Status: 200)\n"
        "me                   (Status: 401)\n"
        "ui                   (Status: 308)\n"
    )
    g = ReachabilityGraph()
    a = AuditLog()
    GobusterRunner(graph=g, scope=_scope(), audit=a).ingest(f"https://{_TARGET}", raw)
    paths = {ep.path for _, ep in g.endpoints()}
    assert paths == {"/console", "/me", "/ui"}
    # 401 → restricted tag.
    me = next(ep for _, ep in g.endpoints() if ep.path == "/me")
    assert me.access_restricted == "401"


def test_gobuster_slash_and_slashless_dedup_to_one() -> None:
    raw = "console              (Status: 200)\n/console             (Status: 200)\n"
    g = ReachabilityGraph()
    a = AuditLog()
    GobusterRunner(graph=g, scope=_scope(), audit=a).ingest(f"https://{_TARGET}", raw)
    assert len(list(g.endpoints())) == 1
    assert list(g.endpoints())[0][1].path == "/console"


# -- 3+4. parameter-less seeding + no-reselect ------------------------------------


def test_parameterless_endpoint_gets_probe_seeded_and_chain_attempted() -> None:
    # A bare endpoint (no parameter) → a probe param is seeded and a real probe
    # fire happens through the payload chain (MockTransport records it).
    fired: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        fired.append(request.url.path)
        if "reachagent-cal" in request.url.path:
            return httpx.Response(404, text="missing")  # no wildcard — fixtures survive
        q = request.url.params.get("q", request.url.params.get("probe", ""))
        if "../" in q:
            return httpx.Response(200, text="root:x:0:0:root:/root")
        return httpx.Response(200, text="ok")

    g = ReachabilityGraph()
    a = AuditLog()
    result = scan_target(
        base_url=f"https://{_TARGET}",
        in_scope="target.test",
        dry_run=False,
        transport=httpx.MockTransport(handler),
        fixtures={"gobuster": "/items (Status: 200)\n"},
        graph=g,
        audit=a,
    )
    # A real fire happened (probe seeded → fingerprint canary → fire).
    assert any("reachagent-canary" in p or "items" in p for p in fired)
    assert result["dry_run"] is False


def test_no_reselect_dead_candidate_moves_on() -> None:
    # First endpoint always 404 (dead). The loop must move on to the second
    # instead of reselecting the dead one for all 20 iterations.
    g = ReachabilityGraph()
    a = AuditLog()
    fired_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/dead", "/alive"):
            fired_paths.append(request.url.path)
        if request.url.path == "/dead":
            return httpx.Response(404, text="not found")
        if request.url.path == "/alive":
            return httpx.Response(200, text="ok")
        # Spec probes, fallback, and calibration all 404 — api_discovery finds
        # nothing, so the loop only sees the gobuster-discovered /dead and /alive.
        return httpx.Response(404, text="missing")

    result = scan_target(
        base_url=f"https://{_TARGET}",
        in_scope="target.test",
        dry_run=False,
        transport=httpx.MockTransport(handler),
        fixtures={"gobuster": "/dead (Status: 200)\n/alive (Status: 200)\n"},
        graph=g,
        audit=a,
    )
    # The dead endpoint is fired exactly once, then the loop moves on — it is not
    # reselected for all 20 iterations.
    assert fired_paths.count("/dead") == 1
    assert "/alive" in fired_paths
    assert result["iterations"] < 20  # loop terminated before burning all iterations


# -- Component 1 (Task 27): theHarvester bare-IP / OSINT filter -----------------


def test_theharvester_bare_ips_filtered_not_hosts() -> None:
    raw = "\n".join(
        [
            "!] Missing API key for Bitbucket.",
            "api.target.test",
            "103.178.166.178",
            "172.66.44.206",
            "2001:db8::1",
            "admin.localhost",
            "mail.target.test",
        ]
    )
    g = ReachabilityGraph()
    a = AuditLog()
    TheHarvesterRunner(graph=g, scope=_scope(), audit=a).ingest("target.test", raw)
    hosts = {h.hostname for _, h in g.hosts()}
    assert hosts == {"api.target.test", "mail.target.test", "admin.localhost"}
    # Bare IPs counted as noise (not Hosts); localhost dictionary names kept.
    noise = [e for e in a.entries if e.outcome.startswith("skipped_banner_noise")]
    assert len(noise) == 1
    assert noise[0].outcome == "skipped_banner_noise:4"  # banner + 2 IPs + IPv6
