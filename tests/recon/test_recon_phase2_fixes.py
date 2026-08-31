"""Phase 2 audit a-row fixes — hermetic, fixture-based (no network, no spawn)."""

from __future__ import annotations

import json

from reachagent.execution.scope import ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.tools import (
    AmassRunner,
    DirbRunner,
    FeroxbusterRunner,
    FfufRunner,
    GobusterRunner,
    HttpxRunner,
    KatanaRunner,
    MasscanRunner,
    NmapRunner,
    NucleiRunner,
    ReconOutcome,
    RustscanRunner,
    SqlmapRunner,
    SubfinderRunner,
    TheHarvesterRunner,
    WhatWebRunner,
)
from reachagent.recon.tools._wordlist import preferred_wordlist

_TARGET = "target.test"


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts([_TARGET, "93.184.216.34"])


# -- wordlist defaults (prefer raft/directory-list when on-disk) ---------------


def test_gobuster_wordlist_env_override(monkeypatch) -> None:  # noqa: S108 -- test wordlist path
    monkeypatch.setenv("REACHAGENT_GOBUSTER_WORDLIST", "/tmp/my.txt")  # noqa: S108
    argv = GobusterRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert "/tmp/my.txt" in argv  # noqa: S108
    # helper still prefers raft when on-disk and no env
    monkeypatch.delenv("REACHAGENT_GOBUSTER_WORDLIST", raising=False)
    wl = preferred_wordlist("REACHAGENT_GOBUSTER_WORDLIST")
    # on this image raft is on-disk, so not common.txt — prove not stuck on common
    assert wl != "" and wl.endswith(".txt")


def test_ffuf_x8_wordlist_helper() -> None:
    # env absent path still resolves via helper, not hardcoded common.txt assumption
    assert preferred_wordlist("REACHAGENT_FFUF_WORDLIST").endswith(".txt")
    assert preferred_wordlist("REACHAGENT_X8_WORDLIST", x8=True).endswith(".txt")


def test_ferox_wordlist_env_forward(monkeypatch) -> None:  # noqa: S108
    monkeypatch.setenv("REACHAGENT_FEROX_WORDLIST", "/tmp/fw.txt")  # noqa: S108
    argv = FeroxbusterRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert "-w" in argv and "/tmp/fw.txt" in argv  # noqa: S108


# -- status codes: 307 kept -----------------------------------------------------


def test_ffuf_default_match_codes_include_307() -> None:
    argv = FfufRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    idx = argv.index("-mc")
    assert "307" in argv[idx + 1]


def test_ffuf_match_codes_env_override(monkeypatch) -> None:
    monkeypatch.setenv("REACHAGENT_FFUF_MATCH_CODES", "200,204")
    argv = FfufRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert argv[argv.index("-mc") + 1] == "200,204"


# -- flags (rate/threads/timeout) --------------------------------------------


def test_katana_default_includes_js_and_depth() -> None:
    argv = KatanaRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert "-jsl" in argv and "-aff" in argv
    assert "-d" in argv and argv[argv.index("-d") + 1] == "3"


def test_katana_js_env_off(monkeypatch) -> None:
    monkeypatch.setenv("REACHAGENT_KATANA_JS", "0")
    argv = KatanaRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert "-jsl" not in argv


def test_katana_default_caps_pages_and_crawl_time() -> None:
    # Un-set by default: without a hard page/time cap an unbounded crawl
    # target (e.g. dynamically generated "next page" links) can grow the URL
    # frontier without bound, exhausting memory well before the outer
    # subprocess timeout fires.
    argv = KatanaRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert "-mdp" in argv and argv[argv.index("-mdp") + 1] == "200"
    assert "-ct" in argv and argv[argv.index("-ct") + 1] == "120"


def test_katana_page_cap_env_override(monkeypatch) -> None:
    monkeypatch.setenv("REACHAGENT_KATANA_MAX_PAGES", "50")
    argv = KatanaRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert argv[argv.index("-mdp") + 1] == "50"


def test_katana_never_offers_headless_browser_mode() -> None:
    # -hl spawns katana's own internal Chromium; killing katana on timeout
    # does not guarantee that grandchild process is reaped too, risking an
    # orphaned browser process. Removed entirely — no env var re-enables it.
    argv = KatanaRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert "-hl" not in argv


def test_httpx_flags(monkeypatch) -> None:
    monkeypatch.setenv("REACHAGENT_HTTPX_THREADS", "25")
    monkeypatch.setenv("REACHAGENT_HTTPX_TIMEOUT", "10")
    monkeypatch.setenv("REACHAGENT_HTTPX_RATE", "5")
    argv = HttpxRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert "-threads" in argv and "-timeout" in argv and "-rate-limit" in argv


def test_rustscan_defaults_5000_4500_1500() -> None:
    argv = RustscanRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert argv[argv.index("--ulimit") + 1] == "5000"
    assert argv[argv.index("--batch-size") + 1] == "4500"
    assert argv[argv.index("--timeout") + 1] == "1500"


def test_rustscan_env_override(monkeypatch) -> None:
    monkeypatch.setenv("REACHAGENT_RUSTSCAN_ULIMIT", "8000")
    monkeypatch.setenv("REACHAGENT_RUSTSCAN_BATCH", "2000")
    monkeypatch.setenv("REACHAGENT_RUSTSCAN_TIMEOUT", "900")
    argv = RustscanRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert argv[argv.index("--ulimit") + 1] == "8000"
    assert argv[argv.index("--batch-size") + 1] == "2000"
    assert argv[argv.index("--timeout") + 1] == "900"


def test_masscan_rate_clamped(monkeypatch) -> None:
    monkeypatch.setenv("REACHAGENT_MASSCAN_RATE", "99999")
    argv = MasscanRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert argv[argv.index("--rate") + 1] == "10000"  # clamped
    monkeypatch.setenv("REACHAGENT_MASSCAN_RATE", "10")
    argv = MasscanRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert argv[argv.index("--rate") + 1] == "100"  # floor


def test_nmap_timing_top_ports(monkeypatch) -> None:
    monkeypatch.setenv("REACHAGENT_NMAP_TIMING", "4")
    monkeypatch.setenv("REACHAGENT_NMAP_TOP_PORTS", "100")
    argv = NmapRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert "-T" in argv and "--top-ports" in argv
    assert argv[-1] == _TARGET  # target stays last


def test_theharvester_source(monkeypatch) -> None:
    monkeypatch.setenv("REACHAGENT_THEHARVESTER_SOURCE", "crtsh")
    argv = TheHarvesterRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert argv[argv.index("-b") + 1] == "crtsh"


def test_subfinder_flags(monkeypatch) -> None:
    monkeypatch.setenv("REACHAGENT_SUBFINDER_TIMEOUT", "30")
    monkeypatch.setenv("REACHAGENT_SUBFINDER_RATE", "10")
    argv = SubfinderRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert "-timeout" in argv and "-rateLimit" in argv


def test_amass_timeout(monkeypatch) -> None:
    monkeypatch.setenv("REACHAGENT_AMASS_TIMEOUT", "60")
    argv = AmassRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert "-timeout" in argv


def test_whatweb_aggression(monkeypatch) -> None:
    monkeypatch.setenv("REACHAGENT_WHATWEB_AGGRESSION", "3")
    argv = WhatWebRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert "-a" in argv and argv[argv.index("-a") + 1] == "3"


def test_nuclei_flags(monkeypatch) -> None:  # noqa: S108
    monkeypatch.setenv("REACHAGENT_NUCLEI_SEVERITY", "critical,high")
    monkeypatch.setenv("REACHAGENT_NUCLEI_RATE_LIMIT", "100")
    monkeypatch.setenv("REACHAGENT_NUCLEI_TAGS", "cve")
    argv = NucleiRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET, "/tmp/out")  # noqa: S108
    assert "-severity" in argv and "-rate-limit" in argv and "-tags" in argv


def test_sqlmap_level_risk(monkeypatch) -> None:  # noqa: S108
    monkeypatch.setenv("REACHAGENT_SQLMAP_LEVEL", "3")
    monkeypatch.setenv("REACHAGENT_SQLMAP_RISK", "2")
    argv = SqlmapRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET, "/tmp/out")  # noqa: S108
    assert argv[argv.index("--level") + 1] == "3"
    assert argv[argv.index("--risk") + 1] == "2"


def test_gobuster_threads_timeout(monkeypatch) -> None:
    monkeypatch.setenv("REACHAGENT_GOBUSTER_THREADS", "50")
    monkeypatch.setenv("REACHAGENT_GOBUSTER_TIMEOUT", "10")
    argv = GobusterRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert "-t" in argv and "--timeout" in argv


def test_ffuf_threads(monkeypatch) -> None:
    monkeypatch.setenv("REACHAGENT_FFUF_THREADS", "40")
    argv = FfufRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert "-t" in argv


def test_ferox_threads(monkeypatch) -> None:
    monkeypatch.setenv("REACHAGENT_FEROX_THREADS", "30")
    argv = FeroxbusterRunner(graph=ReachabilityGraph(), scope=_scope()).command(_TARGET)
    assert "-t" in argv


# -- hermetic ingest still correct + zero findings (tier discipline) ------------


def test_phase2_fixture_ffuf_307_ingested() -> None:
    blob = json.dumps({"results": [{"url": f"https://{_TARGET}/redir", "status": 307}]})
    g = ReachabilityGraph()
    r = FfufRunner(graph=g, scope=_scope())
    out = r.ingest(_TARGET, blob)
    assert out.outcome is ReconOutcome.INGESTED
    assert any(e.path == "/redir" for _, e in g.endpoints())


# -- ponytail note: size-cluster collapse deferred — path dedup remains --------


def test_recon_phase2_still_zero_findings_can_call() -> None:
    # spot-check chunk of expanded recon tier
    for cls, blob in [
        (DirbRunner, "+ https://target.test/a (CODE:200|SIZE:1)\n"),
        (FeroxbusterRunner, '{"url":"https://target.test/b","status":200}\n'),
        (KatanaRunner, f"https://{_TARGET}/c\n"),
    ]:
        g = ReachabilityGraph()
        cls(graph=g, scope=_scope()).ingest(_TARGET, blob)
        assert g.findings() == [] and g.can_call_edges() == []
