"""Recon-tier expansion 3 — naabu, dnsx, shuffledns, waybackurls, gau, wafw00f.

Hermetic fixture-based tests (no network). Each new wrapper parses recorded
tool output into graph facts through the same scope-gated base as every other
recon runner. Also covers the output-truncation helper in base.
"""

from __future__ import annotations

import json

import pytest

from reachagent.execution.scope import ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.tools import (
    DnsxRunner,
    GauRunner,
    NaabuRunner,
    ReconOutcome,
    ShuffleDnsRunner,
    Wafw00fRunner,
    WaybackUrlsRunner,
)
from reachagent.recon.tools.base import _truncate_output

_TARGET = "target.test"


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts([_TARGET])


# -- Fixtures ---------------------------------------------------------------

_NAABU_TEXT = "1.2.3.4:80\n1.2.3.4:443\n1.2.3.4:8080\n"
_NAABU_JSON = json.dumps({"host": "93.184.216.34", "port": 443}) + "\n"
_DNSX = "api.target.test [10.0.0.1]\nmail.target.test [10.0.0.2, 10.0.0.3]\n# comment\n"
_SHUFFLEDNS = "dev.target.test\nstaging.target.test\n# noise\ndev.target.test\n"
_WAYBACK = "https://target.test/admin\nhttps://target.test/api/users?id=1\nhttps://target.test/\n"
_GAU = "https://target.test/login\nhttps://sub.target.test/search?q=x\nnot-a-url\n"
_WAFW00F_JSON = json.dumps([{"url": "https://target.test", "detected": "Cloudflare"}])
_WAFW00F_NONE = "No WAF detected on target.test"

_ALL_NEW = [
    NaabuRunner,
    DnsxRunner,
    ShuffleDnsRunner,
    WaybackUrlsRunner,
    GauRunner,
    Wafw00fRunner,
]


@pytest.mark.parametrize("runner_cls", _ALL_NEW)
def test_ingest_out_of_scope_refused(runner_cls: type) -> None:
    """Out-of-scope targets are refused before any parse (scope gate holds)."""
    runner = runner_cls(graph=ReachabilityGraph(), scope=_scope())
    result = runner.ingest("other.example", "anything")
    assert result.outcome is ReconOutcome.REFUSED_OUT_OF_SCOPE


def test_naabu_text() -> None:
    """naabu host:port lines become Host + Service facts."""
    g = ReachabilityGraph()
    runner = NaabuRunner(graph=g, scope=_scope())
    result = runner.ingest(_TARGET, _NAABU_TEXT)
    assert result.outcome is ReconOutcome.INGESTED
    services = list(g.services())
    ports = {svc.port for _, svc in services}
    assert ports == {80, 443, 8080}


def test_naabu_json() -> None:
    """naabu JSON lines parse the same shape."""
    g = ReachabilityGraph()
    runner = NaabuRunner(graph=g, scope=_scope())
    result = runner.ingest(_TARGET, _NAABU_JSON)
    assert result.outcome is ReconOutcome.INGESTED
    assert len(list(g.services())) == 1


def test_dnsx_resolved() -> None:
    """dnsx hostname [IP] lines become Host facts with resolved addresses."""
    g = ReachabilityGraph()
    runner = DnsxRunner(graph=g, scope=_scope())
    result = runner.ingest(_TARGET, _DNSX)
    assert result.outcome is ReconOutcome.INGESTED
    hosts = {h.hostname: h for _, h in g.hosts()}
    assert "api.target.test" in hosts
    assert hosts["api.target.test"].address == "10.0.0.1"


def test_shuffledns_dedup() -> None:
    """shuffledns hostname-per-line output dedupes and skips comments."""
    g = ReachabilityGraph()
    runner = ShuffleDnsRunner(graph=g, scope=_scope())
    result = runner.ingest(_TARGET, _SHUFFLEDNS)
    assert result.outcome is ReconOutcome.INGESTED
    assert len(list(g.hosts())) == 2  # dev + staging, dup removed


def test_waybackurls_endpoints() -> None:
    """waybackurls URLs become Endpoint facts; root URL adds no endpoint."""
    g = ReachabilityGraph()
    runner = WaybackUrlsRunner(graph=g, scope=_scope())
    result = runner.ingest(_TARGET, _WAYBACK)
    assert result.outcome is ReconOutcome.INGESTED
    paths = {ep.path for _, ep in g.endpoints()}
    assert "/admin" in paths
    assert "/api/users?id=1" in paths  # query preserved as part of the URL fact
    assert "/" not in paths


def test_gau_multi_host() -> None:
    """gau URLs across subdomains create separate Host nodes with Endpoints."""
    g = ReachabilityGraph()
    runner = GauRunner(graph=g, scope=_scope())
    result = runner.ingest(_TARGET, _GAU)
    assert result.outcome is ReconOutcome.INGESTED
    host_addrs = {h.address for _, h in g.hosts()}
    assert "target.test" in host_addrs
    assert "sub.target.test" in host_addrs


def test_wafw00f_detected() -> None:
    """A detected WAF becomes a technology attribute on the Host."""
    g = ReachabilityGraph()
    runner = Wafw00fRunner(graph=g, scope=_scope())
    result = runner.ingest(_TARGET, _WAFW00F_JSON)
    assert result.outcome is ReconOutcome.INGESTED
    host = next(h for _, h in g.hosts())
    assert host.technology == "waf:Cloudflare"


def test_wafw00f_none() -> None:
    """No-WAF-detected records waf:none honestly (a fact, not a gap)."""
    g = ReachabilityGraph()
    runner = Wafw00fRunner(graph=g, scope=_scope())
    result = runner.ingest(_TARGET, _WAFW00F_NONE)
    assert result.outcome is ReconOutcome.INGESTED
    host = next(h for _, h in g.hosts())
    assert host.technology == "waf:none"


class TestTruncateOutput:
    """The context-efficiency truncation helper."""

    def test_short_output_passes_through(self) -> None:
        text = "line1\nline2"
        assert _truncate_output(text) == text

    def test_large_output_capped(self) -> None:
        raw = "x" * 60_000
        out = _truncate_output(raw)
        assert len(out) < 60_000
        assert "[truncated:" in out

    def test_minified_tighter_cap(self) -> None:
        # One very long line → avg line length > threshold → tighter cap.
        raw = "y" * 20_000
        out = _truncate_output(raw)
        assert "[truncated:" in out
