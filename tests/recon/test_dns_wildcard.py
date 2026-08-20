"""DNS wildcard pre-check (D2 deferred item) — hermetic, injected fake resolver only."""

from __future__ import annotations

import socket

import httpx

from reachagent.execution.audit import AuditLog
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.calibration import DnsWildcardProber
from reachagent.recon.tools.subdomains import AmassRunner, SubfinderRunner
from reachagent.recon.tools.theharvester import TheHarvesterRunner
from reachagent.scan.entrypoint import scan_target

_WILDCARD_IP = "1.2.3.4"


def _scope() -> ScopeGuard:
    return ScopeGuard.from_hosts(["example.com"])


# -- D1 probe shape -------------------------------------------------------------


def test_dns_wildcard_detected() -> None:
    def fake_resolve(label: str) -> str:
        return _WILDCARD_IP  # every random label resolves to the same IP

    result = DnsWildcardProber("example.com", resolve=fake_resolve).run()
    assert result.wildcard is True
    assert result.wildcard_ip == _WILDCARD_IP
    assert result.shape_label == f"dns_wildcard:{_WILDCARD_IP}"


def test_dns_no_wildcard_on_nxdomain() -> None:
    def fake_resolve(label: str) -> None:  # noqa: ARG001
        return None  # no label resolves

    result = DnsWildcardProber("example.com", resolve=fake_resolve).run()
    assert result.wildcard is False
    assert result.wildcard_ip is None
    assert result.shape_label == "dns_wildcard:none"


def test_dns_no_wildcard_on_differing_ips() -> None:
    ips = iter([_WILDCARD_IP, "5.6.7.8", _WILDCARD_IP])

    def fake_resolve(label: str) -> str:  # noqa: ARG001
        return next(ips)

    result = DnsWildcardProber("example.com", resolve=fake_resolve).run()
    assert result.wildcard is False


def test_dns_resolver_error_is_conservative() -> None:
    def fake_resolve(label: str) -> str:  # noqa: ARG001
        raise socket.gaierror("nxdomain")

    result = DnsWildcardProber("example.com", resolve=fake_resolve).run()
    assert result.wildcard is False
    assert result.shape_label == "dns_wildcard:none"


def test_dns_probe_labels_distinct() -> None:
    seen: list[str] = []

    def fake_resolve(label: str) -> str:
        seen.append(label)
        return _WILDCARD_IP

    DnsWildcardProber("example.com", resolve=fake_resolve).run()
    assert len(seen) == 3
    assert len(set(seen)) == 3  # distinct labels
    assert all(label.endswith(".example.com") for label in seen)


# -- D2 suppression in the subdomain wrappers ------------------------------------


def test_wildcard_suppresses_subdomain_facts() -> None:
    def fake_resolve(hostname: str) -> str:
        return _WILDCARD_IP

    graph = ReachabilityGraph()
    audit = AuditLog()
    runner = SubfinderRunner(graph=graph, scope=_scope(), audit=audit)
    runner.dns_wildcard_ip = _WILDCARD_IP  # D3 pass-through
    runner.resolve = fake_resolve
    runner.ingest("example.com", "api.example.com\nmail.example.com\n")
    # Both resolve to the wildcard IP → suppressed, zero Host facts asserted.
    assert list(graph.hosts()) == []
    assert len([e for e in audit.entries if e.outcome == "refused_wildcard_dns"]) == 2


def test_no_wildcard_passes_through() -> None:
    graph = ReachabilityGraph()
    audit = AuditLog()
    runner = SubfinderRunner(graph=graph, scope=_scope(), audit=audit)
    runner.ingest("example.com", "api.example.com\n")  # dns_wildcard_ip unset
    assert any(h.hostname == "api.example.com" for _, h in graph.hosts())
    assert not any(e.outcome == "refused_wildcard_dns" for e in audit.entries)


def test_resolution_failure_is_kept_not_suppressed() -> None:
    def fake_resolve(hostname: str) -> None:  # noqa: ARG001
        return None  # fails to resolve → conservative: keep

    graph = ReachabilityGraph()
    audit = AuditLog()
    runner = SubfinderRunner(graph=graph, scope=_scope(), audit=audit)
    runner.dns_wildcard_ip = _WILDCARD_IP
    runner.resolve = fake_resolve
    runner.ingest("example.com", "api.example.com\n")
    assert any(h.hostname == "api.example.com" for _, h in graph.hosts())
    assert not any(e.outcome == "refused_wildcard_dns" for e in audit.entries)


def test_wildcard_suppresses_amass_and_theharvester() -> None:
    for cls in (AmassRunner, TheHarvesterRunner):
        graph = ReachabilityGraph()
        audit = AuditLog()
        runner = cls(graph=graph, scope=_scope(), audit=audit)
        runner.dns_wildcard_ip = _WILDCARD_IP
        runner.resolve = lambda hostname: _WILDCARD_IP  # noqa: ARG005
        runner.ingest("example.com", "api.example.com\n")
        assert list(graph.hosts()) == [], f"{cls.__name__} suppressed nothing"
        assert any(e.outcome == "refused_wildcard_dns" for e in audit.entries)


def test_dns_wildcard_suppress_is_recon_facts_only() -> None:
    graph = ReachabilityGraph()
    audit = AuditLog()
    runner = SubfinderRunner(graph=graph, scope=_scope(), audit=audit)
    runner.dns_wildcard_ip = _WILDCARD_IP
    runner.resolve = lambda hostname: _WILDCARD_IP  # noqa: ARG005
    runner.ingest("example.com", "api.example.com\n")
    assert list(graph.hosts()) == []
    assert graph.findings() == []
    assert graph.can_call_edges() == []


# -- D3 wiring through scan_target -----------------------------------------------


def test_wiring_suppresses_subdomains_on_dns_wildcard() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(200, content=b"x")

    def fake_resolve(label: str) -> str:  # noqa: ARG001
        return _WILDCARD_IP  # every label (probe or discovered) → wildcard IP

    result = scan_target(
        base_url="https://example.com",
        in_scope="*.example.com",
        dry_run=False,
        transport=httpx.MockTransport(handler),
        dns_resolve=fake_resolve,
        fixtures={
            "subfinder": "api.example.com\nmail.example.com\n",
            "amass": "api.example.com\n",
            "theHarvester": "api.example.com\n",
        },
    )
    g = result["graph"]
    # Root target Host carries the dns_wildcard fact (D2).
    root = next(h for _, h in g.hosts() if h.address == "example.com")
    assert root.technology is not None and f"dns_wildcard:{_WILDCARD_IP}" in root.technology
    # Subdomain facts resolving to the wildcard IP are suppressed.
    assert not any(h.hostname == "api.example.com" for _, h in g.hosts())
    assert not any(h.hostname == "mail.example.com" for _, h in g.hosts())
    assert any(e.outcome == "refused_wildcard_dns" for e in result["audit"].entries)
    # Recon-facts-only: a Host is present (root), nothing beyond it.
    assert g.findings() == []
    assert g.can_call_edges() == []


def test_wiring_passes_through_without_wildcard() -> None:
    # Dry-run: no DNS probe fired → subdomain facts pass through unchanged.
    result = scan_target(
        base_url="https://example.com",
        in_scope="*.example.com",
        dry_run=True,
        fixtures={"subfinder": "api.example.com\n"},
    )
    assert result["dry_run"] is True
    assert any(h.hostname == "api.example.com" for _, h in result["graph"].hosts())
    assert not any(e.outcome == "refused_wildcard_dns" for e in result["audit"].entries)
    assert not any(e.outcome.startswith("fired:") for e in result["audit"].entries)


def test_wiring_dry_run_never_probes_dns() -> None:
    def fake_resolve(label: str) -> str:  # noqa: ARG001
        raise AssertionError("must not probe in dry-run")

    result = scan_target(
        base_url="https://example.com",
        in_scope="*.example.com",
        dry_run=True,
        dns_resolve=fake_resolve,
        fixtures={"subfinder": "api.example.com\n"},
    )
    # Dry-run must not fire the DNS probe; the fake resolver would raise if called.
    assert any(h.hostname == "api.example.com" for _, h in result["graph"].hosts())
    # Root host carries no dns_wildcard fact (no probe ran).
    root = next(h for _, h in result["graph"].hosts() if h.address == "example.com")
    assert not root.technology or "dns_wildcard" not in root.technology
