"""Generic scope-driven autonomous entrypoint (plan §6/§9/§10/§13).

Two defense-in-depth scope checkpoints, never one:

  A. Cold-start gating — recon fixtures filtered host-by-host through
     ScopeEnforcer *before* any graph write. Out-of-scope host never becomes a
     Host/Endpoint/resolves_to fact → coordinator never selects it. Audited as
     refused_out_of_scope. Endpoint fixtures (gobuster/nmap) are target-bound,
     not host-filtered.

  B. Firer gating — RequestFirer built from enforcer-backed wrapper that
     delegates to ScopeEnforcer.is_allowed (wildcard-aware). Every
     fire_request/fire_browser checked before any packet. Even direct
     graph.add_host bypass of A still caught by B.

Finding gate: six OracleMechanism only, run_oracle → is_violation → write_finding.
Explorer never calls write_finding/run_oracle; Coordinator never fires; only
Validator confirms — payload_chain drives the public MCP contracts via McpCaller.
"""

from __future__ import annotations

import logging
import urllib.parse
from collections.abc import Iterable
from typing import Any

import httpx

from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import OutOfScopeError, ScopeGuard
from reachagent.graph.chain_solver import ChainSolver
from reachagent.graph.nodes import FindingStatus, Host, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.payloads import build_library
from reachagent.tools import coordinator as _coordinator
from reachagent.tools import coordinator_support as _coordinator_support

_log = logging.getLogger(__name__)


# -- ScopeEnforcer (checkpoint A) --------------------------------------------


def extract_host(target: str) -> str:
    """Bare host from URL or bare host string, lowercased for comparison."""
    raw = target.strip()
    if not raw:
        return ""
    if "://" not in raw:
        host = raw.split("/", 1)[0].split(":", 1)[0]
        return host.lower()
    try:
        parsed = urllib.parse.urlparse(raw)
        host = parsed.hostname or ""
        return host.lower()
    except Exception:  # noqa: BLE001
        return raw.lower()


def parse_patterns(raw: str | None) -> list[str]:
    """Comma-separated host patterns → normalized pattern strings."""
    if not raw:
        return []
    patterns: list[str] = []
    for token in raw.split(","):
        p = token.strip().lower()
        if p:
            patterns.append(p)
    return patterns


def _matches_pattern(host: str, pattern: str) -> bool:
    """Single allowlist pattern vs host (case-insensitive, host-only).

    "*.example.com" matches example.com and any *.example.com (suffix with dot).
    "example.com" matches exactly example.com. No partial string.
    """
    h = host.lower()
    pat = pattern.lower()
    if pat.startswith("*."):
        base = pat[2:]
        if not base:
            return False
        if h == base:
            return True
        return h.endswith("." + base)
    return h == pat


class ScopeEnforcer:
    """Deny-by-default host scope with wildcard and out-of-scope precedence (§10)."""

    def __init__(
        self,
        in_scope: Iterable[str] | str | None,
        out_of_scope: Iterable[str] | str | None = None,
    ) -> None:
        if isinstance(in_scope, str):
            allow_raw = parse_patterns(in_scope)
        else:
            allow_raw = []
            if in_scope is not None:
                for item in in_scope:
                    allow_raw.extend(parse_patterns(item))
        if isinstance(out_of_scope, str):
            deny_raw = parse_patterns(out_of_scope)
        else:
            deny_raw = []
            if out_of_scope is not None:
                for item in out_of_scope:
                    deny_raw.extend(parse_patterns(item))
        self._allow = allow_raw
        self._deny = deny_raw

    @classmethod
    def from_raw(cls, in_scope: str | None, out_of_scope: str | None = None) -> ScopeEnforcer:
        allow = parse_patterns(in_scope) if in_scope else []
        deny = parse_patterns(out_of_scope) if out_of_scope else []
        return cls(allow, deny)

    def is_allowed(self, host: str) -> bool:
        """True only if host matches allowlist and not denylist (host-only compare)."""
        h = extract_host(host)
        if not h:
            return False
        for pat in self._deny:
            if _matches_pattern(h, pat):
                return False
        for pat in self._allow:
            if _matches_pattern(h, pat):
                return True
        return False

    def allowed_hosts(self, hosts: Iterable[str]) -> list[str]:
        """Filter iterable of hosts to allowed ones."""
        return [h for h in hosts if self.is_allowed(h)]


class EnforcerScopeWrapper:
    """ScopeGuard-compatible wrapper delegating to ScopeEnforcer (wildcard-aware).

    Duck-typed for RequestFirer — only enforce()/is_in_scope() are used.
    Host compare via ScopeEnforcer so "*.example.com" truly allows subdomains.
    """

    def __init__(self, enforcer: ScopeEnforcer) -> None:
        self._enforcer = enforcer

    def is_in_scope(self, url: str | httpx.URL) -> bool:
        parsed = httpx.URL(url) if isinstance(url, str) else url
        host = parsed.host
        if not host:
            return False
        return self._enforcer.is_allowed(host)

    def enforce(self, url: str | httpx.URL) -> None:
        if not self.is_in_scope(url):
            parsed = httpx.URL(url) if isinstance(url, str) else url
            raise OutOfScopeError(f"target not in scope: {parsed.host}{parsed.path}")


# -- Cold-start: recon ingest gated by ScopeEnforcer (checkpoint A) ----------

_HOST_LINE_RUNNERS = frozenset({"subfinder", "amass", "theharvester", "theHarvester"})
_PASSTHROUGH_RUNNERS = frozenset(
    {"nmap", "gobuster", "whatweb", "feroxbuster", "ffuf", "dirb", "katana"}
)


def detect_target_type(target: str) -> str:
    """Classify a scan target for recon dispatch (D2): domain | url | ip | cidr | host_port.

    Recon shape is selected by target *type* before any ingest — a bare-IP scan
    should not waste budget on subdomain enumeration, and a host:port target goes
    straight to TLS probes:

      * ``domain``  — bare FQDN: subdomain enum + tech fingerprint + crawl.
      * ``url``     — scheme://host[/path]: same domain-shaped recon as ``domain``.
      * ``ip``      — bare IPv4/IPv6 address: port/network probes (nmap/masscan/rustscan).
      * ``cidr``    — ``a.b.c.d/n`` network block: same port/network probes.
      * ``host_port`` — ``host:port`` with NO scheme: TLS probes (sslscan/sslyze).

    Scheme decides the protocol family; a port alone NEVER selects TLS. A
    scheme-bearing ``http(s)://host:port`` is an HTTP/URL target (content
    discovery + fingerprint) even on a non-default port — the discovery runners
    already take the full ``base_url`` and the firer scopes by host with the port
    distinct. Only a BARE ``host:port`` (no scheme) is a TLS-probe target.
    """
    import ipaddress
    import re as _re

    raw = target.strip()
    if "://" in raw:
        # Scheme present → URL target regardless of port (live-run defect: an
        # HTTP server on a non-default port was misrouted to TLS probes).
        return "url"
    # CIDR netblock — the "/" is a netmask, not a URL path. Checked on the full
    # authority (before any path split) so "10.0.0.0/24" classifies as cidr.
    if "/" in raw:
        try:
            ipaddress.ip_network(raw, strict=False)
            return "cidr"
        except ValueError:
            pass
    authority = raw.split("/", 1)[0]
    has_path = "/" in raw
    # host:port — authority carries a numeric port and no path (no scheme → TLS).
    if ":" in authority and _re.fullmatch(r"[^:]+:\d+", authority):
        return "host_port"
    try:
        ipaddress.ip_address(authority)
        return "ip"
    except ValueError:
        pass
    if has_path:
        return "url"
    return "domain"


def _filter_fixture_by_scope(raw: str, enforcer: ScopeEnforcer, runner_name: str) -> str:
    """Host-per-line runners: filter; endpoint/XML runners: passthrough."""
    if runner_name in _PASSTHROUGH_RUNNERS:
        return raw
    if runner_name not in _HOST_LINE_RUNNERS:
        # Unknown runner — conservative: passthrough (scope still enforced at ingest)
        return raw
    kept: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            kept.append(line)
            continue
        host = extract_host(stripped.split()[0])
        if enforcer.is_allowed(host):
            kept.append(line)
    return "\n".join(kept)


# -- scan_target (Coordinator loop + fire path) --------------------------------


def _vuln_classes_for_library() -> list[str]:
    return [
        "sqli",
        "xss_reflected",
        "path_traversal",
        "ssti",
        "nosqli",
        "ldap_injection",
        "command_injection",
    ]


def _sink_for_vuln_class(vuln_class: str) -> SinkType | None:
    mapping: dict[str, SinkType] = {
        "sqli": SinkType.SQL,
        "nosqli": SinkType.NOSQL,
        "xss_reflected": SinkType.HTML_REFLECTION,
        "command_injection": SinkType.SHELL,
        "path_traversal": SinkType.FILE_PATH,
        "ssti": SinkType.TEMPLATE,
        "ldap_injection": SinkType.LDAP,
    }
    return mapping.get(vuln_class)


def _live_vuln_class_for(selection: object, graph: ReachabilityGraph, base_url: str) -> str | None:
    """Proposal-only vuln-class targeting — flag-gated, double-validated.

    Reads Endpoint/Parameter/Host shape from the graph, calls live proposer
    when enabled, validates every returned class against VULN_CLASS_ALLOWLIST
    again, then returns the first chosen class that matches the param sink
    (honest: only existing oracle wiring). Never fires, never calls
    run_oracle/write_finding, never invents a payload string. Returns None
    when flag OFF or proposer yields no sink-compatible class.
    """
    import os as _os

    if (
        _os.environ.get("REACHAGENT_VULN_TUNING") != "1"
        and _os.environ.get("REACHAGENT_RECON_LIVE_TUNING") != "1"
    ):
        return None
    try:
        from reachagent.recon.vuln_tuning import VULN_CLASS_ALLOWLIST, propose_vuln_targets

        ep = graph.endpoint(getattr(selection, "endpoint_node", ""))
        param_node = getattr(selection, "parameter_node", None)
        param = graph.parameter(param_node) if param_node else None
        signals: dict[str, str] = {
            "method": getattr(ep, "method", "GET"),
            "path": getattr(ep, "path", "/")[:120],
        }
        if param is not None:
            signals["param_name"] = param.name[:80]
            signals["param_location"] = param.location
            if param.inferred_sink_type is not None:
                signals["sink"] = param.inferred_sink_type.value
        # Host tech / base_url hint
        try:
            import httpx as _httpx  # noqa: WPS433

            host = _httpx.URL(base_url).host or ""
            for hid, h in graph.hosts():
                if host in hid or hid in host:
                    if getattr(h, "technology", None):
                        signals["host_tech"] = str(h.technology)[:80]
                    break
        except Exception as exc:  # noqa: BLE001 — host tech best-effort
            _log.debug("host tech collect skipped: %s", exc)
        choice = propose_vuln_targets(signals)
        # Defense in depth: second allowlist check even after propose validates.
        allowed = set(VULN_CLASS_ALLOWLIST)
        sink = signals.get("sink")
        for vc in choice.vuln_classes:
            if vc not in allowed:
                continue
            # Only return a class whose sink matches the param's sink (honest wiring).
            # A mismatch (e.g. file_upload for a SQL sink) is proposal noise — skip.
            vc_sink = _sink_for_vuln_class(vc)
            if sink and vc_sink is not None and sink != vc_sink.value:
                continue
            return vc
        # No sink-compatible class from proposer — keep caller's sink-matched default.
        return None
    except Exception as exc:  # noqa: BLE001 — proposer must not crash scan
        _log.debug("vuln tuning skipped: %s", exc)
        return None


def _harvest_baseline_value(
    graph: ReachabilityGraph,
    firer: RequestFirer,
    identity: str,
    base_url: str,
    endpoint_path: str,
    param_name: str,
) -> str | None:
    """Sibling-list harvest: a 2xx sample value for a path-param endpoint's sibling.

    Generic REST shape — ``/users`` + ``/users/{id}``, not VAmPI-specific logic.
    For an injection endpoint ``/users/v1/{username}``, the sibling ``/users/v1``
    (the placeholder segment removed) is the list that yields a valid sample
    value, so the differential DATABASE_ERROR baseline is 2xx-served rather than a
    literal that 404s (the live-VAmPI gap). Read-only GET through the gated firer;
    never a payload, never a can_call. Returns ``None`` when there is no sibling,
    the sibling is non-2xx, or its JSON has no matching field — the caller falls
    back to a literal baseline.
    """
    import json

    sibling = endpoint_path.replace(f"/{{{param_name}}}", "")
    if sibling == endpoint_path:
        return None
    if not any(e.path == sibling for _, e in graph.endpoints()):
        return None
    try:
        result = firer.fire(identity, "GET", base_url.rstrip("/") + sibling, state_changing=False)
    except Exception:  # noqa: BLE001, S112 — a refused/errored sibling is no baseline
        return None
    if not (200 <= result.status_code < 300):
        return None
    try:
        body = json.loads(result.body.decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001 — a non-JSON sibling body is no baseline
        return None
    fields = (param_name, "username", "name")
    if isinstance(body, list):
        for item in body:
            if isinstance(item, dict):
                for field in fields:
                    value = item.get(field)
                    if value not in (None, ""):
                        return str(value)
    elif isinstance(body, dict):
        # Direct-field first, then the plural-key wrapper — a dict wrapping the
        # list under a key ({"users": [...]}, {"items": [...]}, {"books": [...]}),
        # the generic REST list shape mapper._reveal_items already unwraps.
        for field in fields:
            value = body.get(field)
            if value not in (None, ""):
                return str(value)
        for value in body.values():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        for field in fields:
                            v = item.get(field)
                            if v not in (None, ""):
                                return str(v)
    return None


def scan_target(
    *,
    base_url: str,
    in_scope: str,
    out_of_scope: str | None = None,
    dry_run: bool = True,
    max_attempts: int = 20,
    library: Any | None = None,
    fixtures: dict[str, str] | None = None,
    transport: httpx.BaseTransport | None = None,
    graph: ReachabilityGraph | None = None,
    audit: AuditLog | None = None,
    dns_resolve: Any | None = None,
    resume_path: str | None = None,
    state_path: str | None = None,
    surface_path: str | None = None,
) -> dict[str, Any]:
    """Generic autonomous scan entrypoint.

    Cold-start discovery gated by ScopeEnforcer (A); firing gated by
    enforcer-backed firer wrapper (B, wildcard-aware).

    dry_run=True: discover + score, return plan without firing any payload.
    dry_run=False: full loop (query_graph → score_and_select → check_budget →
                   run_payload_chain via direct Explorer/Validator seam) until
                   score_and_select is None or budget exhausted. advance() on
                   confirmed finding to requery derived edges.

    Durable resume (D6/D2): ``resume_path`` loads a persisted graph + solver +
    audit and CONTINUES the loop (continue-not-replay — confirmed findings are
    loaded as facts, never re-confirmed; unexplored pairs are picked up by the
    normal loop; a RECOVER pass re-surfaces derived-credential pairs whose spawn
    was interrupted). ``state_path`` persists the run state at the end of a live
    run (atomic JSON). On resume, cold-start fixtures are NOT re-ingested — the
    loaded graph already carries them.
    """
    enforcer = ScopeEnforcer(in_scope, out_of_scope)

    resumed = resume_path is not None
    if resumed:
        from reachagent.graph.persistence import load_graph

        g, solver, a = load_graph(resume_path)  # type: ignore[arg-type]
    else:
        g = graph if graph is not None else ReachabilityGraph()
        a = audit if audit is not None else AuditLog()
        solver = ChainSolver(g)
    lib = library if library is not None else build_library()

    target_host = extract_host(base_url)
    if not resumed:
        if enforcer.is_allowed(target_host):
            g.add_host(Host(address=target_host, hostname=target_host, source="scan"))
        else:
            a.record("scan", "RECON", target_host, "refused_out_of_scope")

    # The firer is built once and shared by wildcard calibration (below) and the
    # main loop — scope + read-only-first + audit hold on both (§10).
    firer_scope = EnforcerScopeWrapper(enforcer)
    client = httpx.Client(transport=transport) if transport is not None else httpx.Client()
    firer = RequestFirer(client, firer_scope, a)  # type: ignore[arg-type]

    if not resumed and surface_path is not None:
        # Optional --surface seeding (Task 27): materialize a declared surface
        # (endpoints/parameters/objects) BEFORE cold-start recon, so recon then
        # enriches. The mapper's read-only can_call probes seed real verdicts;
        # state-changing endpoints are materialized but never fired (read-only-
        # first holds). This is an OPTIONAL input — pure cold-start is unchanged.
        from reachagent.identity.store import IdentityStore
        from reachagent.recon.mapper import SurfaceMapper, SurfaceSpec

        SurfaceMapper(g, firer, IdentityStore(), base_url).map_structure(
            SurfaceSpec.from_file(surface_path)
        )

    if not resumed:
        # Recon dispatch by target type (D2): host-shaped targets skip subdomain
        # enumeration; domain/url targets crawl + fingerprint; host:port targets
        # go straight to TLS probes. Scope gates still run before every ingest.
        # Skipped entirely on resume — the loaded graph already carries the facts.
        target_type = detect_target_type(base_url)
        if target_type in ("ip", "cidr"):
            from reachagent.recon.tools.masscan import MasscanRunner
            from reachagent.recon.tools.nmap import NmapRunner
            from reachagent.recon.tools.rustscan import RustscanRunner

            runner_types: list[type[Any]] = [NmapRunner, MasscanRunner, RustscanRunner]
        elif target_type == "host_port":
            from reachagent.recon.tools.tls_probe import SslscanRunner, SslyzeRunner

            runner_types = [SslscanRunner, SslyzeRunner]
        else:  # domain / url
            from reachagent.recon.tools.dirb import DirbRunner
            from reachagent.recon.tools.feroxbuster import FeroxbusterRunner
            from reachagent.recon.tools.ffuf import FfufRunner
            from reachagent.recon.tools.gobuster import GobusterRunner
            from reachagent.recon.tools.katana import KatanaRunner
            from reachagent.recon.tools.subdomains import AmassRunner, SubfinderRunner
            from reachagent.recon.tools.theharvester import TheHarvesterRunner
            from reachagent.recon.tools.whatweb import WhatWebRunner

            runner_types = [
                SubfinderRunner,
                AmassRunner,
                TheHarvesterRunner,
                WhatWebRunner,
                KatanaRunner,
                GobusterRunner,
                FfufRunner,
                FeroxbusterRunner,
                DirbRunner,
            ]

        # URL-shaped tools need the full base_url; host-line and port/TLS tools
        # take the bare host (or host:port) target.
        _URL_TOOLS = frozenset({"gobuster", "whatweb", "katana"})
        scope_guard = ScopeGuard.from_hosts([p.lstrip("*.") for p in enforcer._allow if p])
        runners: list[Any] = [rt(graph=g, scope=scope_guard, audit=a) for rt in runner_types]

        # Wildcard calibration (D5, live only — it *fires* probes, so dry-run
        # stays zero-fired). A catch-all makes content-discovery path facts
        # untrustworthy; the four content wrappers suppress them (D2).
        content_discovery = frozenset({"gobuster", "ffuf", "feroxbuster", "dirb"})
        subdomain_enum = frozenset({"subfinder", "amass", "theharvester", "theHarvester"})
        cal_result = None
        dns_result = None
        if not dry_run:
            if any(r.name in content_discovery for r in runners):
                from reachagent.recon.calibration import CalibrationRunner

                cal_result = CalibrationRunner(firer, base_url).run()
            # DNS wildcard pre-check (D2, live only — DNS probes fire). A zone
            # with a wildcard A record answers any random label with one IP; the
            # three subdomain wrappers suppress hostnames that resolve to it.
            if target_type in ("domain", "url") and any(r.name in subdomain_enum for r in runners):
                from reachagent.recon.calibration import DnsWildcardProber

                prober = (
                    DnsWildcardProber(target_host, resolve=dns_resolve)
                    if dns_resolve is not None
                    else DnsWildcardProber(target_host)
                )
                dns_result = prober.run()
                # The wildcard fact IS recorded on the root target Host (D2).
                g.add_host(
                    Host(
                        address=target_host,
                        hostname=target_host,
                        source="scan",
                        technology=dns_result.shape_label,
                    )
                )

        for runner in runners:
            if runner.name in content_discovery:
                runner.calibration = cal_result
            if runner.name in subdomain_enum and dns_result is not None:
                runner.dns_wildcard_ip = dns_result.wildcard_ip
                if dns_resolve is not None:
                    runner.resolve = dns_resolve
            target_arg = base_url if runner.name in _URL_TOOLS else target_host
            if fixtures is not None:
                raw = fixtures.get(runner.name, "")
                if not raw:
                    continue
                allowed_raw = _filter_fixture_by_scope(raw, enforcer, runner.name)
                runner.ingest(target_arg, allowed_raw)
                # Audit any host lines that were dropped
                for line in raw.splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    host = extract_host(stripped.split()[0])
                    if host and not enforcer.is_allowed(host):
                        a.record(runner.name, "RECON", host, "refused_out_of_scope")
            elif not dry_run:
                # Live cold-start: no fixtures → spawn the real recon binary.
                # runner.run() is the live path — REACHAGENT_RECON_LIVE-gated
                # (unset → SKIPPED_NOT_LIVE), scope-gated before spawn, array
                # args shell=False, missing-binary graceful skip.
                runner.run(target_arg)

        # Spec-first API discovery (Task 27, live only — it fires read-only GET
        # probes). After --surface seeding and cold-start recon, before the
        # Coordinator loop: probe for OpenAPI/GraphQL specs, parse into
        # Endpoint/Parameter facts, else a bounded combinatorial fallback.
        if not dry_run:
            from reachagent.recon.api_discovery import discover_api

            discover_api(g, firer, base_url)

    from reachagent.tools.explorer_context import ExplorerContext

    ctx = ExplorerContext(graph=g, firer=firer, library=lib, base_url=base_url)

    if resumed and not dry_run:
        # RECOVER pass (D3): re-surface unexplored pairs for persisted derived
        # credentials whose spawn/requery was interrupted by the crash. A finding
        # whose spawned identity is already in _spawned_by_path was advanced —
        # skip (no replay). Errored edges need no pass: an errored fire writes no
        # can_call verdict, so the normal loop retries them; inconclusive edges
        # carry a verdict and stay skipped.
        from reachagent.graph.nodes import Session as _SessionNode
        from reachagent.graph.store import identity_id as _identity_id

        for _f_node, f_data in g.findings():
            if f_data.status is not FindingStatus.CONFIRMED_VIOLATION:
                continue
            for from_finding, spawned in g.derived_credential_edges():
                if from_finding != _f_node:
                    continue
                data = g._g.nodes[spawned].get("data")
                if isinstance(data, _SessionNode):
                    target = _identity_id(data.identity_ref)
                else:
                    target = spawned
                solver.recover_derived(target, path_id="scan")

    seeded_identities = list(g.identities())
    if not seeded_identities:
        from reachagent.graph.nodes import AuthState, Identity, Provenance

        g.add_identity(
            "seed",
            Identity(role="user", auth_state=AuthState.USER, provenance=Provenance.SEEDED),
        )

    if not list(g.endpoints()):
        from reachagent.graph.nodes import Endpoint, Parameter

        ep = g.add_endpoint(Endpoint(method="GET", path="/items"))
        g.add_parameter(ep, Parameter(name="id", location="query"))

    from reachagent.tools.coordinator_support import CoordinatorContext

    context = CoordinatorContext(graph=g, solver=solver, run_id="scan", path_id="scan")

    candidates = _coordinator.query_graph(context)
    plan: list[tuple[str, str, str | None, str, str]] = []
    for cand in candidates:
        for vuln_class in _vuln_classes_for_library():
            sink_type = _sink_for_vuln_class(vuln_class)
            entries = lib.get_payloads(vuln_class, sink_type)
            for entry in entries[:max_attempts]:
                plan.append(
                    (
                        cand.identity_node,
                        cand.endpoint_node,
                        cand.parameter_node,
                        vuln_class,
                        entry.payload_ref,
                    )
                )

    if dry_run:
        return {
            "dry_run": True,
            "plan": plan,
            "discovery": {
                "endpoints": len(list(g.endpoints())),
                "hosts": len([n for n, d in g._g.nodes(data=True) if d.get("_kind") == "host"]),
            },
            "fired": len([e for e in a.entries if e.outcome.startswith("fired:")]),
            "scope": {"in_scope": in_scope, "out_of_scope": out_of_scope},
            "graph": g,
            "audit": a,
        }

    findings: list[str] = []
    from mcp.server.fastmcp import FastMCP

    from reachagent.mcp import server as _server
    from reachagent.mcp.server import _Session
    from reachagent.tools import payload_chain as _pc

    session = _Session(ctx=ctx)
    mcp = FastMCP("scan-live")
    _server.register_tools(mcp, session)

    def _caller(name: str, arguments: Any) -> Any:
        return _pc.call_tool_sync(mcp, name, arguments)

    iterations = 0
    max_iterations = 20
    attempted_edges: set[tuple[str, str]] = set()
    while iterations < max_iterations:
        iterations += 1
        cands = _coordinator.query_graph(context)
        if resumed:
            # Resume honors "don't replay what was decided": an INCONCLUSIVE
            # verdict from the prior run is a real negative result and is
            # skipped. (A fresh run's Coordinator re-assesses inconclusive by
            # design — query_graph keeps them eligible; resume deliberately
            # does not.) Errored edges carry no verdict, so they stay eligible
            # and are re-queried — exactly the RECOVER rule (D3).
            cands = [
                c
                for c in cands
                if g.can_call_status(c.identity_node, c.endpoint_node) != FindingStatus.INCONCLUSIVE
            ]
        # No-reselect (live-run divergence #4): skip edges already attempted THIS
        # run — mark_edge_inconclusive writes a durable verdict, but query_graph
        # re-assesses inconclusive edges by design, so without this per-run filter
        # a dead/no-sink candidate is reselected for all 20 iterations.
        cands = [c for c in cands if (c.identity_node, c.endpoint_node) not in attempted_edges]
        sel = _coordinator.score_and_select(cands)
        if sel is None:
            break
        attempted_edges.add((sel.identity_node, sel.endpoint_node))
        if not _coordinator_support.budget_status(context):
            break
        if not solver.consume_budget("scan"):
            break
        vuln_class = "sqli"
        param_sink = g.parameter_sink(sel.parameter_node) if sel.parameter_node else None
        for vc in _vuln_classes_for_library():
            if _sink_for_vuln_class(vc) == param_sink:
                vuln_class = vc
                break
        # Live vuln-class targeting — proposal-only, flag OFF by default.
        # When REACHAGENT_VULN_TUNING=1 or REACHAGENT_RECON_LIVE_TUNING=1, shapes
        # from Endpoint/Parameter/Host are sent to propose_vuln_targets() which
        # picks FROM VULN_CLASS_ALLOWLIST; validated twice (inside + here) before
        # any use. Never writes Finding/can_call, never calls run_oracle/fire.
        _maybe = _live_vuln_class_for(sel, g, base_url)
        if _maybe is not None:
            vuln_class = _maybe
        # Coordinator may select a candidate with no parameter (endpoint-level
        # authz class, or a discovery that surfaced only a bare endpoint — the
        # live-run VAmPI case). Seed a benign probe parameter on the endpoint so
        # the payload chain can fingerprint + fire instead of skipping (live-run
        # divergence #3). Only skip when the endpoint itself is gone.
        param_node = sel.parameter_node
        if param_node is None:
            try:
                _ = g.endpoint(sel.endpoint_node)  # endpoint must exist to seed on it
            except Exception:  # noqa: BLE001 — a missing endpoint cannot be seeded
                solver.consume_budget("scan")
                continue
            from reachagent.graph.nodes import Parameter as _ProbeParam

            param_node = g.add_parameter(
                sel.endpoint_node, _ProbeParam(name="probe", location="query")
            )
        baseline_payload = "baseline"
        if param_node is not None:
            param = g.parameter(param_node)
            if param.location == "path":
                harvested = _harvest_baseline_value(
                    g,
                    firer,
                    sel.identity_node,
                    base_url,
                    g.endpoint(sel.endpoint_node).path,
                    param.name,
                )
                if harvested is not None:
                    baseline_payload = harvested
        result = _pc.run_payload_chain(
            _caller,
            identity=sel.identity_node,
            endpoint_node=sel.endpoint_node,
            param_node=param_node,
            vuln_class=vuln_class,
            baseline_payload=baseline_payload,
            max_attempts=max_attempts,
        )
        if result.confirmed and result.finding_node:
            findings.append(result.finding_node)
            try:
                solver.advance(result.finding_node, acting_identity=sel.identity_node)
            except Exception:  # noqa: BLE001
                _log.debug("solver advance failed", exc_info=True)
            context = CoordinatorContext(graph=g, solver=solver, run_id="scan", path_id="scan")
        # Non-confirmed chains are handled by attempted_edges (added above): the
        # candidate is never re-selected this run. No graph verdict is written —
        # query_graph re-assesses INCONCLUSIVE edges by design (multi-hop), so a
        # durable inconclusive verdict would NOT stop the reselect anyway, and it
        # would violate the recon-facts-only invariant (a dead endpoint is not a
        # negative finding; retrying it on a later resume is acceptable).

    if state_path is not None:
        # Persist run state at the end of a live run (D6) — atomic JSON, so the
        # next resume continues from here.
        from reachagent.graph.persistence import dump_graph

        dump_graph(g, solver, a, state_path)

    return {
        "dry_run": False,
        # Dedup, order-preserving: the loop can confirm the same finding on two
        # iterations, but the graph keys a Finding on (vuln_class, evidence_ref) —
        # the returned list must match the graph's node count, not double-count.
        "findings": list(dict.fromkeys(findings)),
        "plan": plan,
        "graph": g,
        "audit": a,
        "iterations": iterations,
    }


# Backwards alias expected by some builders
scan = scan_target
