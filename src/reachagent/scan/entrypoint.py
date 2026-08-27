"""Generic scope-driven autonomous entrypoint (plan §6/§9/§10/§13).

Two defense-in-depth scope checkpoints, never one:

  A. Cold-start gating — recon fixtures filtered host-by-host through
     ScopeGuard *before* any graph write. Out-of-scope host never becomes a
     Host/Endpoint/resolves_to fact → coordinator never selects it. Audited as
     refused_out_of_scope. Endpoint fixtures (gobuster/nmap) are target-bound,
     not host-filtered.

  B. Firer gating — RequestFirer built from ScopeGuard (wildcard-aware).
     Every fire_request/fire_browser checked before any packet. Even direct
     graph.add_host bypass of A still caught by B.

Finding gate: six OracleMechanism only, run_oracle → is_violation → write_finding.
Explorer never calls write_finding/run_oracle; Coordinator never fires; only
Validator confirms — payload_chain drives the public MCP contracts via McpCaller.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

import httpx

from reachagent.execution.audit import AuditLog
from reachagent.execution.firer import RequestFirer
from reachagent.execution.scope import ScopeGuard
from reachagent.graph.chain_solver import ChainSolver
from reachagent.graph.nodes import FindingStatus, Host, SinkType
from reachagent.graph.store import ReachabilityGraph
from reachagent.payloads import build_library
from reachagent.tools import coordinator as _coordinator
from reachagent.tools import coordinator_support as _coordinator_support

_log = logging.getLogger(__name__)

if TYPE_CHECKING:
    from reachagent.identity.store import IdentityStore


# Host extraction has one implementation: recon.tools._net.host_of.
from reachagent.recon.tools._net import host_of as _host_of  # noqa: E402

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


def _filter_fixture_by_scope(raw: str, scope: ScopeGuard, runner_name: str) -> str:
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
        host = stripped.split()[0]
        if scope.is_in_scope(host):
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
        "ssrf",
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
        "ssrf": SinkType.URL,
    }
    return mapping.get(vuln_class)


def _live_vuln_classes_for(
    selection: object,
    graph: ReachabilityGraph,
    base_url: str,
    operator_prompt: str | None = None,
) -> tuple[str, ...]:
    """Ranked vuln-class targeting — flag-gated, double-validated.

    Reads Endpoint/Parameter/Host shape from the graph, calls live proposer
    when enabled, validates every returned class against VULN_CLASS_ALLOWLIST
    again, then returns ALL sink-compatible classes in the LLM's priority order.
    The caller iterates this list when earlier classes fail. Returns an empty
    tuple when flag OFF (the caller falls back to the default single-class
    sink-matched heuristic).
    """
    from reachagent.llm.runtime import flag_enabled, llm_required

    if not flag_enabled("REACHAGENT_VULN_TUNING") and not flag_enabled(
        "REACHAGENT_RECON_LIVE_TUNING"
    ):
        return ()
    try:
        from reachagent.recon.vuln_tuning import VULN_CLASS_ALLOWLIST, propose_vuln_targets

        ep = graph.endpoint(getattr(selection, "endpoint_node", ""))
        param_node = getattr(selection, "parameter_node", None)
        param = graph.parameter(param_node) if param_node else None
        signals: dict[str, str] = {
            "method": getattr(ep, "method", "GET"),
            "path": getattr(ep, "path", "/")[:120],
        }
        if operator_prompt:
            signals["operator_goal"] = operator_prompt[:500]
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
        compatible: list[str] = []
        for vc in choice.vuln_classes:
            if vc not in allowed:
                continue
            if vc in compatible:
                continue
            # Only keep classes whose sink matches the param's sink (honest wiring).
            # A mismatch (e.g. file_upload for a SQL sink) is proposal noise — skip.
            vc_sink = _sink_for_vuln_class(vc)
            if sink and vc_sink is not None and sink != vc_sink.value:
                continue
            compatible.append(vc)
        return tuple(compatible)
    except Exception as exc:  # noqa: BLE001 — proposer must not crash scan
        if llm_required():
            raise
        _log.debug("vuln tuning skipped: %s", exc)
        return ()


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
    identities: IdentityStore | None = None,
    operator_prompt: str | None = None,
    recon_tools: Iterable[str] | None = None,
    live_recon: bool = False,
    events: list[Any] | None = None,
) -> dict[str, Any]:
    """Generic autonomous scan entrypoint.

    Cold-start discovery gated by ScopeGuard (A); firing gated by
    ScopeGuard (B, wildcard-aware).

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
    scope = ScopeGuard.from_raw(in_scope, out_of_scope)

    resumed = resume_path is not None
    if resumed:
        from reachagent.graph.persistence import load_graph

        g, solver, a = load_graph(resume_path)  # type: ignore[arg-type]
    else:
        g = graph if graph is not None else ReachabilityGraph()
        a = audit if audit is not None else AuditLog()
        solver = ChainSolver(g)
    lib = library if library is not None else build_library()

    target_host = _host_of(base_url)
    selected_recon_tools: tuple[str, ...] = ()
    if not resumed:
        if scope.is_in_scope(target_host):
            g.add_host(Host(address=target_host, hostname=target_host, source="scan"))
        else:
            a.record("scan", "RECON", target_host, "refused_out_of_scope")

    # The firer is built once and shared by wildcard calibration (below) and the
    # main loop — scope + read-only-first + audit hold on both (§10).
    firer_scope = scope
    client = httpx.Client(transport=transport) if transport is not None else httpx.Client()
    identity_headers: dict[str, dict[str, str]] = {}
    if identities is not None:
        for name in identities.names():
            token = identities.token_store(name).get_token()
            if token:
                identity_headers[name] = {"Authorization": f"Bearer {token}"}
    firer = RequestFirer(client, firer_scope, a, identity_headers=identity_headers)

    def _tool_event(tool_name: str, outcome: str, *, detail: str = "", **extra: Any) -> None:
        """Emit a per-tool event so the GUI tools panel streams real activity."""
        if events is None:
            return
        try:
            from reachagent.scan.orchestrator import ScanEvent

            details: dict[str, Any] = {"tool": tool_name, "outcome": outcome}
            if detail:
                details["detail"] = detail
            details.update(extra)
            events.append(
                ScanEvent(
                    phase="tools",
                    kind="step",
                    message=f"{tool_name}: {outcome}",
                    details=details,
                )
            )
        except Exception:  # noqa: BLE001 — event emission must never break the scan
            _log.debug("tool event emission failed for %s", tool_name, exc_info=True)

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

        # A validated LLM plan may choose a compatible subset (or add a
        # registered adapter that the legacy target-type defaults did not use).
        # The registry contains classes already implemented in this package;
        # it never accepts a binary name or an arbitrary command from the model.
        if recon_tools is not None:
            from reachagent.recon.tools.arjun import ArjunRunner
            from reachagent.recon.tools.dnsx import DnsxRunner
            from reachagent.recon.tools.httpx_runner import HttpxRunner
            from reachagent.recon.tools.masscan import MasscanRunner
            from reachagent.recon.tools.naabu import NaabuRunner
            from reachagent.recon.tools.nmap import NmapRunner
            from reachagent.recon.tools.paramspider import ParamSpiderRunner
            from reachagent.recon.tools.rustscan import RustscanRunner
            from reachagent.recon.tools.shuffledns import ShuffleDnsRunner
            from reachagent.recon.tools.tls_probe import TestsslRunner
            from reachagent.recon.tools.url_discovery import GauRunner, WaybackUrlsRunner
            from reachagent.recon.tools.wafw00f import Wafw00fRunner
            from reachagent.recon.tools.wpscan_passive import WpscanPassiveRunner
            from reachagent.recon.tools.x8 import X8Runner

            registry: dict[str, type[Any]] = {rt.name: rt for rt in runner_types}
            registry.update(
                {
                    cls.name: cls
                    for cls in (
                        ArjunRunner,
                        DnsxRunner,
                        GauRunner,
                        HttpxRunner,
                        MasscanRunner,
                        NmapRunner,
                        NaabuRunner,
                        ParamSpiderRunner,
                        RustscanRunner,
                        ShuffleDnsRunner,
                        TestsslRunner,
                        WaybackUrlsRunner,
                        Wafw00fRunner,
                        WpscanPassiveRunner,
                        X8Runner,
                    )
                }
            )
            requested = tuple(dict.fromkeys(str(name).strip().lower() for name in recon_tools))
            runner_types = [registry[name] for name in requested if name in registry]
            selected_recon_tools = tuple(rt.name for rt in runner_types)

        # URL-shaped tools need the full base_url; host-line and port/TLS tools
        # take the bare host (or host:port) target.
        _URL_TOOLS = frozenset(
            {
                "arjun",
                "dirb",
                "feroxbuster",
                "ffuf",
                "gau",
                "gobuster",
                "httpx",
                "katana",
                "paramspider",
                "wafw00f",
                "waybackurls",
                "whatweb",
                "wpscan",
                "x8",
            }
        )
        scope_guard = scope
        runners: list[Any] = [rt(graph=g, scope=scope_guard, audit=a) for rt in runner_types]
        if not selected_recon_tools:
            selected_recon_tools = tuple(runner.name for runner in runners)

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
            _tool_event(runner.name, "starting")
            if fixtures is not None:
                raw = fixtures.get(runner.name, "")
                if not raw:
                    _tool_event(runner.name, "no-fixture", detail="skipped (no fixture data)")
                    continue
                allowed_raw = _filter_fixture_by_scope(raw, scope, runner.name)
                ingest_result = runner.ingest(target_arg, allowed_raw)
                _tool_event(
                    runner.name,
                    ingest_result.outcome.value,
                    nodes=len(ingest_result.nodes),
                    detail=ingest_result.detail,
                )
                # Audit any host lines that were dropped
                for line in raw.splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    host = stripped.split()[0]
                    if host and not scope.is_in_scope(host):
                        # record the raw host token lowercased (matches prior audit shape)
                        h = _host_of(host)
                        a.record(runner.name, "RECON", h or host.lower(), "refused_out_of_scope")
            elif not dry_run:
                run_result = runner.run(
                    target_arg,
                    environ={"REACHAGENT_RECON_LIVE": "1"} if live_recon else None,
                )
                _tool_event(
                    runner.name,
                    run_result.outcome.value,
                    nodes=len(run_result.nodes),
                    detail=run_result.detail,
                )

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

    # Seed every configured identity into the same graph the Coordinator reads.
    # The old path always created only ``seed`` here, so a GUI-provided identity
    # file was used by the bespoke checks but never by the generic insertion-point
    # loop. Credentials stay in IdentityStore; only role/provenance enter the graph.
    if identities is not None and identities.names():
        for name in identities.names():
            g.add_identity(name, identities.identity(name))
    elif not list(g.identities()):
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
            "recon_tools": selected_recon_tools,
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
    # The solver owns the real per-path cap (40 by default). Keep this matching
    # ceiling as a second guard for a graph-mutating plugin that creates candidates.
    max_iterations = 40
    attempted_edges: set[tuple[str, str, str | None]] = set()
    while iterations < max_iterations and solver.budget_remaining("scan") > 0:
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
        # a dead/no-sink candidate is reselected for the full path budget.
        cands = [
            c
            for c in cands
            if (c.identity_node, c.endpoint_node, c.parameter_node) not in attempted_edges
        ]
        sel = _coordinator.score_and_select(cands)
        if sel is None:
            break
        if not _coordinator_support.budget_status(context):
            break
        # Default: the first sink-matched class from the library ordering.
        param_sink = g.parameter_sink(sel.parameter_node) if sel.parameter_node else None
        default_class = "sqli"
        for vc in _vuln_classes_for_library():
            if _sink_for_vuln_class(vc) == param_sink:
                default_class = vc
                break
        # Live vuln-class targeting — ranked list, flag OFF by default. The LLM
        # reasons about which classes fit this insertion point's shape and why;
        # we iterate through its ranking when earlier classes fail.
        ranked_classes = _live_vuln_classes_for(sel, g, base_url, operator_prompt)
        if not ranked_classes:
            ranked_classes = (default_class,)
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
                attempted_edges.add((sel.identity_node, sel.endpoint_node, None))
                continue
            from reachagent.graph.nodes import Parameter as _ProbeParam

            param_node = g.add_parameter(
                sel.endpoint_node, _ProbeParam(name="probe", location="query")
            )
        # Record the concrete insertion point after a bare endpoint has been
        # materialized; otherwise the newly seeded parameter would look like a
        # fresh candidate on the next Coordinator pass.
        attempted_edges.add((sel.identity_node, sel.endpoint_node, param_node))
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

        # LLM-driven transport selection (flag-gated): which mechanism fires
        # this probe — http, browser, or proxy. Advisory only; the oracle
        # still confirms. When the flag is off, the default http path is used.
        from reachagent.recon.transport_tuning import propose_transport

        transport_choice = propose_transport(g, sel.endpoint_node)
        if transport_choice.transport != "http":
            _log.info(
                "transport=%s for %s: %s",
                transport_choice.transport,
                sel.endpoint_node,
                transport_choice.rationale,
            )
        _ = transport_choice  # advisory; the payload chain still uses http by default

        def _on_chain_event(msg: str) -> None:
            if events is not None:
                from reachagent.scan.orchestrator import ScanEvent as SE

                events.append(SE(phase="payloads", kind="step", message=msg))

        # Iterate through the ranked vuln classes: try the LLM's first pick;
        # when it doesn't confirm, move to its second pick, etc. Stop on the
        # first confirmed finding (the oracle decided — not the LLM).
        result: _pc.PayloadChainResult | None = None
        for vc in ranked_classes:
            _log.debug("trying vuln_class=%s on %s", vc, sel.endpoint_node)
            result = _pc.run_payload_chain(
                _caller,
                identity=sel.identity_node,
                endpoint_node=sel.endpoint_node,
                param_node=param_node,
                vuln_class=vc,
                baseline_payload=baseline_payload,
                max_attempts=max_attempts,
                on_event=_on_chain_event,
            )
            if result.confirmed and result.finding_node:
                break
        if result is not None and result.confirmed and result.finding_node:
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
        "recon_tools": selected_recon_tools,
    }


# Backwards alias expected by some builders
scan = scan_target
