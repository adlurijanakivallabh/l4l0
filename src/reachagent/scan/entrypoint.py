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
from collections.abc import Callable, Iterable, Sequence
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


def _recon_state_snapshot(
    graph: ReachabilityGraph,
    audit: AuditLog,
    target: str,
    target_type: str,
    completed_tools: Sequence[str],
    pending_tools: Sequence[str],
) -> dict[str, str]:
    """Return bounded, deterministic facts for the adaptive recon proposer."""

    hosts = [
        {
            "address": host.address,
            "hostname": host.hostname,
            "technology": host.technology,
            "version": host.detected_version,
        }
        for _, host in graph.hosts()
    ][:40]
    services = [
        {
            "port": service.port,
            "protocol": service.protocol,
            "name": service.service_name,
            "version": service.detected_version,
        }
        for _, service in graph.services()
    ][:80]
    endpoints = [
        {
            "method": endpoint.method,
            "path": endpoint.path,
            "technology": endpoint.technology,
            "restricted": endpoint.access_restricted,
        }
        for _, endpoint in graph.endpoints()
    ][:100]
    outcomes = [
        {
            "tool": entry.identity,
            "outcome": entry.outcome,
            "target": entry.target,
        }
        for entry in audit.entries[-40:]
    ]
    import json

    return {
        "target": target[:500],
        "target_type": target_type,
        "completed_tools": json.dumps(list(completed_tools)),
        "pending_tools": json.dumps(list(pending_tools)),
        "host_count": str(len(list(graph.hosts()))),
        "service_count": str(len(list(graph.services()))),
        "endpoint_count": str(len(list(graph.endpoints()))),
        "hosts": json.dumps(hosts, sort_keys=True),
        "services": json.dumps(services, sort_keys=True),
        "endpoints": json.dumps(endpoints, sort_keys=True),
        "recent_tool_outcomes": json.dumps(outcomes, sort_keys=True),
    }


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
    recon_candidates: Iterable[str] | None = None,
    recon_selector: Callable[[dict[str, str], tuple[str, ...], tuple[str, ...]], object]
    | None = None,
    live_recon: bool = False,
    events: list[Any] | None = None,
    cancel_check: object | None = None,
) -> dict[str, Any]:
    """Generic autonomous scan entrypoint.

    Cold-start discovery gated by ScopeGuard (A); firing gated by
    ScopeGuard (B, wildcard-aware).

    dry_run=True: discover + score, return plan without firing any payload.
    dry_run=False: full loop (query_graph → score_and_select → check_budget →
                   run_payload_chain via direct Explorer/Validator seam) until
                   score_and_select is None or budget exhausted. advance() on
                   confirmed finding to requery derived edges.

    ``recon_selector`` is an optional LLM callback. When supplied, it receives
    bounded graph/audit facts after each recon tool and may choose the next
    allowlisted fact emitters or stop; it cannot change commands or confirmation
    authority. ``recon_candidates`` bounds the names it may add beyond the
    initial ``recon_tools`` sequence.

    Durable resume (D6/D2): ``resume_path`` loads a persisted graph + solver +
    audit and CONTINUES the loop (continue-not-replay — confirmed findings are
    loaded as facts, never re-confirmed; unexplored pairs are picked up by the
    normal loop; a RECOVER pass re-surfaces derived-credential pairs whose spawn
    was interrupted). ``state_path`` persists the run state at the end of a live
    run (atomic JSON). On resume, cold-start fixtures are NOT re-ingested — the
    loaded graph already carries them.

    ``cancel_check`` may be a ``threading.Event`` or a callable returning a
    boolean. It is checked before recon tools, candidate selection, and every
    payload class; cancellation raises ``ScanCancelled`` and stops without
    opening another target request.
    """
    from reachagent.scan.agentic_loop import check_cancel

    check_cancel(cancel_check)
    scope = ScopeGuard.from_raw(in_scope, out_of_scope)

    resumed = resume_path is not None
    # A resume run must checkpoint back to its source when no replacement path
    # was supplied. In-memory scans keep the historical zero-I/O behavior.
    checkpoint_path = state_path or resume_path
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
            headers = identities.auth_headers(name)
            if headers:
                identity_headers[name] = headers
    firer = RequestFirer(
        client,
        firer_scope,
        a,
        identity_headers=identity_headers,
        identity_stores=identities,
    )
    try:
        checkpoint_revision = 0

        def _checkpoint(
            phase: str,
            *,
            status: str = "running",
            iteration: int = 0,
            completed_tools: Iterable[str] = (),
            pending_tools: Iterable[str] = (),
            last_error: str | None = None,
        ) -> None:
            """Atomically persist bounded scheduling state when configured."""
            nonlocal checkpoint_revision
            if checkpoint_path is None:
                return
            from reachagent.graph.persistence import dump_graph

            checkpoint_revision += 1
            dump_graph(
                g,
                solver,
                a,
                checkpoint_path,
                phase_state={
                    "run_id": "scan",
                    "phase": phase,
                    "status": status,
                    "iteration": iteration,
                    "revision": checkpoint_revision,
                    "completed_tools": list(completed_tools),
                    "pending_tools": list(pending_tools),
                    "last_error": last_error,
                },
            )

        def _tool_event(
            tool_name: str,
            outcome: str,
            *,
            detail: str = "",
            phase: str = "tools",
            **extra: Any,
        ) -> None:
            """Emit a per-tool event so the GUI tools panel streams real activity."""
            if events is None:
                return
            try:
                from reachagent.scan.orchestrator import ScanEvent

                details: dict[str, Any] = {"tool": tool_name, "outcome": outcome}
                if outcome.lower() in {"error", "failed", "timeout", "refused"}:
                    details["error_category"] = "target"
                if detail:
                    details["detail"] = detail
                details.update(extra)
                events.append(
                    ScanEvent(
                        phase=phase,
                        kind="step",
                        message=f"{tool_name}: {outcome}",
                        details=details,
                    )
                )
            except Exception:  # noqa: BLE001 — event emission must never break the scan
                _log.debug("tool event emission failed for %s", tool_name, exc_info=True)

        def _authenticate_configured() -> None:
            """Bind every configured identity before authenticated mapping/firing.

            One identity's login failure no longer aborts the whole scan: when
            at least one other configured identity authenticates successfully,
            the scan proceeds with whatever sessions it actually has (real
            case: a second/admin credential can fail while the primary
            identity's session is already good). Only a total failure --
            every identity that needed a fresh login failed -- is still a
            hard stop, matching the original "nothing usable" intent.
            """
            if identities is None:
                return
            from reachagent.identity.login import LoginError, authenticate_identity

            attempted = 0
            failures: list[tuple[str, LoginError]] = []
            for name in identities.names():
                if not identities.auth_headers(name):
                    attempted += 1
                    _tool_event(
                        "authentication",
                        "starting",
                        phase="auth",
                        identity=name,
                        detail="locating login surface",
                    )
                    try:
                        authenticate_identity(firer, identities, name, base_url, graph=g)
                    except LoginError as exc:
                        failures.append((name, exc))
                        _tool_event(
                            "authentication",
                            "failed",
                            phase="auth",
                            identity=name,
                            detail=f"{exc.code}: {exc}",
                        )
                        continue
                    _tool_event(
                        "authentication",
                        "authenticated",
                        phase="auth",
                        identity=name,
                        detail="opaque session reference bound",
                    )
                session_node = identities.ensure_session(name)
                if session_node is not None:
                    g.add_session(session_node)

            if attempted and len(failures) == attempted:
                name, exc = failures[-1]
                _tool_event(
                    "authentication",
                    "blocked",
                    phase="auth",
                    identity=name,
                    detail=f"{exc.code}: {exc}",
                )
                raise exc

        if not resumed and surface_path is not None:
            # Optional --surface seeding (Task 27): materialize a declared surface
            # (endpoints/parameters/objects) BEFORE cold-start recon, so recon then
            # enriches. The mapper's read-only can_call probes seed real verdicts;
            # state-changing endpoints are materialized but never fired (read-only-
            # first holds). This is an OPTIONAL input — pure cold-start is unchanged.
            from reachagent.identity.store import IdentityStore
            from reachagent.recon.mapper import SurfaceMapper, SurfaceSpec

            _checkpoint("surface", pending_tools=("surface",))
            try:
                SurfaceMapper(g, firer, identities or IdentityStore(), base_url).map_structure(
                    SurfaceSpec.from_file(surface_path)
                )
            except Exception as exc:  # noqa: BLE001 — persist mapper failure state
                _checkpoint("surface", status="errored", last_error=type(exc).__name__)
                raise
            _checkpoint("surface", status="completed", completed_tools=("surface",))

        if not resumed:
            # Recon dispatch by target type (D2): host-shaped targets skip subdomain
            # enumeration; domain/url targets crawl + fingerprint; host:port targets
            # go straight to TLS probes. Scope gates still run before every ingest.
            target_type = detect_target_type(base_url)
            if target_type in ("ip", "cidr"):
                from reachagent.recon.tools.masscan import MasscanRunner
                from reachagent.recon.tools.nmap import NmapRunner
                from reachagent.recon.tools.rustscan import RustscanRunner

                default_types: list[type[Any]] = [NmapRunner, MasscanRunner, RustscanRunner]
            elif target_type == "host_port":
                from reachagent.recon.tools.tls_probe import SslscanRunner, SslyzeRunner

                default_types = [SslscanRunner, SslyzeRunner]
            else:  # domain / url
                from reachagent.recon.tools.dirb import DirbRunner
                from reachagent.recon.tools.feroxbuster import FeroxbusterRunner
                from reachagent.recon.tools.ffuf import FfufRunner
                from reachagent.recon.tools.gobuster import GobusterRunner
                from reachagent.recon.tools.katana import KatanaRunner
                from reachagent.recon.tools.subdomains import AmassRunner, SubfinderRunner
                from reachagent.recon.tools.theharvester import TheHarvesterRunner
                from reachagent.recon.tools.whatweb import WhatWebRunner

                default_types = [
                    SubfinderRunner,
                    AmassRunner,
                    TheHarvesterRunner,
                    WhatWebRunner,
                    KatanaRunner,
                    # Content-discovery family, ffuf-primary (native -ac
                    # auto-calibration) with feroxbuster/gobuster/dirb as
                    # successive fallbacks — the dispatch loop below stops the
                    # family after the first one yields a useful path, so in the
                    # common case only ONE of these four ever actually fires.
                    # feroxbuster ranks ahead of gobuster: Rust/tokio async I/O
                    # gives materially higher request throughput than gobuster's
                    # Go implementation, plus native recursive/adaptive scanning
                    # and wildcard filtering gobuster lacks — a fallback that
                    # finishes faster and self-tunes better should go first.
                    FfufRunner,
                    FeroxbusterRunner,
                    GobusterRunner,
                    DirbRunner,
                ]

            # The registry contains only ReachAgent-owned adapters. The model can
            # choose names from it, never a binary or arbitrary command string.
            from reachagent.recon.tools.arjun import ArjunRunner
            from reachagent.recon.tools.bbot import BbotRunner
            from reachagent.recon.tools.dnsrecon import DnsreconRunner
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
            from reachagent.recon.tools.urlfinder import UrlfinderRunner
            from reachagent.recon.tools.wafw00f import Wafw00fRunner
            from reachagent.recon.tools.wpscan_passive import WpscanPassiveRunner
            from reachagent.recon.tools.x8 import X8Runner

            registry: dict[str, type[Any]] = {rt.name.lower(): rt for rt in default_types}
            registry.update(
                {
                    cls.name.lower(): cls
                    for cls in (
                        ArjunRunner,
                        BbotRunner,
                        DnsreconRunner,
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
                        UrlfinderRunner,
                        WaybackUrlsRunner,
                        Wafw00fRunner,
                        WpscanPassiveRunner,
                        X8Runner,
                    )
                }
            )
            default_names = tuple(rt.name for rt in default_types)
            initial_names = (
                tuple(
                    dict.fromkeys(
                        registry[str(name).strip().lower()].name
                        for name in recon_tools
                        if str(name).strip().lower() in registry
                    )
                )
                if recon_tools is not None
                else default_names
            )
            candidate_names = tuple(
                dict.fromkeys(
                    registry[str(name).strip().lower()].name
                    for name in (
                        recon_candidates if recon_candidates is not None else initial_names
                    )
                    if str(name).strip().lower() in registry
                )
            )
            if not candidate_names:
                candidate_names = initial_names

            # URL-shaped tools need the full base_url; host-line and port/TLS tools
            # take the bare host (or host:port) target.
            _URL_TOOLS = frozenset(
                {
                    "arjun",
                    "bbot",
                    "dirb",
                    "dnsrecon",
                    "feroxbuster",
                    "ffuf",
                    "gau",
                    "gobuster",
                    "httpx",
                    "katana",
                    "paramspider",
                    "urlfinder",
                    "wafw00f",
                    "waybackurls",
                    "whatweb",
                    "wpscan",
                    "x8",
                }
            )
            content_discovery = frozenset({"gobuster", "ffuf", "feroxbuster", "dirb"})
            subdomain_enum = frozenset(
                {"subfinder", "amass", "theharvester", "theHarvester", "dnsrecon", "bbot"}
            )
            cal_result = None
            dns_result = None

            pending_names = list(initial_names)
            completed_names: list[str] = []
            runners: dict[str, Any] = {}

            _checkpoint("recon", pending_tools=pending_names)

            def _selection_values(selection: object) -> tuple[tuple[str, ...], bool, str]:
                """Read a validated callback result without importing planner types."""

                names = tuple(str(name) for name in getattr(selection, "tools", ()))
                stop = bool(getattr(selection, "stop", False))
                rationale = str(getattr(selection, "rationale", ""))
                return names, stop, rationale

            def _safe_select(
                state: dict[str, str], candidates: tuple[str, ...], completed: tuple[str, ...]
            ) -> object:
                """Call ``recon_selector``; degrade to a clean stop on any failure.

                A planner/provider failure (bad response, exhausted validation
                retries, a transient API error) must never abort the whole scan —
                the deterministic tool set already selected still ran. Degrading to
                "stop adaptive selection, continue with what's collected" is the
                honest, safe default; the scan proceeds past recon with whatever
                facts already landed instead of raising out of scan_target entirely.
                """
                if recon_selector is None:
                    raise RuntimeError("_safe_select called without a recon_selector")
                try:
                    return recon_selector(state, candidates, completed)
                except Exception as exc:  # noqa: BLE001 — degrade, never abort the scan
                    _tool_event(
                        "recon-planner",
                        "degraded",
                        phase="recon",
                        detail=f"{type(exc).__name__}: {exc}"[:300],
                    )
                    from types import SimpleNamespace

                    return SimpleNamespace(
                        tools=(), stop=True, rationale="recon planner failed — degrading"
                    )

            if recon_selector is not None:
                selection = _safe_select(
                    _recon_state_snapshot(
                        g, a, base_url, target_type, completed_names, pending_names
                    ),
                    candidate_names,
                    tuple(completed_names),
                )
                selected_names, stop, rationale = _selection_values(selection)
                pending_names = [name for name in selected_names if name in candidate_names]
                _tool_event(
                    "recon-planner",
                    "selected" if pending_names else "stopped",
                    phase="recon",
                    tools=list(pending_names),
                    rationale=rationale,
                )
                if stop and not pending_names:
                    pending_names = []

            while pending_names:
                check_cancel(cancel_check)
                name = pending_names.pop(0)
                if name in completed_names or name.lower() not in registry:
                    continue
                if not dry_run and name in content_discovery and cal_result is None:
                    from reachagent.recon.calibration import CalibrationRunner

                    cal_result = CalibrationRunner(firer, base_url).run()
                if (
                    not dry_run
                    and target_type in ("domain", "url")
                    and name in subdomain_enum
                    and dns_result is None
                ):
                    from reachagent.recon.calibration import DnsWildcardProber

                    prober = (
                        DnsWildcardProber(target_host, resolve=dns_resolve)
                        if dns_resolve is not None
                        else DnsWildcardProber(target_host)
                    )
                    dns_result = prober.run()
                    g.add_host(
                        Host(
                            address=target_host,
                            hostname=target_host,
                            source="scan",
                            technology=dns_result.shape_label,
                        )
                    )
                runner = runners.setdefault(
                    name,
                    registry[name.lower()](graph=g, scope=scope, audit=a),
                )
                if name in content_discovery:
                    runner.calibration = cal_result
                if name in subdomain_enum and dns_result is not None:
                    runner.dns_wildcard_ip = dns_result.wildcard_ip
                    if dns_resolve is not None:
                        runner.resolve = dns_resolve
                target_arg = base_url if name in _URL_TOOLS else target_host
                _tool_event(name, "starting")
                _checkpoint(
                    "recon",
                    completed_tools=completed_names,
                    pending_tools=(name, *pending_names),
                )
                result_nodes: tuple[str, ...] = ()
                if fixtures is not None:
                    raw = fixtures.get(name, "")
                    if not raw:
                        _tool_event(name, "no-fixture", detail="skipped (no fixture data)")
                    else:
                        allowed_raw = _filter_fixture_by_scope(raw, scope, name)
                        ingest_result = runner.ingest(target_arg, allowed_raw)
                        result_nodes = ingest_result.nodes
                        _tool_event(
                            name,
                            ingest_result.outcome.value,
                            output=ingest_result.output_preview or None,
                            nodes=len(result_nodes),
                            detail=ingest_result.detail,
                        )
                elif not dry_run:
                    try:
                        run_result = runner.run(
                            target_arg,
                            environ={"REACHAGENT_RECON_LIVE": "1"} if live_recon else None,
                        )
                    except Exception as exc:  # noqa: BLE001 — persist retryable tool failure
                        _checkpoint(
                            "recon",
                            status="errored",
                            completed_tools=completed_names,
                            pending_tools=(name, *pending_names),
                            last_error=type(exc).__name__,
                        )
                        raise
                    result_nodes = run_result.nodes
                    _tool_event(
                        name,
                        run_result.outcome.value,
                        command=" ".join(run_result.command) if run_result.command else None,
                        output=run_result.output_preview or None,
                        nodes=len(result_nodes),
                        detail=run_result.detail,
                    )
                # A content-discovery adapter always touches its target Host node
                # (recon-facts-only — every runner does this even on zero hits), so
                # counting ALL touched nodes would make the family look "satisfied"
                # on a genuinely empty result. Count Endpoint nodes specifically —
                # the actual useful yield the primary+fallback economy cares about.
                endpoint_yield = sum(1 for n in result_nodes if n.startswith("endpoint:"))
                if name in content_discovery and endpoint_yield > 0:
                    # Primary+fallback economy (§C): one content brute-forcer's
                    # useful yield satisfies the family — drop the rest of the
                    # queued fallbacks rather than re-crawling the same paths
                    # 3 more times. A fallback only ever fires when the one ahead
                    # of it in `pending_names` returned zero useful paths.
                    dropped = [n for n in pending_names if n in content_discovery]
                    if dropped:
                        pending_names = [n for n in pending_names if n not in content_discovery]
                        _tool_event(
                            "content-discovery",
                            "family-satisfied",
                            phase="recon",
                            detail=f"{name} yielded {endpoint_yield} endpoint(s)",
                            skipped=dropped,
                        )
                completed_names.append(name)
                if name not in selected_recon_tools:
                    selected_recon_tools += (name,)
                _checkpoint(
                    "recon",
                    completed_tools=completed_names,
                    pending_tools=pending_names,
                )

                if recon_selector is None:
                    continue
                remaining_candidates = tuple(
                    candidate
                    for candidate in candidate_names
                    if candidate not in completed_names and candidate not in pending_names
                )
                if not remaining_candidates:
                    continue
                selection = _safe_select(
                    _recon_state_snapshot(
                        g, a, base_url, target_type, completed_names, remaining_candidates
                    ),
                    remaining_candidates,
                    tuple(completed_names),
                )
                selected_names, stop, rationale = _selection_values(selection)
                additions = [
                    candidate
                    for candidate in selected_names
                    if candidate in remaining_candidates and candidate not in pending_names
                ]
                pending_names.extend(additions)
                _tool_event(
                    "recon-planner",
                    "selected" if additions else ("stopped" if stop else "no-new-tools"),
                    phase="recon",
                    tools=additions,
                    rationale=rationale,
                    completed=list(completed_names),
                )
                if stop:
                    break

            # Bind configured identities before spec/API mapping so every subsequent
            # endpoint probe carries the selected isolated session.
            if not dry_run:
                _checkpoint("auth", completed_tools=completed_names, pending_tools=("auth",))
                try:
                    _authenticate_configured()
                except Exception as exc:  # noqa: BLE001 — persist blocked auth state
                    _checkpoint(
                        "auth",
                        status="errored",
                        completed_tools=completed_names,
                        last_error=type(exc).__name__,
                    )
                    raise
                _checkpoint("auth", status="completed", completed_tools=completed_names)

            # Spec-first API discovery (Task 27, live only — it fires read-only GET
            # probes). After --surface seeding and cold-start recon, before the
            # Coordinator loop: probe for OpenAPI/GraphQL specs, parse into
            # Endpoint/Parameter facts, else a bounded combinatorial fallback.
            if not dry_run:
                from reachagent.recon.api_discovery import discover_api

                _checkpoint("endpoints", completed_tools=completed_names, pending_tools=("api",))
                try:
                    discovery = discover_api(g, firer, base_url)
                except Exception as exc:  # noqa: BLE001 — persist retryable discovery failure
                    _checkpoint(
                        "endpoints",
                        status="errored",
                        completed_tools=completed_names,
                        last_error=type(exc).__name__,
                    )
                    raise
                if discovery is None:
                    _tool_event(
                        "surface-mapper",
                        "unavailable",
                        phase="endpoints",
                        detail="discovery provider returned no result",
                    )
                else:
                    _tool_event(
                        "surface-mapper",
                        discovery.report,
                        phase="endpoints",
                        endpoints=len(discovery.endpoints),
                        parameters=len(discovery.parameters),
                        pages=discovery.pages_crawled,
                        scripts=discovery.scripts_parsed,
                        forms=discovery.forms_found,
                    )
                _checkpoint("endpoints", status="completed", completed_tools=completed_names)

        # On resume there is no cold-start block above; authenticate before the
        # coordinator replays any unexplored endpoint. Dry runs never submit creds.
        if resumed and not dry_run:
            _checkpoint("auth", pending_tools=("auth",))
            try:
                _authenticate_configured()
            except Exception as exc:  # noqa: BLE001 — persist blocked auth state
                _checkpoint("auth", status="errored", last_error=type(exc).__name__)
                raise
            _checkpoint("auth", status="completed")

        from reachagent.tools.explorer_context import ExplorerContext

        ctx = ExplorerContext(
            graph=g,
            firer=firer,
            library=lib,
            base_url=base_url,
            identities=identities,
        )

        if resumed and not dry_run:
            # RECOVER pass (D3): re-surface unexplored pairs for persisted derived
            # credentials whose spawn/requery was interrupted by the crash. A finding
            # whose spawned identity is already in _spawned_by_path was advanced —
            # skip (no replay). Errored edges need no pass: an errored fire writes no
            # can_call verdict, so the normal loop retries them; inconclusive edges
            # carry a verdict and stay skipped.
            from reachagent.graph.nodes import Session as _SessionNode
            from reachagent.graph.store import identity_id as _identity_id

            _checkpoint("recover", pending_tools=("derived-credentials",))
            try:
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
            except Exception as exc:  # noqa: BLE001 — persist retryable recovery failure
                _checkpoint("recover", status="errored", last_error=type(exc).__name__)
                raise
            _checkpoint("recover", status="completed")

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

        if dry_run and not list(g.endpoints()):
            from reachagent.graph.nodes import Endpoint, Parameter

            # Dry-run retains the historical planning placeholder so the UI can
            # render an empty-target plan. Live scans never invent an endpoint.
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
            _checkpoint(
                "planning",
                status="completed",
                completed_tools=selected_recon_tools,
            )
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
            check_cancel(cancel_check)
            iterations += 1
            _checkpoint("payloads", iteration=iterations)
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
                    if g.can_call_status(c.identity_node, c.endpoint_node)
                    != FindingStatus.INCONCLUSIVE
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
            selected_endpoint = g.endpoint(sel.endpoint_node)
            selected_parameter = g.parameter(param_node) if param_node else None
            identity_data = next(
                (data for node, data in g.identities() if node == sel.identity_node),
                None,
            )
            auth_state = getattr(
                getattr(identity_data, "auth_state", None),
                "value",
                getattr(identity_data, "auth_state", None),
            )
            payload_context = {
                "method": selected_endpoint.method,
                "content_type": selected_endpoint.content_type,
                "framework": selected_endpoint.technology,
                "auth_state": str(auth_state) if auth_state else None,
                "location": selected_parameter.location if selected_parameter else None,
            }
            for vc in ranked_classes:
                check_cancel(cancel_check)
                _log.debug("trying vuln_class=%s on %s", vc, sel.endpoint_node)
                try:
                    result = _pc.run_payload_chain(
                        _caller,
                        identity=sel.identity_node,
                        endpoint_node=sel.endpoint_node,
                        param_node=param_node,
                        vuln_class=vc,
                        baseline_payload=baseline_payload,
                        method=selected_endpoint.method,
                        payload_context=payload_context,
                        # Mutations are opt-in from the LLM payload proposal; the
                        # default chain remains one parent reference per bucket.
                        mutation_limit=0,
                        max_attempts=max_attempts,
                        on_event=_on_chain_event,
                    )
                except Exception as exc:  # noqa: BLE001 — preserve retryable chain failure
                    _checkpoint(
                        "payloads",
                        status="errored",
                        iteration=iterations,
                        last_error=type(exc).__name__,
                    )
                    raise
                # Persist the oracle result immediately; a crash after a confirmed
                # or inconclusive decision must not turn it into a replay.
                _checkpoint("payloads", iteration=iterations)
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

        _checkpoint(
            "completed",
            status="completed",
            iteration=iterations,
            completed_tools=selected_recon_tools,
        )

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
    finally:
        client.close()


# Backwards alias expected by some builders
scan = scan_target
