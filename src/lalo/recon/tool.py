"""``recon`` agent tool — the missing wiring for Phase 9's spec-ingestion/JS-mining
library code, dispatch-by-``action`` (mirroring :mod:`lalo.integrations.mcp_client`'s
dispatch-by-name shape rather than one tool per underlying function).

``scan_ports`` wraps :func:`~lalo.recon.runner.run_recon_chain` over one
concrete :class:`~lalo.recon.scan.NmapServiceScanRunner` — that orchestrator
existed since Phase 9 with nothing to run through it (no concrete
:class:`~lalo.recon.runner.ReconRunner` was ever built); this closes that,
one curated tool (nmap), not an attempt to wrap every external scanner a
future mission might want. A ``container`` is optional precisely because that
gap existed before this action did: a caller that doesn't pass one simply
doesn't get ``scan_ports`` (checked at call time, not construction time, so
the other three actions stay usable without a container in any test or
future context that has no need for one).

Every action ends at :func:`~lalo.recon.facts.merge_facts` - the same
:class:`~lalo.execution.scope.ScopeGuard` the ``http`` tool itself uses - so a
spec's or a bundle's own claimed URLs can never self-grant scope, matching
:mod:`lalo.recon.facts`'s own design.
"""

from __future__ import annotations

from ..agent.tools import FunctionTool, ToolResult, str_arg
from ..execution.firer import HttpFirer
from ..execution.scope import ScopeGuard
from ..graph.model import ReachabilityGraph
from ..runtime.tool import CommandExecutor
from .facts import FactKind, ReconFact, merge_facts
from .js_mining import endpoint_urls_from_paths, find_sourcemap_url, mine_js_for_paths
from .runner import run_recon_chain
from .scan import NmapServiceScanRunner
from .spec_ingest import fetch_openapi_facts, parse_graphql_introspection, parse_postman_collection


def _report(
    action: str, facts: list[ReconFact], graph: ReachabilityGraph, scope: ScopeGuard
) -> ToolResult:
    if not facts:
        return ToolResult(observation=f"{action}: no facts extracted", ok=False)
    result = merge_facts(graph, scope, facts)
    lines = [f"{action}: {len(result.accepted)} fact(s) merged, {len(result.rejected)} rejected"]
    lines += [f"+ {f.url}" for f in result.accepted]
    lines += [f"- {f.url} ({reason})" for f, reason in result.rejected]
    return ToolResult(observation="\n".join(lines))


def build_recon_tool(
    firer: HttpFirer,
    graph: ReachabilityGraph,
    scope: ScopeGuard,
    *,
    container: CommandExecutor | None = None,
) -> FunctionTool:
    def _recon(args: dict[str, object]) -> ToolResult:
        action = str_arg(args, "action").strip()

        if action == "fetch_openapi":
            spec_url = str_arg(args, "spec_url").strip()
            if not spec_url:
                return ToolResult(observation="error: 'spec_url' is required", ok=False)
            return _report(action, fetch_openapi_facts(firer, spec_url), graph, scope)

        if action == "parse_graphql":
            endpoint_url = str_arg(args, "endpoint_url").strip()
            introspection = args.get("introspection")
            if not endpoint_url or not isinstance(introspection, dict):
                return ToolResult(
                    observation="error: 'endpoint_url' and 'introspection' (dict) are required",
                    ok=False,
                )
            return _report(
                action, parse_graphql_introspection(introspection, endpoint_url), graph, scope
            )

        if action == "parse_postman":
            collection = args.get("collection")
            if not isinstance(collection, dict):
                return ToolResult(
                    observation="error: 'collection' (dict, the raw Postman collection JSON) "
                    "is required",
                    ok=False,
                )
            return _report(action, parse_postman_collection(collection), graph, scope)

        if action == "mine_js":
            js_source = str_arg(args, "js_source")
            base_url = str_arg(args, "base_url").strip()
            if not js_source.strip() or not base_url:
                return ToolResult(
                    observation="error: 'js_source' and 'base_url' are required", ok=False
                )
            paths = mine_js_for_paths(js_source)
            urls = endpoint_urls_from_paths(base_url, paths)
            facts = [ReconFact(kind=FactKind.ENDPOINT, url=u, source="js-mining") for u in urls]
            sourcemap_hint = find_sourcemap_url(js_source)
            result = _report(action, facts, graph, scope)
            if sourcemap_hint:
                result.observation += (
                    f"\nsource map referenced: {sourcemap_hint} (fetch it yourself to mine further)"
                )
            return result

        if action == "scan_ports":
            if container is None:
                return ToolResult(
                    observation="error: no runtime container available for scan_ports", ok=False
                )
            host = str_arg(args, "host").strip()
            if not host:
                return ToolResult(observation="error: 'host' is required", ok=False)
            ports = str_arg(args, "ports", "1-1000").strip()
            runner = NmapServiceScanRunner(container, scope, host=host, ports=ports)
            chain_report = run_recon_chain([runner])
            if chain_report.skipped:
                return ToolResult(
                    observation=f"{action}: {host!r} is not in engagement - refused to scan",
                    ok=False,
                )
            if chain_report.failed:
                name, error = chain_report.failed[0]
                return ToolResult(observation=f"{action}: {name} failed: {error}", ok=False)
            return _report(action, chain_report.facts, graph, scope)

        return ToolResult(
            observation=(
                "error: unknown action "
                f"{action!r} (valid: fetch_openapi, parse_graphql, parse_postman, mine_js, "
                "scan_ports)"
            ),
            ok=False,
        )

    return FunctionTool(
        name="recon",
        description=(
            "Extract candidate endpoints from a spec, Postman collection, or JS bundle, or "
            "run an nmap service scan, and merge the results into the graph (scope-checked, "
            'same as http). args: {"action": "fetch_openapi", "spec_url": str} or '
            '{"action": "parse_graphql", "endpoint_url": str, "introspection": dict '
            "(the raw introspection query response you already fired via http)} or "
            '{"action": "parse_postman", "collection": dict (the raw Postman collection JSON)} '
            'or {"action": "mine_js", "js_source": str, "base_url": str} or '
            '{"action": "scan_ports", "host": str, "ports": str (optional, e.g. "1-1000")}'
        ),
        func=_recon,
    )
