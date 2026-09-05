"""``recon`` agent tool — the missing wiring for Phase 9's spec-ingestion/JS-mining
library code, dispatch-by-``action`` (mirroring :mod:`lalo.integrations.mcp_client`'s
dispatch-by-name shape rather than one tool per underlying function).

Deliberately does NOT wrap :func:`~lalo.recon.runner.run_recon_chain`: that
orchestrator runs concrete :class:`~lalo.recon.runner.ReconRunner`
implementations (external-tool wrappers, e.g. an nmap/feroxbuster adapter), and
no concrete runner is built anywhere in this codebase - wrapping an empty
runner list would be a no-op tool. External tool invocation is exactly what
the free shell (``run_command``) is for; a genuine ``ReconRunner`` adapter is a
real future addition, not a gap this pass silently papers over.

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
from .facts import FactKind, ReconFact, merge_facts
from .js_mining import endpoint_urls_from_paths, find_sourcemap_url, mine_js_for_paths
from .spec_ingest import fetch_openapi_facts, parse_graphql_introspection


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


def build_recon_tool(firer: HttpFirer, graph: ReachabilityGraph, scope: ScopeGuard) -> FunctionTool:
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

        return ToolResult(
            observation=(
                f"error: unknown action {action!r} (valid: fetch_openapi, parse_graphql, mine_js)"
            ),
            ok=False,
        )

    return FunctionTool(
        name="recon",
        description=(
            "Extract candidate endpoints from a spec or JS bundle and merge them into the "
            "graph (scope-checked, same as http). args: "
            '{"action": "fetch_openapi", "spec_url": str} or '
            '{"action": "parse_graphql", "endpoint_url": str, "introspection": dict '
            "(the raw introspection query response you already fired via http)} or "
            '{"action": "mine_js", "js_source": str, "base_url": str}'
        ),
        func=_recon,
    )
