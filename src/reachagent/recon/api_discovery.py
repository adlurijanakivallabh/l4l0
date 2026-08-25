"""Spec-first API discovery — machine-readable specs before combinatorial guessing.

The generalizable close for the two-segment-API-route gap the live VAmPI scan hit:
flat content discovery (gobuster/ffuf) cannot find `/users/v1/{username}` — but a
target that exposes a machine-readable spec (OpenAPI/Swagger/GraphQL introspection)
tells us its whole surface exactly. This layer probes read-only for those specs
FIRST, parses them into Endpoint/Parameter facts, and only falls back to a bounded
combinatorial guess when no spec exists. Facts only — no oracle, no candidate, no
can_call, no Finding.

# DECISION BLOCK (D1-D3)

# D1. SPEC FIRST — build fully.
#     Read-only GET probes (through the gated RequestFirer) for the common spec
#     locations: /openapi.json, /swagger.json, /swagger/v1/swagger.json, /api-docs,
#     /v3/api-docs, /.well-known/openapi.yaml, /api/openapi.json, /openapi.yaml.
#     A found OpenAPI spec → parse the "paths" object (path + methods + parameters
#     per method) → materialize Endpoint(method, path, protocol=REST) +
#     Parameter(name, location from in:query/path/header/body) facts + resolves_to
#     edges (§6 absorption, no new types). GraphQL introspection reuses
#     reachagent.graphql.module.discover_schema (import the seam, never duplicate).
#     Found-nothing is a VALID result, reported honestly.
#
# D2. COMBINATORIAL FALLBACK — bounded.
#     Only when no spec found: {api, rest, api/v1, api/v2, v1, v2} × {users, books,
#     products, orders, items, login, health} as ≤ ~50 GET probes through the gated
#     firer, 2xx → Endpoint facts. Facts only, never primary, budget-capped.
#
# D3. JS BUNDLE MINING — DEFER, documented, not silently dropped.
#     Static regex over katana-discovered .js for fetch(/axios(/XHR URL literals
#     needs a JS-content fetch step; deferred to a future task.
# ---------------------------------------------------------------------------
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from reachagent.execution.firer import RequestFirer
from reachagent.graph.nodes import Endpoint, Host, Parameter, Protocol
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.tools._net import host_of

# Common machine-readable spec locations, probed read-only in order.
_SPEC_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/v3/api-docs",
    "/.well-known/openapi.yaml",
    "/api/openapi.json",
    "/openapi.yaml",
)

# Bounded combinatorial fallback vocab (D2): prefixes × resources, ≤ ~50 GETs.
_FALLBACK_PREFIXES: tuple[str, ...] = ("", "api", "rest", "api/v1", "api/v2", "v1", "v2")
_FALLBACK_RESOURCES: tuple[str, ...] = (
    "users",
    "books",
    "products",
    "orders",
    "items",
    "login",
    "health",
)


@dataclass(frozen=True)
class ApiDiscoveryResult:
    """What spec-first discovery found — honest even when it found nothing."""

    spec_found: bool
    spec_kind: str = ""  # "openapi" | "graphql" | ""
    endpoints: tuple[str, ...] = ()
    parameters: tuple[str, ...] = ()
    fallback_probes: int = 0

    @property
    def report(self) -> str:
        if self.spec_found:
            return f"spec-found {self.spec_kind}: {len(self.endpoints)} endpoints"
        return (
            f"no-spec: {len(self.endpoints)} endpoints from {self.fallback_probes} fallback probes"
        )


def _endpoint_methods(path_item: object) -> list[tuple[str, dict[str, object]]]:
    """The (method, operation) pairs for one OpenAPI path item (GET/POST/PUT/DELETE/PATCH)."""
    if not isinstance(path_item, dict):
        return []
    return [
        (m, op)
        for m, op in path_item.items()
        if m.lower() in ("get", "post", "put", "delete", "patch") and isinstance(op, dict)
    ]


def _param_location(param: object) -> str:
    """Map an OpenAPI parameter `in:` to a Parameter.location string."""
    if not isinstance(param, dict):
        return "query"
    return str(param.get("in", "query"))


def _paths_from_openapi(body: object) -> dict[str, object] | None:
    """The `paths` object of an OpenAPI/Swagger doc (v2 has paths at top level, v3 too)."""
    if not isinstance(body, dict):
        return None
    paths = body.get("paths")
    if isinstance(paths, dict):
        return paths
    # Some v3 docs nest under "paths" but some tools wrap — tolerate both.
    for key in ("paths",):
        candidate = body.get(key)
        if isinstance(candidate, dict):
            return candidate
    return None


def discover_api(
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    *,
    identity: str = "api-discovery",
) -> ApiDiscoveryResult:
    """Run spec-first API discovery against ``base_url``; write Endpoint/Parameter facts.

    Reads machine-readable specs first (D1), falls back to a bounded combinatorial
    probe (D2) only when no spec answers. Every probe is a read-only GET through the
    gated firer (scope + read-only-first + audit hold). Never writes a can_call,
    candidate, or Finding.
    """
    base = base_url.rstrip("/")
    host_addr = _host_of(base)
    host_node = graph.add_host(Host(address=host_addr, hostname=host_addr, source="api-discovery"))

    # D1 — probe the spec locations.
    for spec_path in _SPEC_PATHS:
        try:
            result = firer.fire(identity, "GET", base + spec_path, state_changing=False)
        except Exception:  # noqa: BLE001, S112 — a refused/errored probe is not a spec
            continue
        if not (200 <= result.status_code < 300):
            continue
        body_text = result.body.decode("utf-8", errors="replace")
        try:
            body = json.loads(body_text)
        except json.JSONDecodeError:
            continue
        paths = _paths_from_openapi(body)
        if paths is None:
            continue
        endpoints: list[str] = []
        parameters: list[str] = []
        for path, path_item in paths.items():
            for method, operation in _endpoint_methods(path_item):
                ep = graph.add_endpoint(
                    Endpoint(method=method.upper(), path=str(path), protocol=Protocol.REST)
                )
                graph.add_resolves_to(host_node, ep)
                endpoints.append(ep)
                raw_params = operation.get("parameters", [])
                op_params = raw_params if isinstance(raw_params, list) else []
                for param in op_params:
                    if not isinstance(param, dict):
                        continue
                    name = str(param.get("name", ""))
                    if not name:
                        continue
                    pn = graph.add_parameter(
                        ep, Parameter(name=name, location=_param_location(param))
                    )
                    parameters.append(pn)
        return ApiDiscoveryResult(
            spec_found=True,
            spec_kind="openapi",
            endpoints=tuple(endpoints),
            parameters=tuple(parameters),
        )

    # GraphQL introspection seam (D1) — reuse the existing module, never duplicate.
    try:
        from reachagent.graphql.module import GraphQLClient, discover_schema

        gql = GraphQLClient(firer, base_url=base)
        schema = discover_schema(gql, identity)
    except Exception:  # noqa: BLE001 — no GraphQL endpoint / introspection disabled
        schema = None
    if schema is not None:
        gql_endpoints: list[str] = []
        gql_parameters: list[str] = []
        ep = graph.add_endpoint(Endpoint(method="POST", path="/graphql", protocol=Protocol.GRAPHQL))
        graph.add_resolves_to(host_node, ep)
        gql_endpoints.append(ep)
        for field in schema.fields:
            pn = graph.add_parameter(ep, Parameter(name=field.name, location="graphql"))
            gql_parameters.append(pn)
        return ApiDiscoveryResult(
            spec_found=True,
            spec_kind="graphql",
            endpoints=tuple(gql_endpoints),
            parameters=tuple(gql_parameters),
        )

    # D2 — bounded combinatorial fallback.
    endpoints = []
    probes = 0
    for prefix in _FALLBACK_PREFIXES:
        for resource in _FALLBACK_RESOURCES:
            path = f"/{prefix}/{resource}".replace("//", "/") if prefix else f"/{resource}"
            probes += 1
            try:
                result = firer.fire(identity, "GET", base + path, state_changing=False)
            except Exception:  # noqa: BLE001, S112 — refused/errored is not a hit
                continue
            if 200 <= result.status_code < 300:
                ep = graph.add_endpoint(Endpoint(method="GET", path=path, protocol=Protocol.REST))
                graph.add_resolves_to(host_node, ep)
                endpoints.append(ep)
    return ApiDiscoveryResult(spec_found=False, endpoints=tuple(endpoints), fallback_probes=probes)


def _host_of(target: str) -> str:
    # Keep API-discovery hosts canonical with every other recon runner: a
    # non-default port belongs to the URL, not to a second Host graph node.
    return host_of(target)
