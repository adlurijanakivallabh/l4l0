"""Read-only API and web-surface discovery.

Machine-readable contracts are parsed before bounded HTML/JavaScript discovery.
The output is structural graph evidence only: no form is submitted, no payload
is generated, and no oracle/finding path is reachable from this module.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

import yaml

from reachagent.execution.firer import RequestFirer
from reachagent.graph.nodes import Endpoint, Host, Parameter, Protocol
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.mapper import EndpointSpec, ParameterSpec
from reachagent.recon.surface import (
    ParsedSurface,
    evidence_ref,
    json_example,
    parse_html_surface,
    parse_javascript_surface,
)
from reachagent.recon.tools._net import host_of

_READ_ONLY = frozenset({"GET", "HEAD", "OPTIONS"})
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
_MAX_PAGES = 12
_MAX_SCRIPTS = 20
_MAX_RESPONSE_BYTES = 200_000
_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ApiDiscoveryResult:
    """Bounded discovery counters and graph ids."""

    spec_found: bool
    spec_kind: str = ""
    endpoints: tuple[str, ...] = ()
    parameters: tuple[str, ...] = ()
    fallback_probes: int = 0
    pages_crawled: int = 0
    scripts_parsed: int = 0
    forms_found: int = 0

    @property
    def report(self) -> str:
        if self.spec_found:
            return f"spec-found {self.spec_kind}: {len(self.endpoints)} endpoints"
        return (
            f"surface: {len(self.endpoints)} endpoints, {len(self.parameters)} parameters; "
            f"pages={self.pages_crawled}, scripts={self.scripts_parsed}, "
            f"fallback={self.fallback_probes}"
        )


def _endpoint_methods(path_item: object) -> list[tuple[str, dict[str, object]]]:
    """Return operation objects while ignoring OpenAPI path-item metadata."""
    if not isinstance(path_item, Mapping):
        return []
    methods = {"get", "head", "options", "post", "put", "patch", "delete"}
    return [
        (str(method).lower(), dict(operation))
        for method, operation in path_item.items()
        if str(method).lower() in methods and isinstance(operation, Mapping)
    ]


def _paths_from_openapi(body: object) -> dict[str, object] | None:
    if not isinstance(body, Mapping):
        return None
    paths = body.get("paths")
    return dict(paths) if isinstance(paths, Mapping) else None


def _document(body: bytes) -> Mapping[str, object] | None:
    text = body.decode("utf-8", errors="replace")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        try:
            value = yaml.safe_load(text)
        except yaml.YAMLError:
            return None
    return value if isinstance(value, Mapping) else None


def _resolve_ref(document: Mapping[str, object], value: object) -> Mapping[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    ref = value.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return value
    current: object = document
    for part in ref[2:].split("/"):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part.replace("~1", "/").replace("~0", "~"))
    return current if isinstance(current, Mapping) else None


def _scalar_example(schema: Mapping[str, object]) -> object:
    if schema.get("example") is not None:
        return schema["example"]
    if schema.get("default") is not None:
        return schema["default"]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    kind = str(schema.get("type", "string"))
    if kind in {"integer", "number"}:
        return 1
    if kind == "boolean":
        return True
    if kind == "array":
        return []
    return "reachagent-probe"


def _schema_example(document: Mapping[str, object], schema: object, *, depth: int = 0) -> object:
    if depth > 4:
        return "reachagent-probe"
    resolved = _resolve_ref(document, schema)
    if resolved is None:
        return "reachagent-probe"
    all_of = resolved.get("allOf")
    if isinstance(all_of, list):
        merged: dict[str, object] = {}
        for part in all_of:
            value = _schema_example(document, part, depth=depth + 1)
            if isinstance(value, Mapping):
                merged.update(value)
        return merged
    properties = resolved.get("properties")
    if resolved.get("type") == "object" or isinstance(properties, Mapping):
        if not isinstance(properties, Mapping):
            return {}
        return {
            str(name): _schema_example(document, value, depth=depth + 1)
            for name, value in properties.items()
        }
    return _scalar_example(resolved)


def _schema_parameters(
    document: Mapping[str, object],
    schema: object,
    *,
    location: str,
    serialization: str,
    source: str,
) -> tuple[list[ParameterSpec], str | None]:
    resolved = _resolve_ref(document, schema)
    if resolved is None:
        return [], None
    properties = resolved.get("properties")
    if not isinstance(properties, Mapping):
        name = str(resolved.get("title") or "body")
        example = json_example(_schema_example(document, resolved))
        return [
            ParameterSpec(
                name=name,
                location=location,
                serialization=serialization,
                example=example,
                source=source,
                confidence=0.95,
                evidence_ref=evidence_ref(source, f"body:{name}"),
            )
        ], example
    raw_required = resolved.get("required")
    required = (
        {str(item) for item in raw_required if isinstance(item, str)}
        if isinstance(raw_required, list)
        else set()
    )
    params: list[ParameterSpec] = []
    body_value: dict[str, object] = {}
    for name, raw_property in properties.items():
        resolved_property = _resolve_ref(document, raw_property)
        property_schema: Mapping[str, object] = resolved_property or {}
        example_value = _scalar_example(property_schema)
        body_value[str(name)] = example_value
        params.append(
            ParameterSpec(
                name=str(name),
                location=location,
                serialization=serialization,
                required=str(name) in required,
                example=json_example(example_value),
                source=source,
                confidence=0.95,
                evidence_ref=evidence_ref(source, f"body:{name}"),
            )
        )
    return params, json_example(body_value)


def _parameter_from_openapi(
    document: Mapping[str, object], raw: object, source: str
) -> tuple[list[ParameterSpec], dict[str, str]]:
    parameter = _resolve_ref(document, raw)
    if parameter is None:
        return [], {}
    location = str(parameter.get("in", "query")).lower()
    if location == "querystring":
        location = "query"
    if location == "body":
        schema = parameter.get("schema")
        resolved_schema = _resolve_ref(document, schema) or {}
        if isinstance(resolved_schema.get("properties"), Mapping):
            specs, _body = _schema_parameters(
                document,
                resolved_schema,
                location="body",
                serialization="application/json",
                source=source,
            )
            return specs, {}
        name = str(parameter.get("name") or "body").strip() or "body"
        return [
            ParameterSpec(
                name=name,
                location="body",
                serialization="application/json",
                required=bool(parameter.get("required", False)),
                source=source,
                confidence=0.99,
                evidence_ref=evidence_ref(source, f"parameter:body:{name}"),
            )
        ], {}
    if location not in {"query", "path", "header", "cookie"}:
        return [], {}
    name = str(parameter.get("name", "")).strip()
    if not name:
        return [], {}
    schema = _resolve_ref(document, parameter.get("schema")) or parameter
    example_value = parameter.get("example", schema.get("example", schema.get("default")))
    example = json_example(example_value) if example_value is not None else None
    spec = ParameterSpec(
        name=name,
        location=location,
        serialization="application/x-www-form-urlencoded" if location == "query" else location,
        required=bool(parameter.get("required", False)),
        example=example,
        source=source,
        confidence=0.99,
        evidence_ref=evidence_ref(source, f"parameter:{location}:{name}"),
    )
    sample = str(example_value) if example_value is not None else "reachagent-probe"
    return [spec], {name: sample} if location == "path" else {}


def _response_contract(
    document: Mapping[str, object], operation: Mapping[str, object]
) -> tuple[str | None, str | None]:
    """Normalize one successful response's content type and shape for replay."""
    responses = operation.get("responses")
    if not isinstance(responses, Mapping):
        return None, None
    success = next(
        (value for key, value in responses.items() if str(key).startswith("2")),
        None,
    )
    response = _resolve_ref(document, success)
    if response is not None and isinstance(response.get("schema"), Mapping):
        produces = operation.get("produces") or document.get("produces")
        content_type = str(produces[0]) if isinstance(produces, list) and produces else None
        schema_v2 = _resolve_ref(document, response.get("schema")) or {}
        shape: dict[str, object] = {"type": schema_v2.get("type", "object")}
        properties = schema_v2.get("properties")
        if isinstance(properties, Mapping):
            shape["properties"] = sorted(str(name) for name in properties)
        return content_type, json_example(shape)
    content = response.get("content") if response is not None else None
    if not isinstance(content, Mapping) or not content:
        return None, None
    content_type = str(next(iter(content)))
    media = _resolve_ref(document, content.get(content_type)) or {}
    schema_v3 = _resolve_ref(document, media.get("schema"))
    if schema_v3 is None:
        return content_type, None
    properties = schema_v3.get("properties")
    shape_v3: dict[str, object] = {"type": schema_v3.get("type", "object")}
    if isinstance(properties, Mapping):
        shape_v3["properties"] = sorted(str(name) for name in properties)
    required = schema_v3.get("required")
    if isinstance(required, list):
        shape_v3["required"] = sorted(str(name) for name in required)
    return content_type, json_example(shape_v3)


def _parse_openapi(document: Mapping[str, object], source: str) -> ParsedSurface:
    paths = _paths_from_openapi(document)
    if paths is None:
        return ParsedSurface()
    endpoints: list[EndpointSpec] = []
    for path, path_item in paths.items():
        if not isinstance(path_item, Mapping):
            continue
        common = path_item.get("parameters")
        common_params = common if isinstance(common, list) else []
        for method, operation in _endpoint_methods(path_item):
            params: list[ParameterSpec] = []
            samples: dict[str, str] = {}
            request_headers: dict[str, str] = {}
            raw_operation_parameters = operation.get("parameters")
            operation_parameters = (
                raw_operation_parameters if isinstance(raw_operation_parameters, list) else []
            )
            for raw_param in [*common_params, *operation_parameters]:
                specs, path_samples = _parameter_from_openapi(document, raw_param, source)
                params.extend(specs)
                samples.update(path_samples)
                for spec in specs:
                    if spec.location == "header" and spec.example is not None:
                        try:
                            value = json.loads(spec.example)
                        except json.JSONDecodeError:
                            value = spec.example
                        request_headers[spec.name] = str(value)

            content_type: str | None = None
            request_body: str | None = None
            raw_body = operation.get("requestBody")
            body = _resolve_ref(document, raw_body)
            if body is not None and isinstance(body.get("content"), Mapping):
                content = body["content"]
                if not isinstance(content, Mapping):
                    content = {}
                choices = [str(key) for key in content]
                content_type = next(
                    (key for key in choices if key == "application/json"),
                    choices[0] if choices else None,
                )
                media = _resolve_ref(document, content.get(content_type)) if content_type else None
                if media is not None:
                    location = (
                        "multipart"
                        if content_type == "multipart/form-data"
                        else "form"
                        if content_type == "application/x-www-form-urlencoded"
                        else "json"
                    )
                    body_params, request_body = _schema_parameters(
                        document,
                        media.get("schema"),
                        location=location,
                        serialization=content_type or location,
                        source=source,
                    )
                    params.extend(body_params)
                    if media.get("example") is not None:
                        request_body = json_example(media["example"]) or request_body
                    examples = media.get("examples")
                    if isinstance(examples, Mapping) and examples:
                        first = _resolve_ref(document, next(iter(examples.values()))) or {}
                        request_body = json_example(first.get("value")) or request_body

            consumes = operation.get("consumes") or document.get("consumes")
            if isinstance(consumes, list) and consumes and content_type is None:
                content_type = str(consumes[0])
            for raw_param in operation_parameters:
                parameter = _resolve_ref(document, raw_param)
                if parameter is None or parameter.get("in") != "body":
                    continue
                location = (
                    "multipart"
                    if content_type == "multipart/form-data"
                    else "form"
                    if content_type == "application/x-www-form-urlencoded"
                    else "json"
                )
                body_params, request_body = _schema_parameters(
                    document,
                    parameter.get("schema"),
                    location=location,
                    serialization=content_type or "application/json",
                    source=source,
                )
                params.extend(body_params)

            deduped = {(p.name, p.location): p for p in params}
            if content_type is not None:
                request_headers.setdefault("Content-Type", content_type)
            response_content_type, response_shape = _response_contract(document, operation)
            endpoints.append(
                EndpointSpec(
                    method=method.upper(),
                    path=str(path),
                    content_type=content_type,
                    state_changing=method.upper() not in _READ_ONLY,
                    parameters=tuple(deduped.values()),
                    sample_path_values=samples,
                    source=source,
                    confidence=0.99,
                    evidence_ref=evidence_ref(source, f"operation:{method.upper()}:{path}"),
                    request_body=request_body,
                    request_headers=tuple(sorted(request_headers.items())),
                    response_content_type=response_content_type,
                    response_shape=response_shape,
                )
            )
    return ParsedSurface(tuple(endpoints))


def _materialize(
    graph: ReachabilityGraph, host_node: str, surface: ParsedSurface
) -> tuple[list[str], list[str], int]:
    endpoint_ids: list[str] = []
    parameter_ids: list[str] = []
    forms = 0
    for spec in surface.endpoints:
        endpoint_node = graph.add_endpoint(
            Endpoint(
                method=spec.method.upper(),
                path=spec.path,
                content_type=spec.content_type,
                state_changing=spec.state_changing,
                protocol=spec.protocol,
                graphql_operation_type=spec.graphql_operation_type,
                source=spec.source,
                confidence=spec.confidence,
                evidence_ref=spec.evidence_ref,
                request_headers=spec.request_headers,
                request_body=spec.request_body,
                response_content_type=spec.response_content_type,
                response_shape=spec.response_shape,
            )
        )
        graph.add_resolves_to(host_node, endpoint_node)
        endpoint_ids.append(endpoint_node)
        if spec.method.upper() not in _READ_ONLY and spec.content_type in {
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "application/json",
        }:
            forms += 1
        for param in spec.parameters:
            parameter_ids.append(
                graph.add_parameter(
                    endpoint_node,
                    Parameter(
                        name=param.name,
                        location=param.location,
                        serialization=param.serialization,
                        required=param.required,
                        example=param.example,
                        source=param.source,
                        confidence=param.confidence,
                        evidence_ref=param.evidence_ref,
                    ),
                )
            )
    return endpoint_ids, parameter_ids, forms


def _in_scope_same_host(firer: RequestFirer, candidate: str, base: str) -> bool:
    try:
        parsed = urlsplit(candidate)
        base_host = (urlsplit(base).hostname or "").lower()
        return (parsed.hostname or "").lower() == base_host and firer.scope.is_in_scope(candidate)
    except Exception:  # noqa: BLE001 — malformed discovery data is ignored
        return False


def _discover_web_surface(
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    host_node: str,
    *,
    identity: str,
) -> ApiDiscoveryResult:
    queue: list[str] = [base_url]
    visited: set[str] = set()
    script_urls: list[str] = []
    endpoint_ids: list[str] = []
    parameter_ids: list[str] = []
    forms = pages = scripts = 0
    while queue and pages < _MAX_PAGES:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        try:
            response = firer.fire(identity, "GET", current, state_changing=False)
        except Exception as exc:  # noqa: BLE001 — one unavailable page must not abort discovery
            _log.debug("surface page skipped: %s", exc)
            continue
        if not 200 <= response.status_code < 300:
            continue
        pages += 1
        content_type = response.headers.get("content-type", "").lower()
        text = response.body[:_MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")
        if "html" not in content_type and not re.search(r"<\s*(html|form|a)\b", text, re.I):
            continue
        parsed = parse_html_surface(text, current)
        safe_endpoints = tuple(
            endpoint
            for endpoint in parsed.endpoints
            if endpoint.source is None or _in_scope_same_host(firer, endpoint.source, base_url)
        )
        parsed = ParsedSurface(safe_endpoints, parsed.links, parsed.scripts)
        ids, pids, found_forms = _materialize(graph, host_node, parsed)
        endpoint_ids.extend(ids)
        parameter_ids.extend(pids)
        forms += found_forms
        for link in parsed.links:
            if _in_scope_same_host(firer, link, base_url) and link not in visited:
                queue.append(link)
        for script in parsed.scripts:
            if _in_scope_same_host(firer, script, base_url) and script not in script_urls:
                script_urls.append(script)
    for script_url in script_urls[:_MAX_SCRIPTS]:
        try:
            response = firer.fire(identity, "GET", script_url, state_changing=False)
        except Exception as exc:  # noqa: BLE001
            _log.debug("script skipped: %s", exc)
            continue
        if not 200 <= response.status_code < 300:
            continue
        parsed = parse_javascript_surface(
            response.body[:_MAX_RESPONSE_BYTES].decode("utf-8", errors="replace"), script_url
        )
        ids, pids, _ = _materialize(graph, host_node, parsed)
        endpoint_ids.extend(ids)
        parameter_ids.extend(pids)
        scripts += 1
    return ApiDiscoveryResult(
        spec_found=False,
        endpoints=tuple(dict.fromkeys(endpoint_ids)),
        parameters=tuple(dict.fromkeys(parameter_ids)),
        pages_crawled=pages,
        scripts_parsed=scripts,
        forms_found=forms,
    )


def discover_api(
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    *,
    identity: str = "api-discovery",
) -> ApiDiscoveryResult:
    """Discover specs, HTML forms/links, JavaScript calls, then bounded guesses."""
    base = base_url.rstrip("/")
    host_addr = host_of(base)
    host_node = graph.add_host(Host(address=host_addr, hostname=host_addr, source=identity))

    for spec_path in _SPEC_PATHS:
        try:
            response = firer.fire(identity, "GET", base + spec_path, state_changing=False)
        except Exception as exc:  # noqa: BLE001
            _log.debug("spec probe skipped: %s", exc)
            continue
        if not 200 <= response.status_code < 300:
            continue
        document = _document(response.body)
        surface = (
            _parse_openapi(document, base + spec_path) if document is not None else ParsedSurface()
        )
        if not surface.endpoints:
            continue
        endpoint_ids, parameter_ids, forms = _materialize(graph, host_node, surface)
        return ApiDiscoveryResult(
            spec_found=True,
            spec_kind="openapi",
            endpoints=tuple(endpoint_ids),
            parameters=tuple(parameter_ids),
            forms_found=forms,
        )

    try:
        from reachagent.graphql.module import GraphQLClient, discover_schema

        for endpoint_path in ("/graphql", "/api/graphql", "/gql"):
            try:
                schema = discover_schema(
                    GraphQLClient(firer, base_url=base, endpoint_path=endpoint_path), identity
                )
            except Exception as exc:  # noqa: BLE001 — absent/disabled endpoint
                _log.debug("GraphQL endpoint skipped: %s", exc)
                continue
            surface = ParsedSurface(
                (
                    EndpointSpec(
                        method="GET",
                        path=endpoint_path,
                        protocol=Protocol.GRAPHQL,
                        graphql_operation_type="query",
                        parameters=tuple(
                            parameter
                            for field in schema.fields
                            for parameter in (
                                ParameterSpec(
                                    name=field.name,
                                    location="graphql",
                                    serialization="application/json",
                                    source=base + endpoint_path,
                                    confidence=0.98,
                                    evidence_ref=evidence_ref(
                                        base + endpoint_path, f"field:{field.name}"
                                    ),
                                ),
                                *tuple(
                                    ParameterSpec(
                                        name=f"{field.name}.{argument}",
                                        location="graphql",
                                        serialization="application/json",
                                        source=base + endpoint_path,
                                        confidence=0.95,
                                        evidence_ref=evidence_ref(
                                            base + endpoint_path,
                                            f"field:{field.name}:argument:{argument}",
                                        ),
                                    )
                                    for argument in field.arguments
                                ),
                            )
                        ),
                        source=base + endpoint_path,
                        confidence=0.98,
                        evidence_ref=evidence_ref(base + endpoint_path, "introspection"),
                    ),
                )
            )
            endpoint_ids, parameter_ids, forms = _materialize(graph, host_node, surface)
            return ApiDiscoveryResult(
                spec_found=True,
                spec_kind="graphql",
                endpoints=tuple(endpoint_ids),
                parameters=tuple(parameter_ids),
                forms_found=forms,
            )
    except Exception as exc:  # noqa: BLE001
        _log.debug("GraphQL discovery unavailable: %s", exc)

    surface_result = _discover_web_surface(graph, firer, base, host_node, identity=identity)
    if surface_result.endpoints:
        return surface_result

    endpoints: list[str] = []
    probes = 0
    for prefix in _FALLBACK_PREFIXES:
        for resource in _FALLBACK_RESOURCES:
            path = f"/{prefix}/{resource}".replace("//", "/") if prefix else f"/{resource}"
            probes += 1
            try:
                response = firer.fire(identity, "GET", base + path, state_changing=False)
            except Exception as exc:  # noqa: BLE001
                _log.debug("fallback probe skipped: %s", exc)
                continue
            if 200 <= response.status_code < 300:
                endpoint = graph.add_endpoint(
                    Endpoint(
                        method="GET",
                        path=path,
                        source="bounded-fallback",
                        confidence=0.2,
                        evidence_ref=evidence_ref(base, f"fallback:{path}"),
                    )
                )
                graph.add_resolves_to(host_node, endpoint)
                endpoints.append(endpoint)
    return ApiDiscoveryResult(spec_found=False, endpoints=tuple(endpoints), fallback_probes=probes)


def _host_of(target: str) -> str:
    """Canonical host helper retained for callers that imported this seam."""
    return host_of(target)


__all__ = ["ApiDiscoveryResult", "discover_api"]
