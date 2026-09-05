"""OpenAPI/GraphQL spec ingestion — fired through the real scope-checked firer.

The spec's own claimed base URL (OpenAPI's ``servers[].url``) is untrusted
input, never an automatic scope grant: every endpoint fact this module
produces is anchored to the host the spec was ACTUALLY fetched from, never
to anything the document itself claims — a spec discovery result cannot
self-grant scope, and even a legitimately-fetched-in-engagement spec is
still passed back through the ordinary :func:`~lalo.recon.facts.merge_facts`
gate before it can land on the graph. Confirmed against every reference's
opposite failure mode: none enforces scope at the request layer at all
(Phase 3's finding), so none has a "spec self-grants scope" gap to close in
the first place — this is genuinely original hardening, not an adopted idea.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin

from ..execution.firer import HttpFirer
from .facts import FactKind, ReconFact


def fetch_openapi_facts(
    firer: HttpFirer, spec_url: str, *, source: str = "openapi"
) -> list[ReconFact]:
    """Fire ``spec_url``, parse an OpenAPI document, and return one fact per path.

    Endpoint URLs are built by joining each declared path against the URL the
    spec was actually fetched from — the document's own ``servers`` field is
    never consulted for this.
    """
    result = firer.fire("GET", spec_url)
    if not result.fired or result.status is None or result.status >= 400:
        return []
    try:
        spec = json.loads(result.body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []

    facts: list[ReconFact] = []
    for path, methods in paths.items():
        if not isinstance(path, str):
            continue
        endpoint_url = urljoin(spec_url, path)
        method_names = sorted(m.upper() for m in methods) if isinstance(methods, dict) else []
        facts.append(
            ReconFact(
                kind=FactKind.ENDPOINT,
                url=endpoint_url,
                source=source,
                extra={"methods": method_names},
            )
        )
    return facts


def parse_graphql_introspection(
    introspection: dict[str, object], endpoint_url: str, *, source: str = "graphql"
) -> list[ReconFact]:
    """One fact for the GraphQL endpoint itself, annotated with the schema's type names.

    GraphQL exposes a single URL for every operation, so there is nothing to
    enumerate into separate endpoint facts the way OpenAPI's per-path model
    allows — the useful signal is which types/fields exist behind that URL.
    """
    data = introspection.get("data")
    schema = data.get("__schema") if isinstance(data, dict) else None
    types = schema.get("types") if isinstance(schema, dict) else None
    type_names = (
        [t["name"] for t in types if isinstance(t, dict) and isinstance(t.get("name"), str)]
        if isinstance(types, list)
        else []
    )
    return [
        ReconFact(
            kind=FactKind.ENDPOINT,
            url=endpoint_url,
            source=source,
            extra={"graphql_types": type_names},
        )
    ]
