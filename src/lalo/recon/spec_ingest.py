"""OpenAPI/GraphQL/Postman spec ingestion — fired through the real scope-checked firer.

The spec's own claimed base URL (OpenAPI's ``servers[].url``) is untrusted
input, never an automatic scope grant: every endpoint fact this module
produces is anchored to the host the spec was ACTUALLY fetched from, never
to anything the document itself claims — a spec discovery result cannot
self-grant scope, and even a legitimately-fetched-in-engagement spec is
still passed back through the ordinary :func:`~lalo.recon.facts.merge_facts`
gate before it can land on the graph. A reference recon utility, found on a
retroactive audit pass (its own module docstring states the identical
principle almost verbatim — "which base URLs it authorizes as in-scope hosts
(scope cannot be self-granted by the agent)"), already does this at the host
layer: it parses an OpenAPI/Swagger/Postman spec's declared base URLs into a
prompt-text allowlist the agent is told is authorized, but does not re-check
per request afterward. L4L0's version is mechanically stronger, not merely
different: every fact still passes through the same code-level ScopeGuard
check every other request does, on every use, not just once at discovery
time into advisory prompt text.

Phase 9, another studied reference agent's own pass: re-reading that same
reference's real API-spec-parsing module in full (not just the
module-docstring principle it already contributed) surfaced a genuine gap
this module never closed — it also parses Postman
collections (an extremely common real-world API-spec format), walking nested
folders with a depth cap against pathological nesting, extracting only each
request's own concrete URL. :func:`parse_postman_collection` adds the same
capability here. Deliberately NOT adopted: Postman collection-variable
resolution (``{{baseUrl}}``-style templating) — building a template-
resolution engine to guess what an unresolved variable might mean would risk
fabricating an endpoint that doesn't exist; a request whose URL still
contains an unresolved ``{{...}}`` placeholder after this parse is skipped
outright, never guessed at.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin

from ..execution.firer import HttpFirer
from .facts import FactKind, ReconFact

# OpenAPI 3.x / Swagger 2.0 Path Item Object operation keys. A path item also
# legitimately carries non-operation sibling fields (summary, description,
# parameters, servers, $ref, ...) per spec — without this filter those get
# recorded as bogus "methods" on the resulting fact.
_OPENAPI_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})

# Matches a reference recon utility's own choice: a real-world Postman
# collection is a user-authored tree with no depth guarantee; without a cap,
# a pathological (or adversarially crafted) collection could recurse
# indefinitely.
_POSTMAN_MAX_FOLDER_DEPTH = 25


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
        method_names = (
            sorted(m.upper() for m in methods if m.lower() in _OPENAPI_METHODS)
            if isinstance(methods, dict)
            else []
        )
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


def _postman_request_url(request: Any) -> str | None:
    """Extract the literal URL from one Postman request object, or None.

    Postman allows a request's ``url`` to be either a plain string or a
    structured object with a ``raw`` field — both are real, observed shapes.
    A URL still containing an unresolved ``{{variable}}`` placeholder is
    never returned: guessing what it might resolve to risks fabricating an
    endpoint that was never actually declared.
    """
    if not isinstance(request, dict):
        return None
    url = request.get("url")
    if isinstance(url, str):
        raw = url
    elif isinstance(url, dict) and isinstance(url.get("raw"), str):
        raw = url["raw"]
    else:
        return None
    raw = raw.strip()
    if not raw or "{{" in raw:
        return None
    return raw


def _walk_postman_items(items: Any, *, depth: int) -> list[ReconFact]:
    if depth > _POSTMAN_MAX_FOLDER_DEPTH or not isinstance(items, list):
        return []
    facts: list[ReconFact] = []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        nested = entry.get("item")
        if isinstance(nested, list):
            facts.extend(_walk_postman_items(nested, depth=depth + 1))
            continue
        request = entry.get("request")
        url = _postman_request_url(request)
        if url is None:
            continue
        method = ""
        if isinstance(request, dict) and isinstance(request.get("method"), str):
            method = request["method"].upper()
        facts.append(
            ReconFact(
                kind=FactKind.ENDPOINT,
                url=url,
                source="postman",
                extra={"methods": [method] if method else []},
            )
        )
    return facts


def parse_postman_collection(collection: dict[str, object]) -> list[ReconFact]:
    """One fact per request in a Postman collection, recursively across nested folders.

    ``collection`` is the raw collection JSON (v2.0/v2.1 schema: a top-level
    ``item`` array of request and/or folder entries, folders nesting their
    own ``item`` array). Folder nesting is capped at
    :data:`_POSTMAN_MAX_FOLDER_DEPTH` against a pathological or adversarially
    deep collection. Requests whose URL is not a concrete string — still
    templated with an unresolved ``{{variable}}``, or missing entirely — are
    silently skipped, never guessed at.
    """
    items = collection.get("item") if isinstance(collection, dict) else None
    return _walk_postman_items(items, depth=0)
