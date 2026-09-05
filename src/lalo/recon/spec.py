"""OpenAPI/Swagger spec ingestion with host-side scope validation.

The host (not the LLM) extracts endpoints and validates each candidate base URL
against the engagement before it becomes a target — a spec cannot self-grant scope.
"""

from __future__ import annotations

from urllib.parse import urljoin

from ..execution.scope import ScopeGuard
from .runners import ReconFact

_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def _base_urls(spec: dict[str, object]) -> list[str]:
    bases: list[str] = []
    servers = spec.get("servers")
    if isinstance(servers, list):
        for server in servers:
            if isinstance(server, dict) and isinstance(server.get("url"), str):
                bases.append(server["url"])
    if not bases:
        host = spec.get("host")
        base_path = spec.get("basePath", "")
        schemes = spec.get("schemes")
        scheme = schemes[0] if isinstance(schemes, list) and schemes else "https"
        if isinstance(host, str):
            bases.append(f"{scheme}://{host}{base_path if isinstance(base_path, str) else ''}")
    return bases


def ingest_openapi(
    spec: dict[str, object], *, scope: ScopeGuard | None = None
) -> list[ReconFact]:
    """Return endpoint facts from an OpenAPI/Swagger spec, scope-validated."""
    bases = _base_urls(spec)
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    facts: list[ReconFact] = []
    seen: set[str] = set()
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        methods = [m.upper() for m in item if m.lower() in _METHODS] or ["GET"]
        for base in bases or [""]:
            url = urljoin(base.rstrip("/") + "/", str(path).lstrip("/")) if base else str(path)
            if scope is not None and not scope.check(url).allowed:
                continue  # a spec cannot self-grant out-of-engagement scope
            for method in methods:
                key = f"{method} {url}"
                if key in seen:
                    continue
                seen.add(key)
                facts.append(ReconFact("endpoint", url, {"method": method, "source": "openapi"}))
    return facts
