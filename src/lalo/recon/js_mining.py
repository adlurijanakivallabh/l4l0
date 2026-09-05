"""JS / source-map endpoint mining — pure, zero-I/O, operates on already-captured content.

Confirmed original for this phase against the comparison docs: bundled-JS
route-table mining is a common real-world recon technique but none of the
five references builds it as a distinct mechanism worth citing. Kept
deliberately as candidate-signal generation, not a detector — a matched
string is a lead for the agent (or a later runner) to corroborate via a real
request, never something merge_facts treats as confirmed on its own.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

_PATH_LITERAL = re.compile(r"""["'](/[A-Za-z0-9_\-./{}]{1,200})["']""")
_SOURCEMAP_COMMENT = re.compile(r"//#\s*sourceMappingURL=(\S+)")

_STATIC_EXTENSIONS: frozenset[str] = frozenset(
    {".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico", ".map"}
)


def _looks_like_a_path(path: str) -> bool:
    if path in ("/", "//"):
        return False
    lowered = path.lower()
    return not any(lowered.endswith(ext) for ext in _STATIC_EXTENSIONS)


def mine_js_for_paths(js_source: str) -> list[str]:
    """Extract path-shaped string literals (``"/api/users/{id}"``-style) from JS source.

    A heuristic, not a parser: bundled JS routinely embeds its own route table
    as plain string literals, which is genuinely useful signal even though
    this will also pick up some non-endpoint paths — callers treat the result
    as a candidate list to corroborate, never a confirmed fact by itself.
    """
    seen: list[str] = []
    for match in _PATH_LITERAL.finditer(js_source):
        path = match.group(1)
        if path not in seen and _looks_like_a_path(path):
            seen.append(path)
    return seen


def find_sourcemap_url(js_source: str) -> str | None:
    match = _SOURCEMAP_COMMENT.search(js_source)
    return match.group(1) if match else None


def mine_sourcemap_sources(sourcemap: dict[str, object]) -> list[str]:
    """The ``sources`` array of a parsed source-map JSON document, if present."""
    sources = sourcemap.get("sources")
    if not isinstance(sources, list):
        return []
    return [s for s in sources if isinstance(s, str)]


def endpoint_urls_from_paths(base_url: str, paths: list[str]) -> list[str]:
    return [urljoin(base_url, path) for path in paths]
