"""whatweb recon wrapper — CMS/framework fingerprint as Host attributes (§9 recon tier).

whatweb's ``--log-json`` emits one JSON object per scanned target with a
``plugins`` map (the detected stack: CMS, framework, server, versions). Per §6/§9
(v1.8) a detected technology/version is an **attribute** on the ``Host`` (and,
where the fingerprint is per-URL, reused on the ``Endpoint``) — never a
``Technology`` node (§6 forbids per-class node sprawl). Facts only: a fingerprint
is a fact ("this is WordPress 6.4"), not a vulnerability claim, so nothing here is
a candidate or a ``Finding``.

whatweb JSON is either a single object or a JSON array of them, tolerated both
ways. A version, when a plugin reports one, is joined into ``detected_version``.
"""

from __future__ import annotations

import json
from typing import Any

from reachagent.graph.nodes import Endpoint, Host
from reachagent.recon.tools.base import ReconToolRunner

# Plugins that are HTTP/transport noise rather than a stack fingerprint — excluded
# from the technology attribute so it reflects the CMS/framework, not every header.
_NON_TECH_PLUGINS = frozenset(
    {
        "HTTPServer",
        "IP",
        "Country",
        "Title",
        "RedirectLocation",
        "Cookies",
        "HTML5",
        "UncommonHeaders",
    }
)


class WhatWebRunner(ReconToolRunner):
    """Emit ``Host`` technology/version attributes from whatweb JSON (§9). Facts only."""

    name = "whatweb"
    binary = "whatweb"

    def command(self, target: str) -> list[str]:
        """``whatweb --log-json=- <target>`` — JSON fingerprint to stdout.

        Target is the final distinct list element (``shell=False`` in the base) —
        never interpolated into a shell string.
        """
        return ["whatweb", "--log-json=-", target]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse whatweb JSON into ``Host`` tech attributes + a ``resolves_to`` endpoint."""
        written: list[str] = []
        for record in _iter_records(raw_output):
            uri = str(record.get("target", target))
            host_addr = _host_of(uri)
            technology, version = _stack_from_plugins(record.get("plugins", {}))
            host_node = self.graph.add_host(
                Host(
                    address=host_addr,
                    hostname=host_addr,
                    source=self.name,
                    technology=technology,
                    detected_version=version,
                )
            )
            written.append(host_node)
            # Reuse the per-endpoint tech attribute where whatweb fingerprinted a
            # specific path (not the bare host root).
            path = _path_of(uri)
            if path and path != "/":
                endpoint_node = self.graph.add_endpoint(
                    Endpoint(
                        method="GET", path=path, technology=technology, detected_version=version
                    )
                )
                self.graph.add_resolves_to(host_node, endpoint_node)
                written.append(endpoint_node)
        return tuple(written)


def _iter_records(raw_output: str) -> list[dict[str, Any]]:
    """whatweb JSON as a list of records — tolerating a single object or an array.

    whatweb's ``--log-json`` may emit a bare object, a JSON array, or (older
    builds) one JSON object per line. All three are normalised to a record list; an
    unparseable chunk is skipped rather than crashing the parse (the base audits an
    outright failure as ``errored``).
    """
    text = raw_output.strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        # Fall back to JSON-lines: one object per line, skipping unparseable lines.
        records: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                records.append(obj)
        return records
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return [r for r in parsed if isinstance(r, dict)]
    return []


def _stack_from_plugins(plugins: Any) -> tuple[str | None, str | None]:  # noqa: ANN401 — whatweb JSON shape
    """Reduce whatweb's ``plugins`` map to a (technology, version) attribute pair.

    The technology is the comma-joined set of stack plugin names (CMS/framework/
    server), excluding transport noise (``_NON_TECH_PLUGINS``). The version is the
    first ``version`` any plugin reports. Both are attributes on the ``Host`` — no
    ``Technology`` node is created (§6). Empty/absent → ``(None, None)``.
    """
    if not isinstance(plugins, dict):
        return None, None
    names: list[str] = []
    version: str | None = None
    for plugin_name, detail in plugins.items():
        if plugin_name in _NON_TECH_PLUGINS:
            continue
        names.append(plugin_name)
        if version is None and isinstance(detail, dict):
            ver_list = detail.get("version")
            if isinstance(ver_list, list) and ver_list:
                version = str(ver_list[0])
    technology = ", ".join(sorted(names)) or None
    return technology, version


def _host_of(uri: str) -> str:
    """The bare host of a whatweb target URI (strip scheme + path)."""
    stripped = uri.split("://", 1)[-1]
    return stripped.split("/", 1)[0]


def _path_of(uri: str) -> str:
    """The path component of a whatweb target URI (``/`` when none)."""
    stripped = uri.split("://", 1)[-1]
    slash = stripped.find("/")
    return stripped[slash:] if slash != -1 else "/"
