"""ParamSpider recon wrapper — query-param discovery as Parameter facts (§9).

Tier decision: recon-tier — parameter discovery is a fact, not a claim; see §9.
A discovered query param name on a URL is a fact (Endpoint→Parameter), not a
vulnerability claim. Mirrors gobuster/katana. Facts only.
"""

from __future__ import annotations

import urllib.parse

from reachagent.graph.nodes import Endpoint, Host, Parameter
from reachagent.recon.tools.base import ReconToolRunner


def _host_of(target: str) -> str:
    stripped = target.split("://", 1)[-1]
    return stripped.split("/", 1)[0].split(":", 1)[0].split(":", 1)[0]


def _path_of(url: str) -> str:
    after = url.split("://", 1)[-1] if "://" in url else url
    slash = after.find("/")
    if slash == -1:
        return "/"
    path = after[slash:].split("?", 1)[0].split("#", 1)[0]
    return path or "/"


class ParamSpiderRunner(ReconToolRunner):
    """Emit Parameter per ParamSpider-discovered query param (§9). Facts only."""

    name = "paramspider"
    binary = "paramspider"

    def command(self, target: str) -> list[str]:
        """paramspider --domain <host> — enumerate URLs with query params."""
        host = _host_of(target)
        return ["paramspider", "--domain", host]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse ParamSpider URL lines into Parameter nodes.

        Each URL like https://host/path?foo=1&bar=2 → two Parameters (foo, bar)
        on Endpoint GET path. Deduped. Facts only.
        """
        written: list[str] = []
        host_addr = _host_of(target)
        host_node = self.graph.add_host(Host(address=host_addr, source=self.name))
        written.append(host_node)
        # endpoint cache to avoid duplicate Endpoint nodes
        endpoint_cache: dict[str, str] = {}
        seen_params: set[tuple[str, str]] = set()  # (endpoint_node, param_name)

        for line in raw_output.splitlines():
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            # ParamSpider emits full URLs; skip lines without query
            if "?" not in url:
                continue
            # Parse URL; skip if not parseable or no host
            try:
                parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
            except Exception:  # noqa: BLE001, S112 — skip unparseable URL line
                continue
            query = parsed.query
            if not query:
                continue
            path = parsed.path or "/"
            # Normalize endpoint by path only (ignore query values)
            ep_key = path
            endpoint_node = endpoint_cache.get(ep_key)
            if endpoint_node is None:
                endpoint_node = self.graph.add_endpoint(Endpoint(method="GET", path=path))
                self.graph.add_resolves_to(host_node, endpoint_node)
                endpoint_cache[ep_key] = endpoint_node
                written.append(endpoint_node)
            # Extract param names from query string
            for kv in query.split("&"):
                name = kv.split("=", 1)[0].strip()
                if not name or " " in name or len(name) > 64:
                    continue
                key = (endpoint_node, name)
                if key in seen_params:
                    continue
                seen_params.add(key)
                param_node = self.graph.add_parameter(
                    endpoint_node, Parameter(name=name, location="query")
                )
                written.append(param_node)
        return tuple(written)
