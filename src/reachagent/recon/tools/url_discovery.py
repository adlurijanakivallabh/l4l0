"""waybackurls/gau recon wrappers — archive URL discovery as Endpoint facts (§9).

Both tools emit one URL per line from web archives / common crawl / URLScan.
Each URL's path becomes an Endpoint fact attached to the URL's Host. They
share the identical line-per-URL parser and differ only in name/binary/command.
Facts only — never a candidate, Finding, or can_call.
"""

from __future__ import annotations

from reachagent.graph.nodes import Endpoint, Host
from reachagent.recon.tools._net import host_of as _recon_host_of
from reachagent.recon.tools._net import path_of as _recon_path_of
from reachagent.recon.tools.base import ReconToolRunner

_host_of = _recon_host_of
_path_of = _recon_path_of


class _LineUrlRunner(ReconToolRunner):
    """Shared parser: one URL per non-blank line -> Host + Endpoint facts."""

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        written: list[str] = []
        seen_endpoints: set[str] = set()
        host_cache: dict[str, str] = {}
        for line in raw_output.splitlines():
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            if "://" not in url and "." not in url:
                continue
            addr = _host_of(url)
            if not addr:
                continue
            host_node = host_cache.get(addr)
            if host_node is None:
                host_node = self.graph.add_host(Host(address=addr, hostname=addr, source=self.name))
                host_cache[addr] = host_node
                written.append(host_node)
            path = _path_of(url)
            if path == "/" and "?" not in url:
                continue
            if path in seen_endpoints:
                continue
            seen_endpoints.add(path)
            endpoint_node = self.graph.add_endpoint(Endpoint(method="GET", path=path))
            self.graph.add_resolves_to(host_node, endpoint_node)
            written.append(endpoint_node)
        return tuple(written)


class WaybackUrlsRunner(_LineUrlRunner):
    """Emit Host/Endpoint facts from waybackurls archive URLs (§9). Facts only."""

    name = "waybackurls"
    binary = "waybackurls"

    def command(self, target: str) -> list[str]:
        """waybackurls <host> — reads target from stdin conventionally."""
        return ["waybackurls", _host_of(target)]


class GauRunner(_LineUrlRunner):
    """Emit Host/Endpoint facts from gau multi-source URLs (§9). Facts only."""

    name = "gau"
    binary = "gau"

    def command(self, target: str) -> list[str]:
        """gau --subs <host> — includes known subdomains."""
        return ["gau", "--subs", _host_of(target)]
