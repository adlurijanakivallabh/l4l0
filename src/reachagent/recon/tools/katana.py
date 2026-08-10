"""katana recon wrapper — crawled URLs as Host/Endpoint facts (§9 recon tier).

katana crawls the target and emits discovered URLs (one per line in ``-jc`` mode).
Per §6/§9 (v1.8) each discovered URL is a ``Host`` + ``Endpoint`` fact —
no new node type, same shape as gobuster's path→Endpoint. Facts only.
"""

from __future__ import annotations

import urllib.parse

from reachagent.graph.nodes import Endpoint, Host
from reachagent.recon.tools.base import ReconToolRunner


def _host_of(url: str) -> str:
    stripped = url.split("://", 1)[-1]
    return stripped.split("/", 1)[0].split(":", 1)[0]


def _path_of(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path
    except Exception:  # noqa: BLE001
        # Fallback: raw split
        after_host = url.split("://", 1)[-1]
        slash = after_host.find("/")
        return after_host[slash:] if slash != -1 else "/"


class KatanaRunner(ReconToolRunner):
    """Emit Host/Endpoint + resolves_to from katana crawl output (§9). Facts only."""

    name = "katana"
    binary = "katana"

    def command(self, target: str) -> list[str]:
        """katana -u <target> -jc -silent [+ -jsl -aff -d depth -ct timeout]."""
        import os

        argv: list[str] = ["katana", "-u", target, "-jc", "-silent"]
        # JS parsing behind env (default on): -jsl -aff
        jsl = os.environ.get("REACHAGENT_KATANA_JS", "1")
        if jsl not in ("0", "false", "False"):
            argv += ["-jsl", "-aff"]
        depth = os.environ.get("REACHAGENT_KATANA_DEPTH", "3")
        if depth.isdigit():
            argv += ["-d", depth]
        ct = os.environ.get("REACHAGENT_KATANA_TIMEOUT")
        if ct and ct.isdigit():
            argv += ["-ct", ct]
        return argv

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse katana URL lines into Host + Endpoint + resolves_to facts."""
        written: list[str] = []
        seen_endpoints: set[str] = set()
        for line in raw_output.splitlines():
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            # katana may emit bare paths or full URLs — normalize
            if url.startswith("/"):
                host_addr = _host_of(target)
                path = url
            elif "://" in url:
                host_addr = _host_of(url)
                path = _path_of(url)
            else:
                # Heuristic: if line looks like URL without scheme, treat as path/host
                if "." in url and "/" in url:
                    host_addr = _host_of(url)
                    path = _path_of(url if "://" in url else f"http://{url}")
                else:
                    host_addr = _host_of(target)
                    path = url if url.startswith("/") else f"/{url}"
            host_node = self.graph.add_host(Host(address=host_addr, source=self.name))
            if host_node not in written:
                written.append(host_node)
            endpoint_node = self.graph.add_endpoint(Endpoint(method="GET", path=path))
            if endpoint_node not in seen_endpoints:
                self.graph.add_resolves_to(host_node, endpoint_node)
                written.append(endpoint_node)
                seen_endpoints.add(endpoint_node)
            else:
                # Still ensure edge even if endpoint already seen once
                self.graph.add_resolves_to(host_node, endpoint_node)
        return tuple(written)
