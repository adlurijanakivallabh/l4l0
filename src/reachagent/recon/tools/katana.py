"""katana recon wrapper — crawled URLs as Host/Endpoint facts (§9 recon tier).

katana crawls the target and emits discovered URLs (one per line in ``-jc`` mode).
Per §6/§9 (v1.8) each discovered URL is a ``Host`` + ``Endpoint`` fact —
no new node type, same shape as gobuster's path→Endpoint. Facts only.
"""

from __future__ import annotations

from reachagent.graph.nodes import Endpoint, Host
from reachagent.recon.tools.base import ReconToolRunner, _recon_host_of, _recon_path_of

_host_of = _recon_host_of  # ponytail: deduped to base helper


_path_of = _recon_path_of  # ponytail: deduped to base helper


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
        for env_name, flag in (
            ("REACHAGENT_KATANA_CONCURRENCY", "-c"),
            ("REACHAGENT_KATANA_PARALLELISM", "-p"),
            ("REACHAGENT_KATANA_RATE", "-rl"),
            ("REACHAGENT_KATANA_MAX_PAGES", "-mdp"),
            ("REACHAGENT_KATANA_TIMEOUT_PER_REQUEST", "-timeout"),
        ):
            value = os.environ.get(env_name)
            if value and value.isdigit():
                argv += [flag, value]
        field_scope = os.environ.get("REACHAGENT_KATANA_FIELD_SCOPE")
        if field_scope in {"dn", "rdn", "fqdn"}:
            argv += ["-fs", field_scope]
        extensions = os.environ.get("REACHAGENT_KATANA_EXTENSION_FILTER")
        if extensions:
            argv += ["-ef", extensions]
        if os.environ.get("REACHAGENT_KATANA_HEADLESS", "").lower() in {
            "1",
            "true",
            "yes",
        }:
            argv += ["-hl", "-xhr"]
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
