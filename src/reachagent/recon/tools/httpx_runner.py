"""httpx recon wrapper — probed hosts as Host facts with tech attributes (§9).

httpx in JSON mode emits one JSON object per line with url, status_code, title,
tech/webserver fields. Per §6/§9 (v1.8) tech/version is an **attribute** on Host
(and Endpoint where path-specific) — never a Technology node. Facts only.
"""

from __future__ import annotations

import json

from reachagent.graph.nodes import Endpoint, Host
from reachagent.recon.tools.base import ReconToolRunner, _recon_host_of, _recon_path_of

_host_of = _recon_host_of  # ponytail: deduped to base helper


_path_of = _recon_path_of  # ponytail: deduped to base helper


class HttpxRunner(ReconToolRunner):
    """Emit Host tech attributes + Endpoints from httpx JSON lines (§9). Facts only."""

    name = "httpx"
    binary = "httpx"

    def command(self, target: str) -> list[str]:
        """httpx -u <target> -json [+ -threads/-timeout/-rate-limit]."""
        import os

        argv: list[str] = ["httpx", "-u", target, "-json"]
        threads = os.environ.get("REACHAGENT_HTTPX_THREADS")
        if threads and threads.isdigit():
            argv += ["-threads", threads]
        timeout = os.environ.get("REACHAGENT_HTTPX_TIMEOUT")
        if timeout and timeout.isdigit():
            argv += ["-timeout", timeout]
        rate = os.environ.get("REACHAGENT_HTTPX_RATE")
        if rate and rate.isdigit():
            argv += ["-rate-limit", rate]
        return argv

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse httpx JSON lines into Host + Endpoint tech facts."""
        written: list[str] = []
        seen_endpoints: set[str] = set()
        for line in raw_output.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            url = str(obj.get("url", target))
            host_addr = _host_of(url)
            tech = obj.get("tech") or obj.get("webserver") or obj.get("server")
            if isinstance(tech, list):
                technology: str | None = ", ".join(str(t) for t in tech) or None
            elif isinstance(tech, str):
                technology = tech
            else:
                technology = None
            version = obj.get("version")
            if isinstance(version, list) and version:
                version = str(version[0])
            elif not isinstance(version, str):
                version = None
            # Per-URL tech may be list of dicts with name/version
            if technology is None and isinstance(obj.get("tech"), list):
                names: list[str] = []
                for item in obj.get("tech", []):
                    if isinstance(item, dict) and item.get("name"):
                        names.append(str(item["name"]))
                        if version is None and item.get("version"):
                            v = item["version"]
                            version = str(v[0] if isinstance(v, list) and v else v)
                technology = ", ".join(names) or None
            host_node = self.graph.add_host(
                Host(
                    address=host_addr,
                    hostname=host_addr,
                    source=self.name,
                    technology=technology,
                    detected_version=version,
                )
            )
            if host_node not in written:
                written.append(host_node)
            path = _path_of(url)
            if path and path != "/":
                endpoint_node = self.graph.add_endpoint(
                    Endpoint(
                        method="GET",
                        path=path,
                        technology=technology,
                        detected_version=version,
                    )
                )
                if endpoint_node not in seen_endpoints:
                    self.graph.add_resolves_to(host_node, endpoint_node)
                    written.append(endpoint_node)
                    seen_endpoints.add(endpoint_node)
                else:
                    self.graph.add_resolves_to(host_node, endpoint_node)
        return tuple(written)
