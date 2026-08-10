"""feroxbuster recon wrapper — discovered URLs as Endpoint facts (§9 recon tier).

feroxbuster in JSON mode emits one JSON object per line with url + status fields.
Per §6/§9 each discovered path is an Endpoint + resolves_to edge. Mirror
gobuster.py. Facts only.
"""

from __future__ import annotations

import json

from reachagent.graph.nodes import Endpoint, Host
from reachagent.recon.tools.base import ReconToolRunner


def _host_of(target: str) -> str:
    stripped = target.split("://", 1)[-1]
    return stripped.split("/", 1)[0].split(":", 1)[0]


def _path_of(url: str) -> str:
    after_scheme = url.split("://", 1)[-1] if "://" in url else url
    slash = after_scheme.find("/")
    if slash == -1:
        return "/"
    path = after_scheme[slash:].split("#", 1)[0]
    return path or "/"


class FeroxbusterRunner(ReconToolRunner):
    """Emit Endpoint per feroxbuster-discovered URL + resolves_to edge (§9). Facts only."""

    name = "feroxbuster"
    binary = "feroxbuster"

    def command(self, target: str) -> list[str]:
        """feroxbuster --url <target> --silent --json -o <file> — JSON to file."""
        import os
        import tempfile

        fd, path = tempfile.mkstemp(suffix=".json", prefix="ferox-")  # noqa: S108 — mkstemp safe temp
        os.close(fd)
        return ["feroxbuster", "--url", target, "--silent", "--json", "-o", path]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse feroxbuster JSON lines into Endpoint nodes + resolves_to edges."""
        written: list[str] = []
        host_addr = _host_of(target)
        host_node = self.graph.add_host(Host(address=host_addr, source=self.name))
        written.append(host_node)
        seen_paths: set[str] = set()
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
            url = str(obj.get("url", ""))
            if not url:
                continue
            path = _path_of(url)
            if path in seen_paths:
                continue
            seen_paths.add(path)
            endpoint_node = self.graph.add_endpoint(Endpoint(method="GET", path=path))
            self.graph.add_resolves_to(host_node, endpoint_node)
            written.append(endpoint_node)
        return tuple(written)
