"""ffuf recon wrapper — discovered paths as Endpoint facts (§9 recon tier).

ffuf in JSON mode emits {"results":[{"url":"...","status":200},...]}. Per §6/§9
each discovered path is an Endpoint + resolves_to edge. Mirror gobuster.py
directly — same path+status shape. Facts only.
"""

from __future__ import annotations

import json
import os

from reachagent.graph.nodes import Endpoint, Host
from reachagent.recon.tools.base import ReconToolRunner


def _host_of(target: str) -> str:
    stripped = target.split("://", 1)[-1]
    return stripped.split("/", 1)[0].split(":", 1)[0]


def _path_of(url: str) -> str:
    # Extract path + query from URL
    after_scheme = url.split("://", 1)[-1] if "://" in url else url
    slash = after_scheme.find("/")
    if slash == -1:
        return "/"
    path = after_scheme[slash:]
    # Strip fragment
    path = path.split("#", 1)[0]
    return path or "/"


class FfufRunner(ReconToolRunner):
    """Emit Endpoint per ffuf-discovered path + resolves_to edge (§9). Facts only."""

    name = "ffuf"
    binary = "ffuf"

    def command(self, target: str) -> list[str]:
        """ffuf -u <target>/FUZZ -w <wordlist> -mc 200,204,301,302 -o <file> -of json."""
        import os as _os2
        import tempfile

        wordlist = os.environ.get(
            "REACHAGENT_FFUF_WORDLIST", "/usr/share/wordlists/dirb/common.txt"
        )
        fd, path = tempfile.mkstemp(suffix=".json", prefix="ffuf-")  # noqa: S108 — mkstemp safe temp
        _os2.close(fd)
        return [
            "ffuf",
            "-u",
            target.rstrip("/") + "/FUZZ",
            "-w",
            wordlist,
            "-mc",
            "200,204,301,302",
            "-o",
            path,
            "-of",
            "json",
        ]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse ffuf JSON results into Endpoint nodes + resolves_to edges."""
        written: list[str] = []
        host_addr = _host_of(target)
        host_node = self.graph.add_host(Host(address=host_addr, source=self.name))
        written.append(host_node)
        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError:
            return tuple(written)
        results = parsed.get("results", []) if isinstance(parsed, dict) else []
        if not isinstance(results, list):
            return tuple(written)
        seen_paths: set[str] = set()
        for item in results:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", ""))
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
