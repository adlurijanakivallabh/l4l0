"""dirb recon wrapper — discovered paths as Endpoint facts (§9 recon tier).

dirb text output emits lines like "+ http://host/path (CODE:200|SIZE:...)" — one
discovered path per matching line. Per §6/§9 each is an Endpoint + resolves_to
edge. Mirror gobuster.py. Facts only.
"""

from __future__ import annotations

import re

from reachagent.graph.nodes import Endpoint, Host
from reachagent.recon.tools._wordlist import preferred_wordlist
from reachagent.recon.tools.base import ReconToolRunner

_RESULT = re.compile(r"^\+\s+https?://[^/]+(?P<path>/\S*)\s+\(CODE:(?P<code>\d+)")
_ALT_RESULT = re.compile(r"^\+\s+(?P<url>https?://\S+)\s+\(CODE:(?P<code>\d+)")


def _host_of(target: str) -> str:
    stripped = target.split("://", 1)[-1]
    return stripped.split("/", 1)[0].split(":", 1)[0]


def _path_of_url(url: str) -> str:
    after_scheme = url.split("://", 1)[-1] if "://" in url else url
    slash = after_scheme.find("/")
    if slash == -1:
        return "/"
    path = after_scheme[slash:].split("#", 1)[0]
    return path or "/"


class DirbRunner(ReconToolRunner):
    """Emit Endpoint per dirb-discovered path + resolves_to edge (§9). Facts only."""

    name = "dirb"
    binary = "dirb"

    def command(self, target: str) -> list[str]:
        """dirb <target> <wordlist> -S — silent, results to stdout."""
        wordlist = preferred_wordlist("REACHAGENT_DIRB_WORDLIST")
        return ["dirb", target, wordlist, "-S"]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse dirb + http:// lines into Endpoint nodes + resolves_to edges."""
        written: list[str] = []
        host_addr = _host_of(target)
        host_node = self.graph.add_host(Host(address=host_addr, source=self.name))
        written.append(host_node)
        seen_paths: set[str] = set()
        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            match = _RESULT.match(stripped)
            if match is None:
                match = _ALT_RESULT.match(stripped)
            if match is None:
                continue
            path = match.group("path") if "path" in match.groupdict() else None
            if path is None:
                url = match.group("url")
                path = _path_of_url(url)
            if path in seen_paths:
                continue
            seen_paths.add(path)
            endpoint_node = self.graph.add_endpoint(Endpoint(method="GET", path=path))
            self.graph.add_resolves_to(host_node, endpoint_node)
            written.append(endpoint_node)
        return tuple(written)
