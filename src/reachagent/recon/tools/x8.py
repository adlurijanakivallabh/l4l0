"""X8 recon wrapper — parameter reflection as Parameter facts (§9).

Tier decision: recon-tier — parameter discovery is a fact, not a claim; see §9.
X8 emits which param names reflect in the response — a fact about existence/
reflection (Endpoint→Parameter), not a claim that the reflect is XSS-vuln.
Mirrors gobuster/katana. Facts only.
"""

from __future__ import annotations

import re

from reachagent.graph.nodes import Endpoint, Host, Parameter
from reachagent.recon.tools._wordlist import preferred_wordlist
from reachagent.recon.tools.base import ReconToolRunner

_REFLECT_RE = re.compile(
    r"param\s+['\"]?(?P<name>[A-Za-z0-9_\-]+)['\"]?\s+reflected", re.IGNORECASE
)


def _host_of(target: str) -> str:
    stripped = target.split("://", 1)[-1]
    return stripped.split("/", 1)[0].split(":", 1)[0]


class X8Runner(ReconToolRunner):
    """Emit Parameter per X8-discovered reflecting param (§9). Facts only."""

    name = "x8"
    binary = "x8"

    def command(self, target: str) -> list[str]:
        """x8 -u <target> -w <wordlist> — hidden param discovery, reflected check."""
        wordlist = preferred_wordlist("REACHAGENT_X8_WORDLIST", x8=True)
        return ["x8", "-u", target, "-w", wordlist]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse X8 reflected-param lines into Parameter nodes. Facts only."""
        written: list[str] = []
        param_names: list[str] = []
        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = _REFLECT_RE.search(stripped)
            if match:
                param_names.append(match.group("name"))
                continue
            # Fallback: URL with query like https://host/path?foo=1&bar=2
            if "?" in stripped and "://" in stripped:
                query = stripped.split("?", 1)[1].split("#", 1)[0].split()[0]
                for kv in query.split("&"):
                    name = kv.split("=", 1)[0].strip().strip("\"'")
                    if name and " " not in name and len(name) < 64:
                        param_names.append(name)
        if not param_names:
            return ()
        seen: set[str] = set()
        unique: list[str] = []
        for p in param_names:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        host_addr = _host_of(target)
        host_node = self.graph.add_host(Host(address=host_addr, source=self.name))
        written.append(host_node)
        endpoints = list(self.graph.endpoints())
        if endpoints:
            endpoint_node = endpoints[0][0]
        else:
            endpoint_node = self.graph.add_endpoint(Endpoint(method="GET", path="/"))
            self.graph.add_resolves_to(host_node, endpoint_node)
            written.append(endpoint_node)
        for param_name in unique:
            node = self.graph.add_parameter(
                endpoint_node, Parameter(name=param_name, location="query")
            )
            written.append(node)
        return tuple(written)
