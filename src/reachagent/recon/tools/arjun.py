"""Arjun recon wrapper — parameter discovery as Endpoint/Parameter facts (§9).

Tier decision: recon-tier — parameter discovery is a fact, not a claim; see §9.
A discovered parameter name/location is a fact (Endpoint→Parameter edge, like
gobuster discovering /admin), not a vulnerability claim. These tools state
"parameter X exists / reflects", not "parameter X is vulnerable". So per §9
table (fact → Host/Service/Endpoint/Parameter) this belongs to recon tier,
mirroring katana/gobuster pattern. Same tier as Big Task 1 surface mapper.

Facts only — never a candidate/Finding/can_call, no run_oracle.
"""

from __future__ import annotations

import json

from reachagent.graph.nodes import Endpoint, Host, Parameter
from reachagent.recon.tools.base import ReconToolRunner


def _host_of(target: str) -> str:
    stripped = target.split("://", 1)[-1]
    return stripped.split("/", 1)[0].split(":", 1)[0]


class ArjunRunner(ReconToolRunner):
    """Emit Parameter per Arjun-discovered param name (§9). Facts only."""

    name = "arjun"
    binary = "arjun"

    def command(self, target: str) -> list[str]:
        """arjun -u <target> -oJ <file> — JSON output to file (base reads file)."""
        import os
        import tempfile

        fd, path = tempfile.mkstemp(suffix=".json", prefix="arjun-")  # noqa: S108 — mkstemp is safe temp, not hardcoded /tmp write
        os.close(fd)
        return ["arjun", "-u", target, "-oJ", path]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse Arjun JSON into Parameter nodes.

        Arjun emits JSON like {"param": "..."} or {"parameters": ["a","b"]} or
        line-per-param. Each param name → Parameter on target's Endpoint.
        Deduplicated. Facts only.
        """
        written: list[str] = []
        params: list[str] = []
        text = raw_output.strip()
        if not text:
            return ()
        # Try JSON object with "param" or "parameters"
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                if "parameters" in parsed and isinstance(parsed["parameters"], list):
                    params = [str(p).strip() for p in parsed["parameters"] if str(p).strip()]
                elif "param" in parsed:
                    val = parsed["param"]
                    if isinstance(val, list):
                        params = [str(p).strip() for p in val if str(p).strip()]
                    elif isinstance(val, str) and val.strip():
                        params = [val.strip()]
                elif "params" in parsed and isinstance(parsed["params"], list):
                    params = [str(p).strip() for p in parsed["params"] if str(p).strip()]
            elif isinstance(parsed, list):
                # Bare list of param names
                params = [str(p).strip() for p in parsed if str(p).strip()]
        except json.JSONDecodeError:
            pass
        if not params:
            # Fallback: line-per-param (one non-blank line per param name)
            for line in raw_output.splitlines():
                name = line.strip().strip("[]\"',")
                if name and not name.startswith("#") and not name.startswith("{"):
                    # Heuristic: bare word, not URL
                    if "://" not in name and len(name) < 64 and " " not in name:
                        params.append(name)
        if not params:
            return ()
        seen: set[str] = set()
        unique: list[str] = []
        for p in params:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        host_addr = _host_of(target)
        host_node = self.graph.add_host(Host(address=host_addr, source=self.name))
        written.append(host_node)
        # Target endpoint — prefer existing, else create GET /
        endpoints = list(self.graph.endpoints())
        if endpoints:
            endpoint_node = endpoints[0][0]
        else:
            endpoint_node = self.graph.add_endpoint(Endpoint(method="GET", path="/"))
            self.graph.add_resolves_to(host_node, endpoint_node)
            written.append(endpoint_node)
        for param_name in unique:
            # Location heuristic: arjun --get → query
            node = self.graph.add_parameter(
                endpoint_node, Parameter(name=param_name, location="query")
            )
            written.append(node)
        return tuple(written)
