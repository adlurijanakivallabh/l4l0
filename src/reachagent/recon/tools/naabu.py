"""naabu recon wrapper — fast port scan as Host/Service facts (§9 recon tier).

naabu emits one ip:port pair per discovered open port (or JSON lines with
-json). Each becomes a Service + runs_service edge on the target Host.
Facts only — never a candidate, Finding, or can_call.
"""

from __future__ import annotations

import json
import re

from reachagent.graph.nodes import Host, Service
from reachagent.recon.tools.base import ReconToolRunner

# naabu text output: "1.2.3.4:80" per line (bare host:port)
_PORT_RE = re.compile(r"^(?P<host>\S+):(?P<port>\d+)$")


class NaabuRunner(ReconToolRunner):
    """Emit Host/Service facts from naabu port-scan output. Facts only."""

    name = "naabu"
    binary = "naabu"

    def command(self, target: str) -> list[str]:
        """naabu -host <target> -silent -json [+ -top-ports/-rate]."""
        import os

        argv: list[str] = ["naabu", "-host", target, "-silent", "-json"]
        top = os.environ.get("REACHAGENT_NAABU_TOP_PORTS")
        if top and top.isdigit():
            argv += ["-top-ports", top]
        rate = os.environ.get("REACHAGENT_NAABU_RATE")
        if rate and rate.isdigit():
            argv += ["-rate", rate]
        return argv

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse naabu JSON or host:port lines into Host/Service facts."""
        written: list[str] = []
        seen: set[tuple[str, int]] = set()
        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
                if isinstance(obj, dict):
                    host_addr = str(obj.get("host", "")).strip()
                    try:
                        port = int(obj.get("port", 0))
                    except (ValueError, TypeError):
                        continue
                else:
                    continue
            except json.JSONDecodeError:
                match = _PORT_RE.match(stripped)
                if match is None:
                    continue
                host_addr = match.group("host")
                port = int(match.group("port"))
            key = (host_addr, port)
            if not host_addr or port <= 0 or key in seen:
                continue
            seen.add(key)
            host_node = self.graph.add_host(
                Host(address=host_addr, hostname=host_addr, source=self.name)
            )
            service_node = self.graph.add_service(
                host_node, Service(port=port, protocol="tcp", source=self.name)
            )
            written.extend((host_node, service_node))
        return tuple(written)
