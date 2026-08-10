"""rustscan recon wrapper — open ports as Host/Service facts (§9 recon tier).

rustscan text output reports open ports like "Open 80" or "80/tcp open".
Per §6/§9 (v1.8) each open port is a Service node + runs_service edge on a Host.
Facts only — never a candidate/Finding/can_call.
"""

from __future__ import annotations

import re

from reachagent.graph.nodes import Host, Service
from reachagent.recon.tools.base import ReconToolRunner

_OPEN_RE = re.compile(
    r"(?:Open\s+(?P<port1>\d+)|(?P<port2>\d+)/(?P<proto>\w+)\s+open)",
    re.IGNORECASE,
)


def _host_of(target: str) -> str:
    stripped = target.split("://", 1)[-1]
    return stripped.split("/", 1)[0].split(":", 1)[0]


class RustscanRunner(ReconToolRunner):
    """Emit Host/Service + runs_service from rustscan text output (§9). Facts only."""

    name = "rustscan"
    binary = "rustscan"

    def command(self, target: str) -> list[str]:
        """rustscan -a <target> --ulimit N --batch-size B --timeout T -- -sV.

        Defaults 5000/4500/1500 match spec (ulimit = fd cap, batch = scan
        throughput, timeout = ms before port assumed closed). Env overrides:
        REACHAGENT_RUSTSCAN_ULIMIT/BATCH/TIMEOUT.
        """
        import os

        ulimit = os.environ.get("REACHAGENT_RUSTSCAN_ULIMIT", "5000")
        batch = os.environ.get("REACHAGENT_RUSTSCAN_BATCH", "4500")
        timeout = os.environ.get("REACHAGENT_RUSTSCAN_TIMEOUT", "1500")
        return [
            "rustscan",
            "-a",
            target,
            "--ulimit",
            ulimit,
            "--batch-size",
            batch,
            "--timeout",
            timeout,
            "--",
            "-sV",
        ]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse rustscan open-port lines into Host/Service facts."""
        written: list[str] = []
        host_addr = _host_of(target)
        host_node = self.graph.add_host(Host(address=host_addr, source=self.name))
        written.append(host_node)
        seen_ports: set[int] = set()
        for line in raw_output.splitlines():
            match = _OPEN_RE.search(line)
            if match is None:
                continue
            port_str = match.group("port1") or match.group("port2")
            if port_str is None:
                continue
            try:
                port = int(port_str)
            except ValueError:
                continue
            if port in seen_ports:
                continue
            seen_ports.add(port)
            proto = (match.group("proto") or "tcp").lower()
            # Try to extract service name trailing the port if present
            service_name: str | None = None
            # Common trailing like "80/tcp open http" — last token as service
            tail = line[match.end() :].strip()
            if tail:
                service_name = tail.split()[0].strip("[](),")
            service_node = self.graph.add_service(
                host_node,
                Service(
                    port=port,
                    protocol=proto,
                    service_name=service_name,
                    source=self.name,
                ),
            )
            written.append(service_node)
        return tuple(written)
