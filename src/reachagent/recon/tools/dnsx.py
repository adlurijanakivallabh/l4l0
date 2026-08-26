"""dnsx recon wrapper — DNS resolution as Host facts (§9 recon tier).

dnsx resolves hostnames/subdomains to IPs; each resolved hostname is a Host
node. Facts only — never a candidate, Finding, or can_call.
"""

from __future__ import annotations

from collections.abc import Callable

from reachagent.graph.nodes import Host
from reachagent.recon.calibration import _default_dns_resolve
from reachagent.recon.tools.base import ReconToolRunner


class DnsxRunner(ReconToolRunner):
    """Emit Host per dnsx-resolved hostname (§9). Facts only."""

    name = "dnsx"
    binary = "dnsx"

    dns_wildcard_ip: str | None = None
    resolve: Callable[[str], str | None] = _default_dns_resolve

    def command(self, target: str) -> list[str]:
        """dnsx -d <target> -a -resp -silent — resolve subdomain A records."""
        return ["dnsx", "-d", target, "-a", "-resp", "-silent"]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse dnsx output into Host facts (hostname → resolved IP).

        dnsx -resp emits "hostname [IP]" or "hostname [IP, IP2]" per line.
        DNS wildcard suppression mirrors subdomains.py.
        """
        written: list[str] = []
        seen: set[str] = set()
        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split("[", 1)
            hostname = parts[0].strip()
            if not hostname:
                continue
            ip = None
            if len(parts) > 1:
                bracket = parts[1].split("]", 1)[0].strip()
                ip = bracket.split(",")[0].strip() or None
            if hostname in seen:
                continue
            seen.add(hostname)
            if self.dns_wildcard_ip is not None:
                try:
                    resolved = self.resolve(hostname)
                except Exception:  # noqa: BLE001
                    resolved = None
                if resolved is not None and resolved == self.dns_wildcard_ip:
                    self.audit.record(self.name, "RECON", hostname, "refused_wildcard_dns")
                    continue
            node = self.graph.add_host(
                Host(address=ip or hostname, hostname=hostname, source=self.name)
            )
            written.append(node)
        return tuple(written)
