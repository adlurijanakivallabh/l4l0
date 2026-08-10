"""theHarvester recon wrapper — discovered hostnames as Host facts (§9 recon tier).

theHarvester emits hostnames (one per line, mixed with email lines and banner
noise). Per §6/§9 (v1.8) a discovered hostname is a Host node — no Subdomain
node. Mirrors subdomains.py line-per-host pattern (blank/# skip, seen dedup).
Facts only — emails ignored, no candidate/Finding/can_call.
"""

from __future__ import annotations

from reachagent.graph.nodes import Host
from reachagent.recon.tools.base import ReconToolRunner


class TheHarvesterRunner(ReconToolRunner):
    """Emit Host per theHarvester-discovered hostname line (§9). Facts only."""

    name = "theHarvester"
    binary = "theHarvester"

    def command(self, target: str) -> list[str]:
        """theHarvester -d <target> -b <source> — harvest hostnames."""
        import os

        source = os.environ.get("REACHAGENT_THEHARVESTER_SOURCE", "all")
        return ["theHarvester", "-d", target, "-b", source]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse theHarvester hostname lines into Host facts (emails/hosts sep)."""
        written: list[str] = []
        seen: set[str] = set()
        for line in raw_output.splitlines():
            hostname = line.strip()
            if not hostname or hostname.startswith("#"):
                continue
            # Skip email lines — they contain "@"; harvest emails not graph nodes
            if "@" in hostname:
                continue
            # Skip banner/progress noise (no dot, or known noise prefixes)
            if "." not in hostname:
                continue
            # Strip trailing punctuation that banner lines carry
            hostname = hostname.strip("[](),:;")
            if not hostname or "@" in hostname or "." not in hostname:
                continue
            if hostname in seen:
                continue
            seen.add(hostname)
            node = self.graph.add_host(Host(address=hostname, hostname=hostname, source=self.name))
            written.append(node)
        return tuple(written)
