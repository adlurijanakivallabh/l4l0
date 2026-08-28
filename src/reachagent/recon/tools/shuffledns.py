"""shuffledns recon wrapper — active DNS brute force as Host facts (§9).

Facts only. No DNS wildcard suppression here (the tool already resolves each
candidate before emitting it, so a wildcard catch-all would be resolved and
emitted by the target zone itself — the scan entrypoint's DnsWildcardProber is
responsible for flagging that at the zone level).
"""

from __future__ import annotations

from reachagent.graph.nodes import Host
from reachagent.recon.tools.base import ReconToolRunner


class ShuffleDnsRunner(ReconToolRunner):
    """Emit Host per shuffledns-discovered subdomain (§9). Facts only."""

    name = "shuffledns"
    binary = "shuffledns"

    def command(self, target: str) -> list[str]:
        """shuffledns -d <target> -w <wordlist> -r resolvers -o -."""
        from reachagent.recon.tools._wordlist import preferred_wordlist

        wordlist = preferred_wordlist("REACHAGENT_SHUFFLEDNS_WORDLIST", purpose="dns")
        return [
            "shuffledns",
            "-d",
            target,
            "-w",
            wordlist,
            "-r",
            "/etc/resolv.conf",
            "-o",
            "-",
        ]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse shuffledns hostname-per-line output into Host facts."""
        written: list[str] = []
        seen: set[str] = set()
        for line in raw_output.splitlines():
            hostname = line.strip()
            if not hostname or hostname.startswith("#"):
                continue
            if hostname in seen:
                continue
            seen.add(hostname)
            node = self.graph.add_host(Host(address=hostname, hostname=hostname, source=self.name))
            written.append(node)
        return tuple(written)
