"""theHarvester recon wrapper — discovered hostnames as Host facts (§9 recon tier).

theHarvester emits hostnames (one per line, mixed with email lines and banner
noise). Per §6/§9 (v1.8) a discovered hostname is a Host node — no Subdomain
node. Mirrors subdomains.py line-per-host pattern (blank/# skip, seen dedup).
Facts only — emails ignored, no candidate/Finding/can_call.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable

from reachagent.graph.nodes import Host
from reachagent.recon.calibration import _default_dns_resolve
from reachagent.recon.tools.base import ReconToolRunner

# A REAL theHarvester hostname is a bare hostname — no whitespace, no leading
# !/*/[ banner prefix, at least one dot, no path/query/colon. Real output mixes
# this with banner noise ("!] Missing API key …", "*] Searching …", "* theHarvester
# 4.10.1") that the old "has a dot" heuristic admitted (live-run divergence #1).
_HOSTNAME = re.compile(r"^[a-z0-9._-]+\.[a-z0-9._-]+$", re.IGNORECASE)


class TheHarvesterRunner(ReconToolRunner):
    """Emit Host per theHarvester-discovered hostname line (§9). Facts only."""

    name = "theHarvester"
    binary = "theHarvester"

    # Set by the scan entrypoint before ingest (D3 DNS-wildcard pass-through).
    dns_wildcard_ip: str | None = None
    resolve: Callable[[str], str | None] = _default_dns_resolve

    def command(self, target: str) -> list[str]:
        """theHarvester -d <target> -b <source> — harvest hostnames."""
        import os

        source = os.environ.get("REACHAGENT_THEHARVESTER_SOURCE", "all")
        return ["theHarvester", "-d", target, "-b", source]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse theHarvester hostname lines into Host facts (emails/hosts sep).

        DNS wildcard suppression (D2): a hostname resolving to exactly
        ``dns_wildcard_ip`` is the zone's catch-all, not a real host — its Host
        fact is suppressed and audited ``refused_wildcard_dns``. A hostname that
        fails to resolve is kept (conservative).

        Bare-IP filter (live-run divergence): theHarvester against a loopback/IP
        target does internet OSINT and returns off-target third-party IPs. A bare
        IPv4/IPv6 line is never a Host fact here — nmap/masscan/rustscan own IP
        facts; theHarvester's job is names. Bare IPs are counted as noise. A
        ``*.localhost`` dictionary name is still a name and is KEPT (only bare IPs
        are rejected). Callers targeting loopback should expect such noise.
        """
        written: list[str] = []
        seen: set[str] = set()
        noise = 0
        for line in raw_output.splitlines():
            hostname = line.strip()
            if not hostname or hostname.startswith("#"):
                continue
            # Email lines are a legitimately-distinct section, not banner noise —
            # silently skipped (never graph nodes), never counted.
            if "@" in hostname:
                continue
            # Bare IP → OSINT junk from off-target lookups; counted, never a Host.
            try:
                ipaddress.ip_address(hostname)
                noise += 1
                continue
            except ValueError:
                pass
            # A real hostname is a bare hostname — no whitespace, no banner prefix,
            # no path. Banner/noise lines ("!] …", "*] …", "* …") fail the strict
            # match and are counted (one summary audit), not audited per line.
            if not _HOSTNAME.fullmatch(hostname):
                noise += 1
                continue
            if hostname in seen:
                continue
            seen.add(hostname)
            if self.dns_wildcard_ip is not None:
                try:
                    ip = self.resolve(hostname)
                except Exception:  # noqa: BLE001 — resolver hiccup is conservative (keep)
                    ip = None
                if ip is not None and ip == self.dns_wildcard_ip:
                    self.audit.record(self.name, "RECON", hostname, "refused_wildcard_dns")
                    continue
            node = self.graph.add_host(Host(address=hostname, hostname=hostname, source=self.name))
            written.append(node)
        if noise:
            self.audit.record(self.name, "RECON", target, f"skipped_banner_noise:{noise}")
        return tuple(written)
