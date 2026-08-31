"""dnsx recon wrapper — DNS resolution as Host facts (§9 recon tier).

dnsx resolves hostnames/subdomains to IPs and CNAME targets; each resolved
hostname is a Host node. A CNAME target is the input a dangling-subdomain
takeover check needs (a subdomain's CNAME pointing at an unclaimed third-party
service). Facts only — never a candidate, Finding, or can_call.
"""

from __future__ import annotations

from collections.abc import Callable

from reachagent.graph.nodes import Host
from reachagent.recon.calibration import _default_dns_resolve
from reachagent.recon.tools.base import ReconToolRunner


def _parse_dnsx_line(line: str) -> tuple[str, str, str]:
    """Split one dnsx ``-resp`` line into ``(hostname, record_type, value)``.

    Multiple type flags (``-a -cname``) make dnsx tag each line: ``hostname
    [TYPE] [value]``. A single type flag omits the tag (``hostname [value]``)
    — treated as an A record, so a fixture recorded before ``-cname`` was
    added still parses. A multi-value bracket (``[ip1, ip2]``) keeps only the
    first value, matching dnsx's own "first answer" convention.
    """
    parts = line.split("[")
    hostname = parts[0].strip()
    brackets = [p.split("]", 1)[0].strip() for p in parts[1:]]
    if len(brackets) >= 2:
        record_type, raw_value = brackets[0].upper(), brackets[1]
    elif len(brackets) == 1:
        record_type, raw_value = "A", brackets[0]
    else:
        return hostname, "", ""
    return hostname, record_type, raw_value.split(",")[0].strip()


class DnsxRunner(ReconToolRunner):
    """Emit Host per dnsx-resolved hostname (§9). Facts only."""

    name = "dnsx"
    binary = "dnsx"

    dns_wildcard_ip: str | None = None
    resolve: Callable[[str], str | None] = _default_dns_resolve

    def command(self, target: str) -> list[str]:
        """dnsx -d <target> -a -cname -resp -silent -nc.

        -cname surfaces a subdomain's CNAME target as a Host fact. -nc
        disables the ANSI color codes dnsx otherwise emits even under
        -silent, which would corrupt line parsing.
        """
        return ["dnsx", "-d", target, "-a", "-cname", "-resp", "-silent", "-nc"]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse dnsx output into Host facts (hostname → resolved IP + CNAME).

        Records are grouped by hostname across however many lines dnsx emits
        per host (one per requested record type), so one Host node reflects
        both its resolved address and any CNAME target regardless of line
        order.
        """
        records: dict[str, dict[str, str]] = {}
        order: list[str] = []
        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            hostname, record_type, value = _parse_dnsx_line(stripped)
            if not hostname or not record_type or not value:
                continue
            if hostname not in records:
                records[hostname] = {}
                order.append(hostname)
            records[hostname].setdefault(record_type, value)

        written: list[str] = []
        for hostname in order:
            by_type = records[hostname]
            ip = by_type.get("A")
            cname = by_type.get("CNAME")
            if self.dns_wildcard_ip is not None:
                try:
                    resolved = self.resolve(hostname)
                except Exception:  # noqa: BLE001
                    resolved = None
                if resolved is not None and resolved == self.dns_wildcard_ip:
                    self.audit.record(self.name, "RECON", hostname, "refused_wildcard_dns")
                    continue
            node = self.graph.add_host(
                Host(address=ip or hostname, hostname=hostname, source=self.name, cname=cname)
            )
            written.append(node)
        return tuple(written)
