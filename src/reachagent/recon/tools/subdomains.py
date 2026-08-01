"""Subdomain-enumeration recon wrappers — amass, subfinder (§9 recon tier).

Both tools emit one discovered hostname per output line. Per §6/§9 (v1.8) a
subdomain is just a hostname, so each becomes a ``Host`` node — there is
deliberately no ``Subdomain`` node. Facts only: no candidate, no ``Finding``.

amass and subfinder share the identical line-per-hostname output contract, so
they share one parser and differ only in ``name``/``binary``/``command``.
"""

from __future__ import annotations

from reachagent.graph.nodes import Host
from reachagent.recon.tools.base import ReconToolRunner


class _LineHostRunner(ReconToolRunner):
    """Shared parser: one hostname per non-blank line → one ``Host`` node.

    A blank line or a ``#`` comment is skipped. Each hostname is stamped with the
    asserting tool's ``source`` so a transport fact is auditable to its emitter.
    Idempotent: the same hostname from amass and subfinder keys to one ``Host``.
    """

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
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


class AmassRunner(_LineHostRunner):
    """Emit a ``Host`` per amass-discovered subdomain (§9). Facts only."""

    name = "amass"
    binary = "amass"

    def command(self, target: str) -> list[str]:
        """``amass enum -d <target> -o -`` — passive/active enum, hostnames to stdout.

        Target is the final distinct list element (``shell=False`` in the base) —
        never interpolated into a shell string.
        """
        return ["amass", "enum", "-d", target, "-o", "-"]


class SubfinderRunner(_LineHostRunner):
    """Emit a ``Host`` per subfinder-discovered subdomain (§9). Facts only."""

    name = "subfinder"
    binary = "subfinder"

    def command(self, target: str) -> list[str]:
        """``subfinder -silent -d <target>`` — one hostname per line to stdout.

        Target is a distinct list element; ``-silent`` keeps stdout to hostnames.
        """
        return ["subfinder", "-silent", "-d", target]
