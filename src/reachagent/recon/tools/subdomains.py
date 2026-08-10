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
        """``amass enum -d <target> -o -`` [+ ``-timeout``]."""
        import os

        argv: list[str] = ["amass", "enum", "-d", target, "-o", "-"]
        timeout = os.environ.get("REACHAGENT_AMASS_TIMEOUT")
        if timeout and timeout.isdigit():
            argv += ["-timeout", timeout]
        return argv


class SubfinderRunner(_LineHostRunner):
    """Emit a ``Host`` per subfinder-discovered subdomain (§9). Facts only."""

    name = "subfinder"
    binary = "subfinder"

    def command(self, target: str) -> list[str]:
        """``subfinder -silent -d <target>`` [+ ``-timeout``/``-rateLimit``]."""
        import os

        argv: list[str] = ["subfinder", "-silent", "-d", target]
        timeout = os.environ.get("REACHAGENT_SUBFINDER_TIMEOUT")
        if timeout and timeout.isdigit():
            argv += ["-timeout", timeout]
        rate = os.environ.get("REACHAGENT_SUBFINDER_RATE")
        if rate and rate.isdigit():
            argv += ["-rateLimit", rate]
        return argv
