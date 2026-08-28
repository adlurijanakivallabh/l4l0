"""Subdomain-enumeration recon wrappers — amass, subfinder (§9 recon tier).

Both tools emit one discovered hostname per output line. Per §6/§9 (v1.8) a
subdomain is just a hostname, so each becomes a ``Host`` node — there is
deliberately no ``Subdomain`` node. Facts only: no candidate, no ``Finding``.

amass and subfinder share the identical line-per-hostname output contract, so
they share one parser and differ only in ``name``/``binary``/``command``.
"""

from __future__ import annotations

from collections.abc import Callable

from reachagent.graph.nodes import Host
from reachagent.recon.calibration import _default_dns_resolve
from reachagent.recon.tools.base import ReconToolRunner


class _LineHostRunner(ReconToolRunner):
    """Shared parser: one hostname per non-blank line → one ``Host`` node.

    A blank line or a ``#`` comment is skipped. Each hostname is stamped with the
    asserting tool's ``source`` so a transport fact is auditable to its emitter.
    Idempotent: the same hostname from amass and subfinder keys to one ``Host``.

    DNS wildcard suppression (D2): when ``dns_wildcard_ip`` is set (by the scan
    entrypoint), a hostname that resolves to exactly that IP is the zone's
    catch-all, not a real host — its Host fact is suppressed and audited
    ``refused_wildcard_dns``. A hostname that FAILS to resolve is kept
    (conservative — don't over-suppress on uncertainty). ``resolve`` defaults to
    stdlib ``socket.gethostbyname``; tests inject a fake for hermetic runs.
    """

    # Set by the scan entrypoint before ingest (D3 pass-through).
    dns_wildcard_ip: str | None = None
    resolve: Callable[[str], str | None] = _default_dns_resolve

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
        if os.environ.get("REACHAGENT_SUBFINDER_ALL", "").lower() in {"1", "true", "yes"}:
            argv.append("-all")
        if os.environ.get("REACHAGENT_SUBFINDER_RECURSIVE", "").lower() in {
            "1",
            "true",
            "yes",
        }:
            argv.append("-recursive")
        timeout = os.environ.get("REACHAGENT_SUBFINDER_TIMEOUT")
        if timeout and timeout.isdigit():
            argv += ["-timeout", timeout]
        rate = os.environ.get("REACHAGENT_SUBFINDER_RATE")
        if rate and rate.isdigit():
            argv += ["-rateLimit", rate]
        return argv
