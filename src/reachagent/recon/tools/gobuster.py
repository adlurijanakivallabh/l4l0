"""gobuster recon wrapper — discovered HTTP paths as Endpoint facts (§9 recon tier).

gobuster's ``dir`` mode emits one discovered path per line. Per §6/§9 (v1.8) a
discovered path is an ordinary ``Endpoint`` node (no new type), attached to the
target ``Host`` by a ``resolves_to`` edge. Facts only: gobuster asserts that a
path *exists* (a fact), never that it is *vulnerable* (a claim) — so nothing here
is a candidate or a ``Finding``. The HTTP status it reports is provenance in the
audit trail, not a ``can_call`` verdict (recon never writes ``can_call``).

Default gobuster stdout lines look like::

    /admin                (Status: 200) [Size: 1234]
    /login                (Status: 301) [Size: 0] [--> /login/]
"""

from __future__ import annotations

import os
import re

from reachagent.graph.nodes import Endpoint, Host
from reachagent.recon.tools._wordlist import preferred_wordlist
from reachagent.recon.tools.base import ReconToolRunner

# A gobuster result line: a path token, then a "(Status: NNN)" marker. Anything
# without both is banner/progress noise and is skipped.
_RESULT = re.compile(r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d{3})\)")


class GobusterRunner(ReconToolRunner):
    """Emit an ``Endpoint`` per gobuster-discovered path + ``resolves_to`` edge (§9)."""

    name = "gobuster"
    binary = "gobuster"

    def command(self, target: str) -> list[str]:
        """``gobuster dir -q -u <target> -w <wordlist>`` — quiet, results to stdout.

        Target is a distinct list element (``shell=False`` in the base). The
        wordlist path comes from ``REACHAGENT_GOBUSTER_WORDLIST`` or a common
        default; it is a fixed path element, never the target, so it is not an
        injection surface.
        """
        wordlist = preferred_wordlist("REACHAGENT_GOBUSTER_WORDLIST")
        argv: list[str] = ["gobuster", "dir", "-q", "-u", target, "-w", wordlist]
        # ponytail: env-only tuning, no config file until env count >12
        threads = os.environ.get("REACHAGENT_GOBUSTER_THREADS")
        if threads and threads.isdigit():
            argv += ["-t", threads]
        timeout = os.environ.get("REACHAGENT_GOBUSTER_TIMEOUT")
        if timeout and timeout.isdigit():
            argv += ["--timeout", f"{timeout}s"]
        return argv

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse gobuster result lines into ``Endpoint`` nodes + ``resolves_to`` edges."""
        written: list[str] = []
        host_node = self.graph.add_host(Host(address=_host_of(target), source=self.name))
        written.append(host_node)
        for line in raw_output.splitlines():
            match = _RESULT.match(line.strip())
            if match is None:
                continue
            path = match.group("path")
            # A discovered path is an ordinary GET Endpoint (recon asserts it
            # exists; it never assigns a can_call or a method beyond the probe verb).
            endpoint_node = self.graph.add_endpoint(Endpoint(method="GET", path=path))
            self.graph.add_resolves_to(host_node, endpoint_node)
            written.append(endpoint_node)
        return tuple(written)


def _host_of(target: str) -> str:
    """The bare host of a recon target (strip scheme + any path), for the Host node."""
    stripped = target.split("://", 1)[-1]
    return stripped.split("/", 1)[0]
