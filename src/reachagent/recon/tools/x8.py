"""X8 recon wrapper — parameter reflection as Parameter facts (§9).

Tier decision: recon-tier — parameter discovery is a fact, not a claim; see §9.
X8 emits which param names reflect in the response — a fact about existence/
reflection (Endpoint→Parameter), not a claim that the reflect is XSS-vuln.
Mirrors gobuster/katana. Facts only.
"""

from __future__ import annotations

import re

from reachagent.graph.nodes import Host, Parameter
from reachagent.recon.tools._wordlist import preferred_wordlist
from reachagent.recon.tools.base import ReconToolRunner, _recon_host_of, _scope_url

_REFLECT_RE = re.compile(
    r"param\s+['\"]?(?P<name>[A-Za-z0-9_\-]+)['\"]?\s+reflected", re.IGNORECASE
)


_host_of = _recon_host_of  # ponytail: deduped to base helper


class X8Runner(ReconToolRunner):
    """Emit Parameter per X8-discovered reflecting param (§9). Facts only."""

    name = "x8"
    binary = "x8"

    def command(self, target: str) -> list[str]:
        """x8 -u <target> -w <wordlist> — hidden param discovery, reflected check."""
        from reachagent.recon.live_tuning import profile_argv  # ponytail: 5× copy → 1

        if (profile := profile_argv(target, [])) is not None:
            wordlist = preferred_wordlist("REACHAGENT_X8_WORDLIST", x8=True)
            argv: list[str] = ["x8", "-u", target, "-w", wordlist]
            argv += list(profile.flags)
            return argv
        wordlist = preferred_wordlist("REACHAGENT_X8_WORDLIST", x8=True)
        return ["x8", "-u", target, "-w", wordlist]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse X8 reflected-param lines into Parameter nodes. Facts only."""
        written: list[str] = []
        targets: dict[str, list[str]] = {}
        current_target = target
        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = _REFLECT_RE.search(stripped)
            if match:
                targets.setdefault(current_target, []).append(match.group("name"))
                continue
            # Fallback: URL with query like https://host/path?foo=1&bar=2
            if "?" in stripped and "://" in stripped:
                current_target = stripped.split()[0]
                query = stripped.split("?", 1)[1].split("#", 1)[0].split()[0]
                for kv in query.split("&"):
                    name = kv.split("=", 1)[0].strip().strip("\"'")
                    if name and " " not in name and len(name) < 64:
                        targets.setdefault(current_target, []).append(name)
        if not any(targets.values()):
            return ()
        host_addr = _host_of(target)
        host_node = self.graph.add_host(Host(address=host_addr, source=self.name))
        written.append(host_node)
        for endpoint_target, names in targets.items():
            try:
                self.scope.enforce(_scope_url(endpoint_target))
            except Exception:  # noqa: BLE001 — raw tool lines can contain foreign URLs
                self.audit.record(self.name, "RECON", endpoint_target, "refused_out_of_scope")
                continue
            endpoint_node = self.endpoint_for_target(endpoint_target)
            for param_name in dict.fromkeys(names):
                node = self.graph.add_parameter(
                    endpoint_node,
                    Parameter(
                        name=param_name,
                        location="query",
                        serialization="application/x-www-form-urlencoded",
                        source=self.name,
                        confidence=0.75,
                    ),
                )
                written.append(node)
        return tuple(written)
