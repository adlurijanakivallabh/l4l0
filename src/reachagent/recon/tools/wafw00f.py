"""wafw00f recon wrapper — WAF fingerprint as Host technology attribute (§9).

wafw00f identifies which WAF (if any) sits between us and the target. The
detection result is a technology attribute on the Host — same shape as whatweb.
Facts only.
"""

from __future__ import annotations

import json

from reachagent.graph.nodes import Host
from reachagent.recon.tools.base import ReconToolRunner, _recon_host_of

_host_of = _recon_host_of


class Wafw00fRunner(ReconToolRunner):
    """Emit Host WAF-fingerprint attributes from wafw00f output (§9). Facts only."""

    name = "wafw00f"
    binary = "wafw00f"

    def command(self, target: str) -> list[str]:
        """wafw00f -a <url> -o - — all-detection, results to stdout."""
        return ["wafw00f", "-a", target, "-o", "-"]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse wafw00f JSON/text into a Host technology attribute."""
        written: list[str] = []
        host_addr = _host_of(target)
        waf_name: str | None = None
        try:
            parsed = json.loads(raw_output)
            entries = parsed if isinstance(parsed, list) else [parsed]
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                detected = entry.get("detected") or entry.get("firewall")
                if isinstance(detected, str) and detected.lower() not in ("none", "", "no"):
                    waf_name = detected
                    break
        except json.JSONDecodeError:
            lowered = raw_output.lower()
            for marker in ("is behind ", "detected waf:", "waf:", "firewall:"):
                idx = lowered.find(marker)
                if idx >= 0:
                    rest = raw_output[idx + len(marker) :].strip().splitlines()[0].strip()
                    if rest and rest.lower() not in ("none", "no waf"):
                        waf_name = rest[:60]
                    break
        technology = f"waf:{waf_name}" if waf_name else "waf:none"
        node = self.graph.add_host(
            Host(address=host_addr, hostname=host_addr, source=self.name, technology=technology)
        )
        written.append(node)
        return tuple(written)
