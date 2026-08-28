"""Arjun recon wrapper — parameter discovery as Endpoint/Parameter facts (§9).

Tier decision: recon-tier — parameter discovery is a fact, not a claim; see §9.
A discovered parameter name/location is a fact (Endpoint→Parameter edge, like
gobuster discovering /admin), not a vulnerability claim. These tools state
"parameter X exists / reflects", not "parameter X is vulnerable". So per §9
table (fact → Host/Service/Endpoint/Parameter) this belongs to recon tier,
mirroring katana/gobuster pattern. Same tier as Big Task 1 surface mapper.

Facts only — never a candidate/Finding/can_call, no run_oracle.
"""

from __future__ import annotations

import json

from reachagent.graph.nodes import Host, Parameter
from reachagent.recon.tools.base import ReconToolRunner, _recon_host_of, _scope_url

_host_of = _recon_host_of  # ponytail: deduped to base helper


class ArjunRunner(ReconToolRunner):
    """Emit Parameter per Arjun-discovered param name (§9). Facts only."""

    name = "arjun"
    binary = "arjun"

    def command(self, target: str) -> list[str]:
        """arjun -u <target> -oJ <file> — JSON output to file (base reads file)."""
        import os
        import tempfile

        fd, path = tempfile.mkstemp(suffix=".json", prefix="arjun-")  # noqa: S108 — mkstemp is safe temp, not hardcoded /tmp write
        os.close(fd)
        return ["arjun", "-u", target, "-oJ", path]

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse Arjun JSON into Parameter nodes.

        Arjun emits JSON like {"param": "..."} or {"parameters": ["a","b"]} or
        line-per-param. Each param name → Parameter on target's Endpoint.
        Deduplicated. Facts only.
        """
        written: list[str] = []
        by_target: dict[str, list[str]] = {}
        text = raw_output.strip()
        if not text:
            return ()
        # Arjun output appears as a URL→parameter mapping, a single parameter
        # object, or a plain list. Keep the URL association when it exists.
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                if any(key in parsed for key in ("parameters", "params", "param")):
                    values = parsed.get("parameters", parsed.get("params", parsed.get("param")))
                    values = values if isinstance(values, list) else [values]
                    by_target[target] = [str(p).strip() for p in values if str(p).strip()]
                else:
                    for raw_url, values in parsed.items():
                        if not isinstance(values, (list, tuple, str)):
                            continue
                        values_list = values if isinstance(values, (list, tuple)) else [values]
                        by_target[str(raw_url)] = [
                            str(p).strip() for p in values_list if str(p).strip()
                        ]
            elif isinstance(parsed, list):
                by_target[target] = [str(p).strip() for p in parsed if str(p).strip()]
        except json.JSONDecodeError:
            pass
        if not by_target:
            # Fallback: line-per-param (one non-blank line per param name)
            params: list[str] = []
            for line in raw_output.splitlines():
                name = line.strip().strip("[]\"',")
                if name and not name.startswith("#") and not name.startswith("{"):
                    # Heuristic: bare word, not URL
                    if "://" not in name and len(name) < 64 and " " not in name:
                        params.append(name)
            by_target[target] = params
        if not any(by_target.values()):
            return ()
        host_addr = _host_of(target)
        host_node = self.graph.add_host(Host(address=host_addr, source=self.name))
        if host_node not in written:
            written.append(host_node)
        for endpoint_target, params in by_target.items():
            if not params:
                continue
            try:
                self.scope.enforce(_scope_url(endpoint_target))
            except Exception:  # noqa: BLE001 — raw tool lines can contain foreign URLs
                self.audit.record(self.name, "RECON", endpoint_target, "refused_out_of_scope")
                continue
            endpoint_node = self.endpoint_for_target(endpoint_target)
            for param_name in dict.fromkeys(params):
                node = self.graph.add_parameter(
                    endpoint_node,
                    Parameter(
                        name=param_name,
                        location="query",
                        serialization="application/x-www-form-urlencoded",
                        source=self.name,
                        confidence=0.8,
                    ),
                )
                written.append(node)
        return tuple(written)
