"""dirb recon wrapper — discovered paths as Endpoint facts (§9 recon tier).

dirb text output emits lines like "+ http://host/path (CODE:200|SIZE:...)" — one
discovered path per matching line. Per §6/§9 each is an Endpoint + resolves_to
edge. Mirror gobuster.py. Facts only.
"""

from __future__ import annotations

import re

from reachagent.graph.nodes import Endpoint, Host
from reachagent.recon.calibration import CalibrationResult
from reachagent.recon.tools._wordlist import preferred_wordlist
from reachagent.recon.tools.base import ReconToolRunner, _recon_host_of, _recon_path_of
from reachagent.recon.tools.gobuster import _restricted_status

_RESULT = re.compile(r"^\+\s+https?://[^/]+(?P<path>/\S*)\s+\(CODE:(?P<code>\d+)")
_ALT_RESULT = re.compile(r"^\+\s+(?P<url>https?://\S+)\s+\(CODE:(?P<code>\d+)")


_host_of = _recon_host_of  # ponytail: deduped to base helper


_path_of_url = _recon_path_of  # ponytail: deduped to base helper


class DirbRunner(ReconToolRunner):
    """Emit Endpoint per dirb-discovered path + resolves_to edge (§9). Facts only."""

    name = "dirb"
    binary = "dirb"

    def command(self, target: str) -> list[str]:
        """dirb <target> <wordlist> -S — silent, results to stdout."""
        from reachagent.recon.live_tuning import profile_argv  # ponytail: 5× copy → 1

        if (profile := profile_argv(target, [])) is not None:
            return ["dirb", target, profile.wordlist, "-S"]
        wordlist = preferred_wordlist("REACHAGENT_DIRB_WORDLIST")
        return ["dirb", target, wordlist, "-S"]

    # Set by the scan entrypoint before ingest (D3 pass-through).
    calibration: CalibrationResult | None = None

    def parse(
        self, target: str, raw_output: str, calibration: CalibrationResult | None = None
    ) -> tuple[str, ...]:
        """Parse dirb + http:// lines into Endpoint nodes + resolves_to edges.

        Wildcard catch-all (D2): discovered paths are untrustworthy — each result
        is audited ``refused_wildcard_catchall``, no Endpoint is asserted.
        """
        cal = calibration if calibration is not None else self.calibration
        technology = f"wildcard_shape:{cal.shape_label}" if cal is not None else None
        written: list[str] = []
        host_addr = _host_of(target)
        host_node = self.graph.add_host(
            Host(address=host_addr, source=self.name, technology=technology)
        )
        written.append(host_node)
        seen_paths: set[str] = set()
        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            match = _RESULT.match(stripped)
            if match is None:
                match = _ALT_RESULT.match(stripped)
            if match is None:
                continue
            if cal is not None and cal.wildcard:
                self.audit.record(self.name, "RECON", target, "refused_wildcard_catchall")
                continue
            path = match.group("path") if "path" in match.groupdict() else None
            if path is None:
                url = match.group("url")
                path = _path_of_url(url)
            if path in seen_paths:
                continue
            seen_paths.add(path)
            code_raw = match.group("code")
            access = None
            if code_raw and _restricted_status(int(code_raw)):
                access = code_raw
                self.audit.record(self.name, "RECON", target, f"discovered_restricted:{code_raw}")
            endpoint_node = self.graph.add_endpoint(
                Endpoint(method="GET", path=path, access_restricted=access)
            )
            self.graph.add_resolves_to(host_node, endpoint_node)
            written.append(endpoint_node)
        return tuple(written)
