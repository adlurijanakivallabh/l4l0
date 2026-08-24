"""feroxbuster recon wrapper — discovered URLs as Endpoint facts (§9 recon tier).

feroxbuster in JSON mode emits one JSON object per line with url + status fields.
Per §6/§9 each discovered path is an Endpoint + resolves_to edge. Mirror
gobuster.py. Facts only.
"""

from __future__ import annotations

import json
import os

from reachagent.graph.nodes import Endpoint, Host
from reachagent.recon.calibration import CalibrationResult
from reachagent.recon.tools._wordlist import preferred_wordlist
from reachagent.recon.tools.base import ReconToolRunner, _recon_host_of, _recon_path_of
from reachagent.recon.tools.gobuster import _restricted_status

_host_of = _recon_host_of  # ponytail: deduped to base helper


_path_of = _recon_path_of  # ponytail: deduped to base helper


class FeroxbusterRunner(ReconToolRunner):
    """Emit Endpoint per feroxbuster-discovered URL + resolves_to edge (§9). Facts only."""

    name = "feroxbuster"
    binary = "feroxbuster"

    def command(self, target: str) -> list[str]:
        """feroxbuster --url <target> --silent --json -o <file> — JSON to file."""
        import tempfile

        from reachagent.recon.live_tuning import profile_argv  # ponytail: 5× copy → 1

        if (profile := profile_argv(target, [])) is not None:
            fd, path = tempfile.mkstemp(suffix=".json", prefix="ferox-")  # noqa: S108
            os.close(fd)
            argv: list[str] = [
                "feroxbuster",
                "--url",
                target,
                "--silent",
                "--json",
                "-o",
                path,
                "-w",
                profile.wordlist,
            ]
            argv += list(profile.flags)
            threads = os.environ.get("REACHAGENT_FEROX_THREADS")
            if threads and threads.isdigit() and "-t" not in argv:
                argv += ["-t", threads]
            return argv
        fd, path = tempfile.mkstemp(suffix=".json", prefix="ferox-")  # noqa: S108 — mkstemp safe temp
        os.close(fd)
        argv: list[str] = ["feroxbuster", "--url", target, "--silent", "--json", "-o", path]  # type: ignore[no-redef]
        wordlist = preferred_wordlist("REACHAGENT_FEROX_WORDLIST")
        # Forward -w when explicitly set or richer default found
        if (
            os.environ.get("REACHAGENT_FEROX_WORDLIST")
            or wordlist != "/usr/share/wordlists/dirb/common.txt"
        ):
            argv += ["-w", wordlist]
        threads = os.environ.get("REACHAGENT_FEROX_THREADS")
        if threads and threads.isdigit():
            argv += ["-t", threads]
        return argv

    # Set by the scan entrypoint before ingest (D3 pass-through).
    calibration: CalibrationResult | None = None

    def parse(
        self, target: str, raw_output: str, calibration: CalibrationResult | None = None
    ) -> tuple[str, ...]:
        """Parse feroxbuster JSON lines into Endpoint nodes + resolves_to edges.

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
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            url = str(obj.get("url", ""))
            if not url:
                continue
            if cal is not None and cal.wildcard:
                self.audit.record(self.name, "RECON", target, "refused_wildcard_catchall")
                continue
            path = _path_of(url)
            if path in seen_paths:
                continue
            seen_paths.add(path)
            status_raw = obj.get("status")
            access = None
            if isinstance(status_raw, int) and _restricted_status(status_raw):
                access = str(status_raw)
                self.audit.record(self.name, "RECON", target, f"discovered_restricted:{status_raw}")
            endpoint_node = self.graph.add_endpoint(
                Endpoint(method="GET", path=path, access_restricted=access)
            )
            self.graph.add_resolves_to(host_node, endpoint_node)
            written.append(endpoint_node)
        return tuple(written)
