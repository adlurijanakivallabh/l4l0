"""ffuf recon wrapper — discovered paths as Endpoint facts (§9 recon tier).

ffuf in JSON mode emits {"results":[{"url":"...","status":200},...]}. Per §6/§9
each discovered path is an Endpoint + resolves_to edge. Mirror gobuster.py
directly — same path+status shape. Facts only.
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


class FfufRunner(ReconToolRunner):
    """Emit Endpoint per ffuf-discovered path + resolves_to edge (§9). Facts only."""

    name = "ffuf"
    binary = "ffuf"

    def command(self, target: str) -> list[str]:
        """Build a bounded, non-interactive JSON ffuf invocation."""
        import os as _os2
        import tempfile

        from reachagent.recon.live_tuning import profile_argv  # ponytail: 5× copy → 1

        if (profile := profile_argv(target, [], graph=self.graph)) is not None:
            fd, path = tempfile.mkstemp(suffix=".json", prefix="ffuf-")  # noqa: S108
            _os2.close(fd)
            argv: list[str] = [
                "ffuf",
                "-u",
                target.rstrip("/") + "/FUZZ",
                "-w",
                profile.wordlist,
                "-mc",
                profile.status_codes,
                "-noninteractive",
                "-o",
                path,
                "-of",
                "json",
            ]
            argv += list(profile.flags)
            threads = os.environ.get("REACHAGENT_FFUF_THREADS")
            if threads and threads.isdigit() and "-t" not in argv:
                argv += ["-t", threads]
            return argv
        wordlist = preferred_wordlist("REACHAGENT_FFUF_WORDLIST")
        # Include ACL responses as facts (the parser marks 401/403 restricted);
        # this never turns a response into a vulnerability verdict.
        match_codes = os.environ.get(
            "REACHAGENT_FFUF_MATCH_CODES",
            "200,201,202,204,301,302,307,401,403,405",
        )
        fd, path = tempfile.mkstemp(suffix=".json", prefix="ffuf-")  # noqa: S108 — mkstemp safe temp
        _os2.close(fd)
        argv: list[str] = [  # type: ignore[no-redef]
            "ffuf",
            "-u",
            target.rstrip("/") + "/FUZZ",
            "-w",
            wordlist,
            "-mc",
            match_codes,
            "-noninteractive",
            "-o",
            path,
            "-of",
            "json",
        ]
        threads = os.environ.get("REACHAGENT_FFUF_THREADS")
        if threads and threads.isdigit():
            argv += ["-t", threads]
        rate = os.environ.get("REACHAGENT_FFUF_RATE")
        if rate and rate.isdigit():
            argv += ["-rate", rate]
        timeout = os.environ.get("REACHAGENT_FFUF_TIMEOUT")
        if timeout and timeout.isdigit():
            argv += ["-timeout", timeout]
        if os.environ.get("REACHAGENT_FFUF_AUTO_CALIBRATE", "").lower() in {
            "1",
            "true",
            "yes",
        }:
            argv.append("-ac")
        return argv

    # Set by the scan entrypoint before ingest (D3 pass-through).
    calibration: CalibrationResult | None = None

    def parse(
        self, target: str, raw_output: str, calibration: CalibrationResult | None = None
    ) -> tuple[str, ...]:
        """Parse ffuf JSON results into Endpoint nodes + resolves_to edges.

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
        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError:
            return tuple(written)
        results = parsed.get("results", []) if isinstance(parsed, dict) else []
        if not isinstance(results, list):
            return tuple(written)
        seen_paths: set[str] = set()
        for item in results:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", ""))
            if not url:
                continue
            if cal is not None and cal.wildcard:
                self.audit.record(self.name, "RECON", target, "refused_wildcard_catchall")
                continue
            path = _path_of(url)
            if path in seen_paths:
                continue
            seen_paths.add(path)
            status_raw = item.get("status")
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
