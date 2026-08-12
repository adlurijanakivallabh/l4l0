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
from reachagent.recon.tools.base import ReconToolRunner
from reachagent.recon.tools.gobuster import _restricted_status


def _host_of(target: str) -> str:
    stripped = target.split("://", 1)[-1]
    return stripped.split("/", 1)[0].split(":", 1)[0]


def _path_of(url: str) -> str:
    # Extract path + query from URL
    after_scheme = url.split("://", 1)[-1] if "://" in url else url
    slash = after_scheme.find("/")
    if slash == -1:
        return "/"
    path = after_scheme[slash:]
    # Strip fragment
    path = path.split("#", 1)[0]
    return path or "/"


class FfufRunner(ReconToolRunner):
    """Emit Endpoint per ffuf-discovered path + resolves_to edge (§9). Facts only."""

    name = "ffuf"
    binary = "ffuf"

    def command(self, target: str) -> list[str]:
        """ffuf -u <target>/FUZZ -w <wordlist> -mc 200,204,301,302 -o <file> -of json."""
        import os as _os2
        import tempfile

        wordlist = preferred_wordlist("REACHAGENT_FFUF_WORDLIST")
        # 307 added; 401/403 left as audit TODO (ACL surface, not auto-match)
        match_codes = os.environ.get("REACHAGENT_FFUF_MATCH_CODES", "200,204,301,302,307")
        fd, path = tempfile.mkstemp(suffix=".json", prefix="ffuf-")  # noqa: S108 — mkstemp safe temp
        _os2.close(fd)
        argv: list[str] = [
            "ffuf",
            "-u",
            target.rstrip("/") + "/FUZZ",
            "-w",
            wordlist,
            "-mc",
            match_codes,
            "-o",
            path,
            "-of",
            "json",
        ]
        threads = os.environ.get("REACHAGENT_FFUF_THREADS")
        if threads and threads.isdigit():
            argv += ["-t", threads]
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
