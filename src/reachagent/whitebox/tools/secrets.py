"""TruffleHog secrets wrapper (Build Order 7).

Writes ``Secret`` facts only — the secret VALUE never enters the graph, only
its detector type and location (§10) — never a ``Finding``, never
``run_oracle``. A hit here STEERS live-testing priority (e.g. an endpoint
whose config file leaked a real credential is worth testing first), it never
gates or substitutes for oracle confirmation.

Targets the modern TruffleHog v3 CLI (``trufflehog filesystem <path>
--json``), which emits JSON LINES (one object per line), each shaped like::

    {"SourceMetadata": {"Data": {"Filesystem": {"file": "...", "line": N}}},
     "DetectorName": "AWS", "Verified": true, "Raw": "...", ...}

Disclosed honestly: this exact shape is TruffleHog's own well-documented
public output format, not independently live-verified in every environment —
this session's own sandbox has an older, git-history-only "truffleHog"
(different CLI, no ``filesystem`` subcommand) installed instead, so this
wrapper's live path is hermetically tested against a representative fixture
but has not been run against a real modern binary here. ``Raw``/``RawV2``/
``Redacted`` are deliberately never read, even though they exist on the real
tool's output — the parser only ever touches detector metadata and location.
"""

from __future__ import annotations

import json

from reachagent.graph.nodes import Secret
from reachagent.whitebox.tools.base import SourceToolRunner


class TruffleHogRunner(SourceToolRunner):
    """Runs TruffleHog's filesystem secret scan against a local repo path."""

    name = "trufflehog"
    binary = "trufflehog"

    def command(self, repo_path: str) -> list[str]:
        return ["trufflehog", "filesystem", repo_path, "--json", "--no-update"]

    def parse(self, repo_path: str, raw_output: str) -> tuple[str, ...]:
        nodes: list[str] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            detector = record.get("DetectorName")
            if not isinstance(detector, str) or not detector:
                continue
            metadata = record.get("SourceMetadata", {})
            filesystem = (
                metadata.get("Data", {}).get("Filesystem", {})
                if isinstance(metadata, dict) and isinstance(metadata.get("Data"), dict)
                else {}
            )
            path = filesystem.get("file") if isinstance(filesystem, dict) else None
            line_no = filesystem.get("line") if isinstance(filesystem, dict) else None
            if not isinstance(path, str) or not isinstance(line_no, int):
                continue
            verified = bool(record.get("Verified", False))
            node = self.graph.add_secret(
                Secret(
                    path=path,
                    line=line_no,
                    detector=detector,
                    verified=verified,
                    source=self.name,
                )
            )
            nodes.append(node)
        return tuple(nodes)
