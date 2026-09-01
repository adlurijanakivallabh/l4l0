"""semgrep SAST wrapper (Build Order 7).

Writes ``SourceFile`` facts only — never a ``Finding``, never ``run_oracle``.
A hit here STEERS live-testing priority (folded into the same bounded
``signals`` dict the tech-aware picker already uses); it never gates or
substitutes for oracle confirmation.

Result shape verified against a real local semgrep 1.172.0 run (this
session): ``results[]`` items carry ``check_id``, ``path``,
``start.line``/``end.line``, and ``extra.message``/``extra.severity``.

Network disclosure (adversarial review): ``--config=auto`` resolves its
ruleset from the Semgrep Registry (semgrep.dev) over the network — this
one call is NOT purely local, unlike TruffleHog/SCA's manifest parsing.
``--metrics=off`` is passed explicitly so at least scan telemetry (project
characteristics, timing, rule-match counts) is never phoned home even
though ruleset resolution still is; there is currently no bundled local
ruleset shipped with ReachAgent to avoid the network call entirely, a
disclosed limit, not a silent one — see ``base.py``'s module docstring.
"""

from __future__ import annotations

import json

from reachagent.graph.nodes import SourceFile
from reachagent.whitebox.tools.base import SourceToolRunner

_MAX_MESSAGE = 500


class SemgrepRunner(SourceToolRunner):
    """Runs semgrep's auto-config ruleset against a local repo path.

    ``--config=auto`` reaches the Semgrep Registry over the network to
    resolve which rules apply — a real, disclosed exception to this mode's
    otherwise-local analysis (see module docstring above and
    ``base.py``'s). ``--metrics=off`` suppresses semgrep's own default
    telemetry reporting regardless.
    """

    name = "semgrep"
    binary = "semgrep"

    def command(self, repo_path: str) -> list[str]:
        return [
            "semgrep",
            "--config=auto",
            "--metrics=off",
            "--json",
            "--quiet",
            "--timeout=120",
            repo_path,
        ]

    def parse(self, repo_path: str, raw_output: str) -> tuple[str, ...]:
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return ()
        results = data.get("results", [])
        if not isinstance(results, list):
            return ()
        nodes: list[str] = []
        for result in results:
            if not isinstance(result, dict):
                continue
            path = result.get("path")
            check_id = result.get("check_id")
            start = result.get("start", {})
            line = start.get("line") if isinstance(start, dict) else None
            if not isinstance(path, str) or not isinstance(check_id, str):
                continue
            if not isinstance(line, int):
                continue
            extra = result.get("extra", {}) if isinstance(result.get("extra"), dict) else {}
            message = str(extra.get("message", ""))[:_MAX_MESSAGE]
            severity = str(extra.get("severity", "info")).lower()
            node = self.graph.add_source_file(
                SourceFile(
                    path=path,
                    rule_id=check_id,
                    line=line,
                    message=message,
                    severity=severity,
                    source=self.name,
                )
            )
            nodes.append(node)
        return tuple(nodes)
