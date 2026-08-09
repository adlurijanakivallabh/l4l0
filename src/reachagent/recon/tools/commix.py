"""Commix signal-gated candidate emitter — command injection claims, gated on SHELL (§9).

Commix is invoked ONLY after ReachAgent's own probe raised a SHELL-class signal —
a Parameter with inferred_sink_type == shell (set by fingerprint_parameter). No
such signal → commix not a candidate source (has_signal False). Commix's verdict
is never trusted: results become inert command_injection Candidates the
Validator's run_oracle (oob_callback) must independently re-confirm.

Output parsed: commix text/CSV with vulnerable parameter lines.
Each finding → one command_injection Candidate routed to OOB_CALLBACK.
"""

from __future__ import annotations

import csv
import io
import re

from reachagent.graph.nodes import SinkType
from reachagent.oracles import OracleMechanism
from reachagent.recon.tools.signal_gated import SignalGatedToolRunner
from reachagent.tools.candidate import Candidate, ResponseSignal

_VULN_RE = re.compile(r"parameter\s+['\"]?(?P<param>\w+)['\"]?\s+.*vulnerable", re.IGNORECASE)


class CommixRunner(SignalGatedToolRunner):
    """Emit inert command_injection candidates from commix output — gated on SHELL (§9)."""

    name = "commix"
    binary = "commix"

    def has_signal(self, target: str) -> bool:
        """True iff graph already holds a SHELL-class signal (§9 gate).

        ReachAgent's OWN probe: a Parameter with inferred_sink_type == shell.
        No such parameter → commix is not invoked.
        """
        return any(
            param.inferred_sink_type is SinkType.SHELL
            for _ep_node, _ep in self.graph.endpoints()
            for _p_node, param in self.graph.parameters_of(_ep_node)
        )

    def command(self, target: str, output_path: str) -> list[str]:
        """commix --url <target> --batch --output-dir <dir> — claims to output dir."""
        return ["commix", "--url", target, "--batch", "--output-dir", output_path]

    def parse(self, target: str, raw_output: str) -> tuple[Candidate, ...]:
        """Parse commix text/CSV into inert command_injection candidates (never a finding)."""
        candidates: list[Candidate] = []
        # Try CSV first (commix results CSV has Parameter column)
        try:
            reader = csv.DictReader(io.StringIO(raw_output))
            if reader.fieldnames and any(
                "param" in h.lower() or "parameter" in h.lower() for h in reader.fieldnames
            ):
                for row in reader:
                    param = (
                        row.get("Parameter") or row.get("parameter") or row.get("param") or ""
                    ).strip()
                    if not param:
                        continue
                    candidates.append(
                        Candidate(
                            identity="commix",
                            endpoint_node=target,
                            param_node=param,
                            vuln_class="command_injection",
                            suggested_oracle=OracleMechanism.OOB_CALLBACK,
                            payload_ref=None,
                            signal=ResponseSignal(
                                status_code=0, body_length=0, elapsed_seconds=0.0, error_strings=()
                            ),
                            notes=("commix CLAIM (unverified) — requires oob_callback oracle",),
                        )
                    )
                if candidates:
                    return tuple(candidates)
        except Exception:  # noqa: BLE001, S110 — CSV parse best-effort, text fallback below
            pass
        # Fallback: text lines like "parameter 'foo' appears to be vulnerable"
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            match = _VULN_RE.search(line)
            if match:
                param = match.group("param")
                candidates.append(
                    Candidate(
                        identity="commix",
                        endpoint_node=target,
                        param_node=param,
                        vuln_class="command_injection",
                        suggested_oracle=OracleMechanism.OOB_CALLBACK,
                        payload_ref=None,
                        signal=ResponseSignal(
                            status_code=0, body_length=0, elapsed_seconds=0.0, error_strings=()
                        ),
                        notes=("commix CLAIM (unverified) — requires oob_callback oracle",),
                    )
                )
            elif "vulnerable" in line.lower() and "parameter" in line.lower():
                candidates.append(
                    Candidate(
                        identity="commix",
                        endpoint_node=target,
                        param_node=None,
                        vuln_class="command_injection",
                        suggested_oracle=OracleMechanism.OOB_CALLBACK,
                        payload_ref=None,
                        signal=ResponseSignal(
                            status_code=0, body_length=0, elapsed_seconds=0.0, error_strings=()
                        ),
                        notes=("commix CLAIM (unverified) — requires oob_callback oracle",),
                    )
                )
        return tuple(candidates)
