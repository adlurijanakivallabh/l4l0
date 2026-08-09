"""Dalfox signal-gated candidate emitter — XSS claims, gated on html_reflection (§9).

Dalfox is invoked ONLY after ReachAgent's own probe raised an XSS-class signal —
a Parameter with inferred_sink_type == html_reflection (set by fingerprint_parameter,
§9 step 1). No such signal → dalfox not a candidate source (has_signal False).
Dalfox's verdict is never trusted: results become inert xss_reflected Candidates
the Validator's run_oracle (execution_confirmation) must independently re-confirm.

Output parsed: JSON lines per finding with fields url, payload, evidence/param.
Each finding → one xss_reflected Candidate routed to execution_confirmation.
"""

from __future__ import annotations

import json

from reachagent.graph.nodes import SinkType
from reachagent.oracles import OracleMechanism
from reachagent.recon.tools.signal_gated import SignalGatedToolRunner
from reachagent.tools.candidate import Candidate, ResponseSignal


class DalfoxRunner(SignalGatedToolRunner):
    """Emit inert xss_reflected candidates from dalfox JSON — gated on html_reflection (§9)."""

    name = "dalfox"
    binary = "dalfox"

    def has_signal(self, target: str) -> bool:
        """True iff graph already holds an XSS-class signal (§9 gate).

        ReachAgent's OWN probe: a Parameter with html_reflection sink (XSS heuristic)
        or an endpoint with XSS-like technology hint. No signal → dalfox not invoked.
        """
        for _ep_node, _ep in self.graph.endpoints():
            for _p_node, param in self.graph.parameters_of(_ep_node):
                if param.inferred_sink_type is SinkType.HTML_REFLECTION:
                    return True
        # Fallback: endpoint technology mentioning xss (defense-in-depth)
        for _ep_node, ep in self.graph.endpoints():
            if ep.technology and "xss" in ep.technology.lower():
                return True
        return False

    def command(self, target: str, output_path: str) -> list[str]:
        """dalfox url <target> --format json --silence — JSON claims to stdout."""
        return ["dalfox", "url", target, "--format", "json", "--silence"]

    def parse(self, target: str, raw_output: str) -> tuple[Candidate, ...]:
        """Parse dalfox JSON lines into inert xss_reflected candidates (never a finding)."""
        candidates: list[Candidate] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            url = str(obj.get("url", target))
            payload = str(obj.get("payload", obj.get("evidence", "")))
            candidates.append(
                Candidate(
                    identity="dalfox",
                    endpoint_node=url,
                    param_node=None,
                    vuln_class="xss_reflected",
                    suggested_oracle=OracleMechanism.EXECUTION_CONFIRMATION,
                    payload_ref=None,
                    signal=ResponseSignal(
                        status_code=0, body_length=0, elapsed_seconds=0.0, error_strings=()
                    ),
                    notes=("dalfox CLAIM (unverified) — requires execution_confirmation oracle",),
                )
            )
            # Keep payload provenance in param if present
            _ = payload  # provenance, not trusted
        return tuple(candidates)
