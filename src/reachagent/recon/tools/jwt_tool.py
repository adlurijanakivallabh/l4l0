"""JWT-Tool signal-gated candidate emitter — JWT forgery claims, gated on auth/JWT (§9).

JWT-Tool is invoked ONLY after ReachAgent's own graph holds a JWT/auth-endpoint
signal — any Endpoint path containing auth/login/jwt or Host technology mentioning
jwt. No such signal → jwt-tool not a candidate source (has_signal False).
JWT-Tool's verdict is never trusted: results become inert jwt_forgery Candidates
the Validator's run_oracle (structural JWT_FORGERY) must independently re-confirm.

Output parsed: text/JSON with alg confusion / none-algorithm mentions.
Each finding → one jwt_forgery Candidate routed to STRUCTURAL.
"""

from __future__ import annotations

import json

from reachagent.oracles import OracleMechanism
from reachagent.recon.tools.signal_gated import SignalGatedToolRunner
from reachagent.tools.candidate import Candidate, ResponseSignal


def _has_jwt_signal(graph) -> bool:  # type: ignore[no-untyped-def]
    for _ep_node, ep in graph.endpoints():
        path = ep.path.lower()
        if any(kw in path for kw in ("auth", "login", "jwt", "token", "session")):
            return True
    for _n, host in graph.hosts():
        if host.technology and "jwt" in host.technology.lower():
            return True
    return False


class JwtToolRunner(SignalGatedToolRunner):
    """Emit inert jwt_forgery candidates from jwt_tool output — gated on JWT/auth (§9)."""

    name = "jwt-tool"
    binary = "python3"

    def has_signal(self, target: str) -> bool:
        """True iff graph holds a JWT/auth-endpoint signal (§9 gate)."""
        return _has_jwt_signal(self.graph)

    def command(self, target: str, output_path: str) -> list[str]:
        """python3 /home/kali/jwt_tool/jwt_tool.py -t <target> — JWT analysis."""
        import os

        jwt_path = os.environ.get("REACHAGENT_JWT_TOOL_PATH", "/home/kali/jwt_tool/jwt_tool.py")
        return ["python3", jwt_path, "-t", target]

    def parse(self, target: str, raw_output: str) -> tuple[Candidate, ...]:
        """Parse jwt_tool text/JSON into inert jwt_forgery candidates (never a finding)."""
        text_lower = raw_output.lower()
        has_alg_none = "none" in text_lower and "alg" in text_lower
        has_confusion = "confusion" in text_lower or "key confusion" in text_lower
        has_weak = "weak" in text_lower and "secret" in text_lower
        has_valid_claim = has_alg_none or has_confusion or has_weak
        # Also try JSON with findings array
        try:
            parsed = json.loads(raw_output)
            if isinstance(parsed, dict):
                vulns = parsed.get("vulnerabilities", parsed.get("findings", []))
                if isinstance(vulns, list) and vulns:
                    has_valid_claim = True
                # Legacy jwt_tool JSON may have "results" with "valid"
                if parsed.get("valid") is True:
                    has_valid_claim = True
        except json.JSONDecodeError:
            pass
        if not has_valid_claim:
            # Generic fallback: any JWT-related finding mentioning token
            if "jwt" not in text_lower and "token" not in text_lower:
                return ()
            if not any(kw in text_lower for kw in ("vuln", "exploit", "bypass", "forgery", "alg")):
                return ()
        return (
            Candidate(
                identity="jwt-tool",
                endpoint_node=target,
                param_node=None,
                vuln_class="jwt_forgery",
                suggested_oracle=OracleMechanism.STRUCTURAL,
                payload_ref=None,
                signal=ResponseSignal(
                    status_code=0, body_length=0, elapsed_seconds=0.0, error_strings=()
                ),
                notes=("jwt-tool CLAIM (unverified) — routes through structural JWT oracle",),
            ),
        )
