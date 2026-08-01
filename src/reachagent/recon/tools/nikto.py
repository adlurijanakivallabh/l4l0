"""nikto signal-gated candidate emitter — vulnerability-claim mode (§9; v1.7/v1.8).

nikto in **vulnerability-claim mode** is invoked ONLY after a server/tech/version
signal already exists in the graph for the class it would claim (§9 named
activation). nikto's *informational* mode is recon-tier (facts) and is Big Task 1's
concern — this module is the claim-emitting half only, and it does not duplicate
the recon path. No server/tech signal → nikto is not invoked (:meth:`has_signal`
False). Every nikto item is a *claim*, re-confirmed independently by ``run_oracle``
before any ``Finding`` — nikto never touches ``write_finding``.

Output parsed: ``-Format json`` — a top-level object with a ``vulnerabilities`` (or
``vulns``) array; each item carries ``msg``/``url``/``method``/``osvdb``/``id``. The
message text implies the class and the §7 oracle that can re-confirm it (a traversal
/ file-exposure message → structural; an injection message → differential). An
unmapped message defaults to structural (retrieval/version-match evidence), so the
claim is always independently re-checkable, never auto-trusted.
"""

from __future__ import annotations

import json

from reachagent.oracles import OracleMechanism
from reachagent.recon.tools.signal_gated import SignalGatedToolRunner
from reachagent.tools.candidate import Candidate, ResponseSignal

# Substring-in-message → (vuln_class, §7 oracle that independently re-confirms it).
# ReachAgent's routing of a nikto CLAIM to the right oracle — not a trust of nikto.
_MESSAGE_ROUTING: tuple[tuple[str, str, OracleMechanism], ...] = (
    ("traversal", "path_traversal", OracleMechanism.STRUCTURAL),
    ("../", "path_traversal", OracleMechanism.STRUCTURAL),
    ("sql", "sqli", OracleMechanism.DIFFERENTIAL),
    ("xss", "xss_reflected", OracleMechanism.EXECUTION_CONFIRMATION),
    ("cross site scripting", "xss_reflected", OracleMechanism.EXECUTION_CONFIRMATION),
    ("remote file", "ssrf", OracleMechanism.OOB_CALLBACK),
    ("command", "command_injection", OracleMechanism.OOB_CALLBACK),
)


class NiktoRunner(SignalGatedToolRunner):
    """Emit inert candidates from nikto JSON — gated on a graph server/tech signal (§9)."""

    name = "nikto"
    binary = "nikto"

    def has_signal(self, target: str) -> bool:
        """True iff the graph already holds a server/tech/version signal (§9 gate).

        The signal is ReachAgent's OWN recon: a ``Service`` (a scanned port/service,
        e.g. from nmap) or any ``Host``/``Endpoint`` technology/version fingerprint.
        nikto's claims are server/version-driven, so the presence of a mapped service
        or a stack fingerprint is the class signal that gates it. Reads only graph
        facts, never nikto's output.
        """
        service_sig = len(self.graph.services()) > 0
        host_sig = any((h.technology or h.detected_version) for _n, h in self.graph.hosts())
        endpoint_sig = any((e.technology or e.detected_version) for _n, e in self.graph.endpoints())
        return service_sig or host_sig or endpoint_sig

    def command(self, target: str, output_path: str) -> list[str]:
        """``nikto -h <target> -Format json -o <file>`` — JSON vuln claims out.

        Target is a distinct argv element (``shell=False`` in the base), never a
        shell string.
        """
        return ["nikto", "-h", target, "-Format", "json", "-o", output_path]

    def parse(self, target: str, raw_output: str) -> tuple[Candidate, ...]:
        """Parse nikto JSON ``vulnerabilities[]`` into inert candidates (never a finding).

        Each item → one ``Candidate`` tagged with the class + §7 oracle its message
        implies, carrying the msg/url/osvdb as unverified provenance. A missing/empty
        vulnerabilities array yields no candidates.
        """
        candidates: list[Candidate] = []
        parsed = json.loads(raw_output) if raw_output.strip() else {}
        report = _first_report(parsed)
        vulns = report.get("vulnerabilities") or report.get("vulns") or []
        if not isinstance(vulns, list):
            return ()
        for item in vulns:
            if not isinstance(item, dict):
                continue
            msg = str(item.get("msg") or item.get("message") or "").strip()
            url = str(item.get("url") or target).strip()
            osvdb = str(item.get("osvdb") or item.get("id") or "").strip()
            vuln_class, oracle = _route_message(msg)
            candidates.append(
                Candidate(
                    identity="nikto-signal-gated",
                    endpoint_node=url or target,
                    param_node=None,
                    vuln_class=vuln_class,
                    suggested_oracle=oracle,
                    payload_ref=None,
                    signal=ResponseSignal(status_code=0, body_length=0, elapsed_seconds=0.0),
                    notes=(
                        f"nikto CLAIM (unverified): osvdb={osvdb} msg={msg[:80]}",
                        "requires independent run_oracle re-confirmation before any Finding",
                    ),
                )
            )
        return tuple(candidates)


def _first_report(parsed: object) -> dict[str, object]:
    """Normalise nikto JSON to a single report dict (it may be an object or a list).

    Some nikto builds wrap the report in a list of host scans; take the first dict.
    Anything else yields an empty report (no candidates), never a crash.
    """
    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, list):
        for item in parsed:
            if isinstance(item, dict):
                return item
    return {}


def _route_message(msg: str) -> tuple[str, OracleMechanism]:
    """Map a nikto message to (vuln_class, §7 oracle) for independent re-confirmation.

    First matching keyword wins; an unmapped message defaults to
    ``(server_misconfiguration, structural)`` — retrieval/version-match evidence,
    still handed to a real §7 family for re-confirmation, never auto-trusted.
    """
    lowered = msg.lower()
    for keyword, vuln_class, oracle in _MESSAGE_ROUTING:
        if keyword in lowered:
            return vuln_class, oracle
    return "server_misconfiguration", OracleMechanism.STRUCTURAL
