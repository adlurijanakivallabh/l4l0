"""nuclei signal-gated candidate emitter (§9 signal-gated tier; v1.7/v1.8).

nuclei is invoked ONLY after a class/technology signal already exists in the graph
— a ``Host``/``Endpoint`` ``technology``/``detected_version`` fingerprint, or a
``Service`` version, from Big Task 1's whatweb/nmap recon (§9 named activation:
"template-matched claims only … after a class/technology signal exists"). No
fingerprint → nuclei is not a candidate source here (:meth:`has_signal` False).
nuclei's template match is a *claim*, never trusted: each finding line becomes an
inert ``Candidate`` the Validator's ``run_oracle`` must independently re-confirm.

Output parsed: ``-jsonl`` — one JSON object per line. Read ``template-id`` (also
seen as ``templateID``), ``matched-at``, and ``info.severity`` (severity is nested
under ``info``). The template id implies the vuln class and the §7 oracle family
that can independently re-confirm it (an sqli template → differential; an
xss/rce/ssti template → execution/oob; a traversal/exposure template → structural).
An unmapped template still routes to structural as a conservative default so the
claim is always independently re-checkable, never auto-trusted.
"""

from __future__ import annotations

import json

from reachagent.oracles import OracleMechanism
from reachagent.recon.tools.signal_gated import SignalGatedToolRunner
from reachagent.tools.candidate import Candidate, ResponseSignal

# Substring-in-template-id → (vuln_class, §7 oracle family that re-confirms it).
# Ordered: the first matching keyword wins. This is ReachAgent's routing of a
# nuclei CLAIM to the oracle that must independently confirm it — not a trust of
# nuclei's own severity/verdict.
_TEMPLATE_ROUTING: tuple[tuple[str, str, OracleMechanism], ...] = (
    ("sqli", "sqli", OracleMechanism.DIFFERENTIAL),
    ("sql-injection", "sqli", OracleMechanism.DIFFERENTIAL),
    ("xss", "xss_reflected", OracleMechanism.EXECUTION_CONFIRMATION),
    ("ssti", "ssti", OracleMechanism.EXECUTION_CONFIRMATION),
    ("rce", "command_injection", OracleMechanism.OOB_CALLBACK),
    ("ssrf", "ssrf", OracleMechanism.OOB_CALLBACK),
    ("lfi", "path_traversal", OracleMechanism.STRUCTURAL),
    ("traversal", "path_traversal", OracleMechanism.STRUCTURAL),
    ("exposure", "information_exposure", OracleMechanism.STRUCTURAL),
    ("cve", "cve_match", OracleMechanism.STRUCTURAL),
)


class NucleiRunner(SignalGatedToolRunner):
    """Emit inert candidates from nuclei JSONL — gated on a graph tech signal (§9)."""

    name = "nuclei"
    binary = "nuclei"

    def has_signal(self, target: str) -> bool:
        """True iff the graph already holds a technology/version fingerprint (§9 gate).

        The signal is ReachAgent's OWN recon: any ``Host`` or ``Endpoint`` with a
        ``technology`` or ``detected_version`` attribute, or any ``Service`` with a
        ``detected_version`` (whatweb/nmap, Big Task 1). Reads only graph facts,
        never nuclei's output. No fingerprint → nuclei is not invoked.
        """
        host_sig = any((h.technology or h.detected_version) for _n, h in self.graph.hosts())
        endpoint_sig = any((e.technology or e.detected_version) for _n, e in self.graph.endpoints())
        service_sig = any(s.detected_version for _n, s in self.graph.services())
        return host_sig or endpoint_sig or service_sig

    def command(self, target: str, output_path: str) -> list[str]:
        """``nuclei -u <target> -jsonl -o <file>`` — template-matched claims, JSONL out.

        Target is a distinct argv element (``shell=False`` in the base), never a
        shell string.
        """
        return ["nuclei", "-u", target, "-jsonl", "-o", output_path]

    def parse(self, target: str, raw_output: str) -> tuple[Candidate, ...]:
        """Parse nuclei JSONL into inert candidates (never a finding).

        One JSON object per line; a blank or unparseable line is skipped (the base
        audits an outright failure). Each finding → one ``Candidate`` tagged with the
        class + §7 oracle its template implies, carrying the template id / matched-at
        / severity as unverified provenance.
        """
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
            template_id = str(obj.get("template-id") or obj.get("templateID") or "").strip()
            matched_at = str(obj.get("matched-at") or obj.get("matched") or target).strip()
            info_value = obj.get("info")
            info = info_value if isinstance(info_value, dict) else {}
            severity = str(info.get("severity", "unknown"))
            vuln_class, oracle = _route_template(template_id)
            candidates.append(
                Candidate(
                    identity="nuclei-signal-gated",
                    endpoint_node=matched_at or target,
                    param_node=None,
                    vuln_class=vuln_class,
                    suggested_oracle=oracle,
                    payload_ref=None,
                    signal=ResponseSignal(status_code=0, body_length=0, elapsed_seconds=0.0),
                    notes=(
                        f"nuclei CLAIM (unverified): template={template_id} severity={severity}",
                        "requires independent run_oracle re-confirmation before any Finding",
                    ),
                )
            )
        return tuple(candidates)


def _route_template(template_id: str) -> tuple[str, OracleMechanism]:
    """Map a nuclei template id to (vuln_class, §7 oracle) for independent re-confirm.

    First matching keyword in ``_TEMPLATE_ROUTING`` wins; an unmapped template
    defaults to ``(cve_match, structural)`` — a conservative route that still hands
    the claim to a real §7 family for re-confirmation, never auto-trusts it.
    """
    lowered = template_id.lower()
    for keyword, vuln_class, oracle in _TEMPLATE_ROUTING:
        if keyword in lowered:
            return vuln_class, oracle
    return "cve_match", OracleMechanism.STRUCTURAL
