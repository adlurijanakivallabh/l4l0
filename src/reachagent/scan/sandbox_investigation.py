"""LLM-driven sandbox investigation (v4 R3 slice 2).

The autonomous loop's own decision to run a genuinely free-form command
inside the per-scan sandbox (R4, `sandbox/agent_shell.py`) for deeper
investigation beyond what a vuln class's structured driver covers — no
allowlist, no flag validation, the LLM composes the full command line
itself. Any resulting lead is independently judged before becoming a
Finding, the same two-step propose->run_oracle shape as
`scan/llm_vuln_review.py`: a source proposes, `run_oracle` decides.

Fails open at every step (no client configured, sandbox unavailable, the
command errors, the proposal declines) — this is additive investigation on
top of the structured drivers' own coverage, never a replacement for it and
never something a failure here should abort the scan over.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from reachagent.graph.nodes import Finding
from reachagent.graph.store import ReachabilityGraph
from reachagent.llm.client import build_openai_compatible_client
from reachagent.oracles import OracleMechanism
from reachagent.oracles.surface_judgment import SurfaceJudgmentEvidence
from reachagent.sandbox.agent_shell import AgentSandbox
from reachagent.tools import validator

if TYPE_CHECKING:
    from reachagent.scan.orchestrator import ScanEvent

_log = logging.getLogger(__name__)

_MAX_ENDPOINTS_IN_PROMPT = 30
_MAX_COMMAND_CHARS = 2000
_MAX_OUTPUT_IN_EVIDENCE = 3000
_COMMAND_TIMEOUT_S = 60.0

# Stated plainly, matching R4's own design: what's available, not how to use
# it — the model reads --help/man itself, exactly like a human operator
# would. No per-tool flag table to maintain.
_SANDBOX_CONTEXT = (
    "You have a disposable Linux container with these tools installed: nmap, "
    "feroxbuster, hydra, john, ffuf, sqlmap, curl, python3, git. Run `<tool> "
    "--help` or `man <tool>` if you're unsure of flags. Wordlists are under "
    "/usr/share/seclists/. Technique write-ups and further payload files are "
    "under /opt/PayloadsAllTheThings/. The container can reach the assessment "
    "target directly; nothing else."
)

_PROPOSE_PROMPT = (
    "You are an experienced pentester deciding whether a sandboxed shell command "
    "would help investigate a specific vulnerability class on an AUTHORIZED target, "
    "beyond what the built-in structured detector already tried. Only propose a "
    "command if it would genuinely add investigative value — a targeted nmap "
    "script, a feroxbuster/ffuf pass with a specific wordlist, a hydra/john run "
    "against captured material, an sqlmap pass against a specific parameter, or "
    "similar. If nothing in the sandbox would meaningfully add to what's already "
    "known, decline.\n\n"
    f"{_SANDBOX_CONTEXT}\n\n"
    "Vulnerability class under investigation: {vuln_class}\n"
    "Target: {target}\n"
    "Host technology: {tech}\n"
    "Already tried by the structured detector: {prior_outcome}\n"
    "Relevant discovered endpoints:\n{endpoints}\n\n"
    'Reply ONLY as JSON: {{"propose": true|false, "command": "the exact shell '
    'command to run, or empty if propose is false", "rationale": "one short '
    'sentence", "severity": "critical|high|medium|low|info (only meaningful '
    'if this actually confirms a real vulnerability)"}}.'
)

_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_DEFAULT_SEVERITY = "medium"


@dataclass(frozen=True)
class SandboxProposal:
    """A validated (non-empty, bounded) proposed command, or a decline."""

    propose: bool
    command: str
    rationale: str
    severity: str = _DEFAULT_SEVERITY


def _clean(value: object, *, maximum: int) -> str:
    return str(value or "").replace("\n", " ").replace("\r", " ").strip()[:maximum]


def _endpoint_digest(
    graph: ReachabilityGraph, *, max_endpoints: int = _MAX_ENDPOINTS_IN_PROMPT
) -> str:
    endpoints = sorted(graph.endpoints(), key=lambda pair: pair[1].path)
    lines = [f"{ep.method} {ep.path}" for _node, ep in endpoints[:max_endpoints]]
    if len(endpoints) > max_endpoints:
        lines.append(f"... ({len(endpoints) - max_endpoints} more omitted)")
    return "\n".join(lines) or "(no endpoints discovered)"


def _host_tech(graph: ReachabilityGraph) -> str:
    for _node, host in graph.hosts():
        if getattr(host, "technology", None):
            return str(host.technology)[:200]
    return "unknown"


def propose_sandbox_command(
    vuln_class: str,
    graph: ReachabilityGraph,
    target: str,
    *,
    prior_outcome: str = "no signal",
    client: object | None = None,
) -> SandboxProposal | None:
    """One bounded call: propose a sandbox command for ``vuln_class``, or decline.

    Returns ``None`` on any failure or when no provider is configured — a
    strategy convenience, never something a scan should abort over.
    """
    try:
        proposer = client if client is not None else build_openai_compatible_client()
        if proposer is None:
            return None
        prompt = _PROPOSE_PROMPT.format(
            vuln_class=vuln_class,
            target=target[:500],
            tech=_host_tech(graph),
            prior_outcome=prior_outcome[:300],
            endpoints=_endpoint_digest(graph),
        )
        raw = proposer.propose_json(prompt, max_tokens=800)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001 — proposal failure must never break the scan
        _log.warning("sandbox proposal failed (%s); skipping", exc)
        return None
    if not isinstance(raw, dict):
        return None
    if raw.get("propose") is not True:
        return SandboxProposal(
            propose=False, command="", rationale=_clean(raw.get("rationale"), maximum=200)
        )
    command = _clean(raw.get("command"), maximum=_MAX_COMMAND_CHARS)
    if not command:
        return SandboxProposal(propose=False, command="", rationale="empty command")
    severity = _clean(raw.get("severity"), maximum=20).lower()
    if severity not in _VALID_SEVERITIES:
        severity = _DEFAULT_SEVERITY
    return SandboxProposal(
        propose=True,
        command=command,
        rationale=_clean(raw.get("rationale"), maximum=200),
        severity=severity,
    )


def run_sandbox_investigation(
    *,
    vuln_class: str,
    graph: ReachabilityGraph,
    sandbox: AgentSandbox,
    target: str,
    prior_outcome: str = "no signal",
    client: object | None = None,
    events: list[ScanEvent] | None = None,
) -> int:
    """Propose one sandbox command for ``vuln_class``, run it, judge the output.

    Returns 1 if a new ``Finding`` was written, 0 otherwise (declined,
    command produced nothing judgment-worthy, or any step failed). Never
    raises — every failure mode degrades to 0, matching every other
    LLM-driven review pass in this codebase. ``client``, once resolved, is
    reused for BOTH the propose call and the confirmation judgment (one
    client, not one build per stage) — the same pattern
    ``llm_vuln_review.py`` uses, and needed here too: without it, a
    caller relying on the default (``client=None``, "use the scan's
    configured provider") gets two independently-built client objects
    instead of one, which is both wasteful and breaks a caller that
    injects a client but expects it honored for both stages.
    """
    try:
        resolved_client = client if client is not None else build_openai_compatible_client()
        if resolved_client is None:
            return 0
        proposal = propose_sandbox_command(
            vuln_class, graph, target, prior_outcome=prior_outcome, client=resolved_client
        )
        if proposal is None or not proposal.propose:
            return 0
        result = sandbox.run_command(proposal.command, timeout=_COMMAND_TIMEOUT_S)
        output = result.output.strip()
        if not output:
            return 0
        surface_context = (
            f"$ {proposal.command}\n(exit={result.exit_code}"
            f"{', timed out' if result.timed_out else ''})\n"
            f"{output[:_MAX_OUTPUT_IN_EVIDENCE]}"
        )
        evidence = SurfaceJudgmentEvidence(
            vuln_class=vuln_class,
            endpoint=target,
            location="sandbox",
            reason=proposal.rationale or "sandbox command output",
            surface_context=surface_context,
            evidence_ref=f"sandbox/{vuln_class}/{proposal.command[:80]}",
        )
        verdict = validator.run_oracle(OracleMechanism.STRUCTURAL, evidence, client=resolved_client)
    except Exception as exc:  # noqa: BLE001 — investigation must never break the scan
        _log.warning("sandbox investigation failed (%s); no finding added", exc)
        return 0
    if not verdict.is_violation:
        return 0
    # "info" is this module's own prompt-facing severity word (matches
    # llm_vuln_review.py's exact choice); the rest of the codebase's Finding
    # severity vocabulary spells it "informational" — translate at the
    # Finding-construction boundary, same fix R1 already applied there.
    report_severity = "informational" if proposal.severity == "info" else proposal.severity
    finding = Finding(
        vuln_class=vuln_class, severity=report_severity, oracle_used="", evidence_ref=""
    )
    try:
        node_id = validator.write_finding(graph, finding, verdict)
    except Exception as exc:  # noqa: BLE001 — write failure must never break the scan
        _log.warning("sandbox investigation write_finding failed (%s); lead dropped", exc)
        return 0
    if events is not None:
        from reachagent.scan.orchestrator import ScanEvent as _ScanEvent

        events.append(
            _ScanEvent(
                phase="payloads",
                kind="finding",
                message=f"sandbox investigation confirmed: {vuln_class} ({proposal.command[:80]})",
                details={"vuln_class": vuln_class, "finding": node_id, "command": proposal.command},
            )
        )
    return 1
