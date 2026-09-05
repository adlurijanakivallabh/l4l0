"""Concrete scan tools bound to the real services (firer, runtime, graph)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import cast

from ..agent.tools import FunctionTool, ToolRegistry, ToolResult
from ..confirmation.scoring import score_finding
from ..core.redaction import redact
from ..execution.firer import HttpFirer
from ..graph.store import ReachGraph
from ..models import Evidence, EvidenceKind, Finding, Severity
from ..runtime.container import RuntimeContainer

ToolFunc = Callable[[dict[str, object]], ToolResult]

_MAX_OBS = 800


@dataclass
class ScanContext:
    graph: ReachGraph
    firer: HttpFirer
    container: RuntimeContainer | None = None
    captures: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    _fire_seq: int = 0


def _severity(value: object) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError:
        return Severity.MEDIUM


def _evidence_kind(value: object) -> EvidenceKind:
    try:
        return EvidenceKind(str(value).lower())
    except ValueError:
        return EvidenceKind.STRUCTURAL


def _http_tool(ctx: ScanContext) -> ToolFunc:
    def run(args: dict[str, object]) -> ToolResult:
        method = str(args.get("method", "GET")).upper()
        url = str(args.get("url", ""))
        raw_headers = args.get("headers")
        headers = (
            {str(k): str(v) for k, v in raw_headers.items()}
            if isinstance(raw_headers, dict)
            else None
        )
        body = args.get("body")
        content = body.encode("utf-8") if isinstance(body, str) else None
        result = ctx.firer.fire(method, url, headers=headers, content=content)
        ctx.graph.add_endpoint(url, method)
        if not result.fired:
            return ToolResult(f"not fired (scope: {result.scope_reason})", ok=False)
        if result.error:
            return ToolResult(f"transport error: {result.error}", ok=False)
        ref = f"fire{ctx._fire_seq}"
        ctx._fire_seq += 1
        body_text = result.body.decode("utf-8", "replace")
        ctx.captures[ref] = body_text
        snippet = redact(body_text[:_MAX_OBS])
        return ToolResult(
            f"[fire_ref={ref}] status={result.status} len={len(result.body)}\n{snippet}"
        )

    return run


def _record_tool(ctx: ScanContext) -> ToolFunc:
    def run(args: dict[str, object]) -> ToolResult:
        raw_evidence = args.get("evidence")
        evidence: list[Evidence] = []
        if isinstance(raw_evidence, list):
            for item in raw_evidence:
                if not isinstance(item, dict):
                    continue
                entry = cast("dict[str, object]", item)
                fire_ref = entry.get("fire_ref")
                evidence.append(
                    Evidence(
                        kind=_evidence_kind(entry.get("kind")),
                        summary=str(entry.get("summary", "")),
                        fire_ref=str(fire_ref) if fire_ref else None,
                        observed=str(entry.get("observed", "")),
                    )
                )
        finding = Finding.create(
            title=str(args.get("title", "untitled")),
            vuln_class=str(args.get("vuln_class", "unknown")),
            severity=_severity(args.get("severity")),
            target=str(args.get("target", "")),
            evidence=evidence,
        )
        breakdown = score_finding(finding, captures=ctx.captures)
        ctx.graph.add_finding(finding)
        flags = f" flags={breakdown.flags}" if breakdown.flags else ""
        return ToolResult(
            f"recorded finding {finding.id[:8]} '{finding.title}' "
            f"confidence={breakdown.total}{flags}"
        )

    return run


def _run_command_tool(ctx: ScanContext) -> ToolFunc:
    # Intentional free shell (the core L4L0 execution model): the agent may run
    # ANY command — no allowlist, no argv restriction — because that freedom never
    # reaches the host. `exec` runs ONLY inside the disposable, host-isolated
    # runtime container (no host mounts, no docker socket, cap-drop ALL,
    # no-new-privileges; see runtime/container.py). There is deliberately no
    # host-shell path: the tool is unavailable unless such a container exists, so a
    # prompt-injected command from a target response can at worst dirty the
    # throwaway container, never the operator's machine. See CLAUDE.md "Safety
    # posture". This is the accepted, operator-chosen tradeoff, not an oversight.
    def run(args: dict[str, object]) -> ToolResult:
        if ctx.container is None:
            return ToolResult("run_command unavailable: no runtime container", ok=False)
        cmd = str(args.get("cmd", ""))
        result = ctx.container.exec(cmd)  # contained: runs inside the isolated container only
        output = redact((result.stdout + result.stderr)[:_MAX_OBS])
        return ToolResult(f"exit={result.exit_code}\n{output}", ok=result.ok)

    return run


def _note_tool(ctx: ScanContext) -> ToolFunc:
    def run(args: dict[str, object]) -> ToolResult:
        ctx.notes.append(str(args.get("text", "")))
        return ToolResult("noted")

    return run


def build_registry(ctx: ScanContext) -> ToolRegistry:
    tools = [
        FunctionTool(
            "http",
            "Fire an HTTP request against an in-scope target. "
            "args: method, url, headers?(obj), body?(str). Returns status, length, "
            "a body snippet, and a fire_ref to cite as evidence.",
            _http_tool(ctx),
        ),
        FunctionTool(
            "record_finding",
            "Record a vulnerability. args: title, vuln_class, "
            "severity(info|low|medium|high|critical), target, "
            "evidence:[{kind,summary,fire_ref,observed}]. Confidence is scored "
            "against captured traffic; nothing is withheld.",
            _record_tool(ctx),
        ),
        FunctionTool("note", "Save a short note. args: text", _note_tool(ctx)),
    ]
    if ctx.container is not None:
        tools.append(
            FunctionTool(
                "run_command",
                "Run a shell command in the isolated sandbox (any tool). args: cmd",
                _run_command_tool(ctx),
            )
        )
    return ToolRegistry(tools)
