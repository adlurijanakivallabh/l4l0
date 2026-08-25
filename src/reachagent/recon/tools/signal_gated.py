"""Signal-gated exploitation-tool base: gated candidate-emitters (§9, §13; v1.7/v1.8).

Signal-gated tools (sqlmap, nuclei, nikto in vulnerability-claim mode) sit one tier
above recon (§9). A recon tool emits a *fact* straight into the graph; a
signal-gated tool emits a *claim* of a vulnerability — and a claim is never
trusted. The §9 flow this module enforces, end to end:

    existing graph signal for the class   (the "gated" in signal-gated)
      → invoke the tool (only when gated)
      → parse the tool's CLAIM into an inert Explorer ``Candidate``
      → the Validator's ``run_oracle`` re-confirms it *independently*
      → a ``Finding`` is written ONLY on that independent ``is_violation`` verdict

A claim ReachAgent's own oracle does not independently confirm is dropped — never
written as a ``Finding``. That is the whole reason this tier exists (§9): a
sqlmap/nuclei/nikto false positive must not become a finding. So these wrappers:

  * are **gated** — :meth:`SignalGatedToolRunner.has_signal` reads the graph and
    refuses (audited, no spawn) unless a signal for the class the tool would claim
    already exists (a ReachAgent-owned probe result, not the tool's own say-so);
  * emit **candidates only** — :meth:`parse` returns inert
    :class:`~reachagent.tools.candidate.Candidate` records tagged with the
    ``vuln_class`` and the §7 ``suggested_oracle`` that must re-confirm them. They
    write nothing to the graph, import no ``write_finding``/``run_oracle``, and have
    no path to a confirmation (proven by an AST import scan in the tests);
  * carry the **same safety spine as the recon tier** — scope-enforce before any
    spawn, argument-array with ``shell=False`` (target never interpolated),
    missing-binary graceful skip, every invocation audited, live spawning off
    unless ``REACHAGENT_RECON_LIVE`` is set (default + tests parse fixtures).

Independent re-confirmation lives in :func:`reconfirm_candidate` — the ONLY place a
tool-sourced candidate can become a finding, and only via a real ``run_oracle``
verdict. The tool never touches ``write_finding``.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # noqa: S404 — argument-array only, shell=False, never a shell string
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import ClassVar

from reachagent.execution.audit import AuditLog
from reachagent.execution.scope import OutOfScopeError, ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.tools.base import RECON_ENV_LIVE, _scope_url
from reachagent.tools.candidate import Candidate

_LIVE_TIMEOUT = 300.0


class SignalGatedOutcome(StrEnum):
    """Why a signal-gated invocation landed where it did — audited on every run.

    Extends the recon vocabulary with ``REFUSED_NO_SIGNAL`` — the gate that makes
    this tier signal-*gated*: no existing class signal in the graph → no invocation.
    """

    EMITTED_CANDIDATES = "emitted_candidates"  # claims parsed into inert candidates
    REFUSED_NO_SIGNAL = "refused_no_signal"  # no class signal in graph — not invoked
    REFUSED_OUT_OF_SCOPE = "refused_out_of_scope"  # scope gate refused — no spawn
    SKIPPED_MISSING_BINARY = "skipped_missing_binary"  # tool absent — graceful skip
    SKIPPED_NOT_LIVE = "skipped_not_live"  # live path off (env flag unset)
    ERRORED = "errored"  # spawn/parse error — audited, never crashes the run


@dataclass(frozen=True)
class SignalGatedResult:
    """Outcome of one signal-gated invocation, plus the candidates it emitted.

    ``candidates`` are inert :class:`Candidate` handoffs — NEVER findings, never
    graph writes. ``outcome`` records why, so a caller distinguishes a clean
    candidate emission from a signal-gate refusal, a scope refusal, a missing
    binary, or an error, without exceptions.
    """

    tool: str
    target: str
    outcome: SignalGatedOutcome
    candidates: tuple[Candidate, ...] = ()
    detail: str = ""


@dataclass
class SignalGatedToolRunner:
    """Base for a signal-gated candidate-emitter (§9). Subclasses supply gate + parse.

    The base owns every gate — signal, scope, missing-binary, command-array, audit —
    and the fixture/live split. A subclass supplies: ``name``/``binary``; a
    ``command`` array; a ``has_signal`` predicate over the graph (the §9 gate); and
    a ``parse`` turning tool output into inert candidates. A subclass NEVER writes to
    the graph and NEVER imports ``write_finding``/``run_oracle``.
    """

    graph: ReachabilityGraph
    scope: ScopeGuard
    audit: AuditLog = field(default_factory=AuditLog)

    name: ClassVar[str] = "signal-gated"  # overridden per tool
    binary: ClassVar[str] = ""  # executable on PATH (overridden per tool)

    # -- subclass contract -------------------------------------------------

    def has_signal(self, target: str) -> bool:
        """Return True iff the graph already holds a signal for this tool's class (§9).

        The "gated" in signal-gated: an ungated tool is never invoked. Reads only
        ReachAgent-owned facts already in the graph (a probe's inferred sink, a
        recon fingerprint) — never the tool's own output. Implemented per tool.
        """
        raise NotImplementedError

    def command(self, target: str, output_path: str) -> list[str]:
        """Build the argument array for a live invocation (subclass overrides).

        MUST return a list passed to ``subprocess.run`` with ``shell=False``; the
        target is always a distinct element, never interpolated into a shell string.
        ``output_path`` is the machine-readable output file/dir the parser reads.
        """
        raise NotImplementedError

    def parse(self, target: str, raw_output: str) -> tuple[Candidate, ...]:
        """Parse the tool's CLAIM output into inert candidates (never a finding).

        Returns :class:`Candidate` records tagged with ``vuln_class`` and the §7
        ``suggested_oracle`` that must independently re-confirm them. Writes nothing
        to the graph. Implemented per tool.
        """
        raise NotImplementedError

    # -- the network-free entry point: parse recorded tool output ----------

    def ingest(self, target: str, raw_output: str) -> SignalGatedResult:
        """Signal-gate + scope-gate ``target``, then parse ``raw_output`` into candidates.

        The primary, network-free path (unit tests, in-process callers). Order is the
        invariant: **signal gate first** (no class signal → refuse, no parse), then
        scope, then parse. A candidate about an out-of-scope or unsignalled target is
        never produced. A parse error is caught, audited, and returned — never raised.
        """
        # Gate 1: the signal gate — the defining §9 precondition. No graph signal
        # for this tool's class → the tool is not a candidate source here at all.
        if not self.has_signal(target):
            self.audit.record(
                self.name, "SIGNAL_GATED", target, SignalGatedOutcome.REFUSED_NO_SIGNAL
            )
            return SignalGatedResult(self.name, target, SignalGatedOutcome.REFUSED_NO_SIGNAL)

        # Gate 2: scope — a claim about an out-of-scope target is refused, audited.
        try:
            self.scope.enforce(_scope_url(target))
        except OutOfScopeError:
            self.audit.record(
                self.name, "SIGNAL_GATED", target, SignalGatedOutcome.REFUSED_OUT_OF_SCOPE
            )
            return SignalGatedResult(self.name, target, SignalGatedOutcome.REFUSED_OUT_OF_SCOPE)

        try:
            candidates = self.parse(target, raw_output)
        except Exception as exc:  # noqa: BLE001 — a parse error must not crash the run
            self.audit.record(
                self.name,
                "SIGNAL_GATED",
                target,
                f"{SignalGatedOutcome.ERRORED}:{type(exc).__name__}",
            )
            return SignalGatedResult(
                self.name, target, SignalGatedOutcome.ERRORED, detail=type(exc).__name__
            )

        self.audit.record(self.name, "SIGNAL_GATED", target, SignalGatedOutcome.EMITTED_CANDIDATES)
        return SignalGatedResult(
            self.name, target, SignalGatedOutcome.EMITTED_CANDIDATES, candidates=tuple(candidates)
        )

    # -- the live path: env-gated, signal-first, scope, command-array ------

    def run(
        self, target: str, output_path: str, *, environ: dict[str, str] | None = None
    ) -> SignalGatedResult:
        """Live invocation: env-gate → signal-gate → scope → binary → spawn → ``ingest``.

        Off by default (``REACHAGENT_RECON_LIVE`` unset → spawns nothing). When live,
        the order is the safety contract: signal gate (no class signal → refuse, no
        spawn), then scope (refuse out-of-scope before spawn), then binary presence
        (missing → clean skip), then ``subprocess.run(command, shell=False)`` with the
        target as a distinct list element (never a shell string), then parse the
        machine-readable output file the tool wrote at ``output_path``.
        """
        env = os.environ if environ is None else environ

        if not env.get(RECON_ENV_LIVE):
            self.audit.record(
                self.name, "SIGNAL_GATED", target, SignalGatedOutcome.SKIPPED_NOT_LIVE
            )
            return SignalGatedResult(self.name, target, SignalGatedOutcome.SKIPPED_NOT_LIVE)

        # Signal gate before any spawn — the §9 precondition, even on the live path.
        if not self.has_signal(target):
            self.audit.record(
                self.name, "SIGNAL_GATED", target, SignalGatedOutcome.REFUSED_NO_SIGNAL
            )
            return SignalGatedResult(self.name, target, SignalGatedOutcome.REFUSED_NO_SIGNAL)

        try:
            self.scope.enforce(_scope_url(target))
        except OutOfScopeError:
            self.audit.record(
                self.name, "SIGNAL_GATED", target, SignalGatedOutcome.REFUSED_OUT_OF_SCOPE
            )
            return SignalGatedResult(self.name, target, SignalGatedOutcome.REFUSED_OUT_OF_SCOPE)

        if shutil.which(self.binary) is None:
            self.audit.record(
                self.name, "SIGNAL_GATED", target, SignalGatedOutcome.SKIPPED_MISSING_BINARY
            )
            return SignalGatedResult(self.name, target, SignalGatedOutcome.SKIPPED_MISSING_BINARY)

        try:
            completed = subprocess.run(  # noqa: S603 — array args, shell=False, no interpolation
                self.command(target, output_path),
                capture_output=True,
                text=True,
                timeout=_LIVE_TIMEOUT,
                check=False,
                shell=False,
            )
            raw_output = getattr(completed, "stdout", "") or ""
            output = Path(output_path)
            if output.is_file():
                raw_output += output.read_text(encoding="utf-8", errors="replace")
            elif output.is_dir():
                # sqlmap/commix use an output directory while nuclei/nikto use a
                # file. Read bounded text from either shape; claims remain inert.
                for child in sorted(output.rglob("*")):
                    if child.is_file():
                        raw_output += child.read_text(encoding="utf-8", errors="replace")[
                            :1_000_000
                        ]
        except FileNotFoundError:
            self.audit.record(
                self.name, "SIGNAL_GATED", target, SignalGatedOutcome.SKIPPED_MISSING_BINARY
            )
            return SignalGatedResult(self.name, target, SignalGatedOutcome.SKIPPED_MISSING_BINARY)
        except (subprocess.SubprocessError, OSError) as exc:
            self.audit.record(
                self.name,
                "SIGNAL_GATED",
                target,
                f"{SignalGatedOutcome.ERRORED}:{type(exc).__name__}",
            )
            return SignalGatedResult(
                self.name, target, SignalGatedOutcome.ERRORED, detail=type(exc).__name__
            )

        return self.ingest(target, raw_output)


# ---------------------------------------------------------------------------
# The ONLY place a tool-sourced candidate can become a finding: an independent
# run_oracle re-check. The tool never touches write_finding — this does, and only
# on run_oracle's own is_violation verdict.
# ---------------------------------------------------------------------------


def reconfirm_candidate(
    candidate: Candidate,
    evidence: object,
    *,
    run_oracle: object,
    write_finding: object,
    graph: ReachabilityGraph,
    finding_factory: object,
) -> str | None:
    """Independently re-confirm a tool-sourced ``candidate`` via ``run_oracle`` (§9, §13).

    This is the anti-false-positive gate §9 demands: a tool's *claim* becomes a
    ``Finding`` ONLY when ReachAgent's own oracle, run over independently-gathered
    ``evidence``, returns ``is_violation``. The candidate's ``suggested_oracle`` is
    the §7 family to run; a verdict that is inconclusive/denied → ``None`` (the claim
    is dropped, no finding). Only a ``confirmed_violation`` verdict reaches
    ``write_finding``, whose own gate is the last line.

    ``run_oracle``/``write_finding`` are injected (the Validator's tools, or the MCP
    boundary) so this helper imports neither — the emitter modules stay provably
    free of any confirmation path. ``finding_factory(candidate, verdict)`` builds the
    ``Finding`` the Validator commits. Returns the finding node id, or ``None`` when
    the oracle did not independently confirm.
    """
    verdict = run_oracle(candidate.suggested_oracle, evidence)  # type: ignore[operator]
    if not getattr(verdict, "is_violation", False):
        # The tool claimed it; ReachAgent's own oracle did not confirm it → dropped.
        return None
    finding = finding_factory(candidate, verdict)  # type: ignore[operator]
    return write_finding(graph, finding, verdict)  # type: ignore[operator, no-any-return]
