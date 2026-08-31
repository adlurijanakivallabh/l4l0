"""Recon-tier tool-wrapper base: scope-gated, audited, subprocess-array fact-emitters (§9, §13).

Recon-tier tools (nmap, amass, subfinder, gobuster, whatweb) are **fact-emitters**,
not detectors. They write only transport-tier graph facts — ``Host``/``Service``
nodes, ``runs_service``/``resolves_to`` edges, and ``Endpoint`` nodes for
discovered paths (§6, §9; v1.8). They never write a ``can_call``, a candidate, a
``Finding``, and never call ``run_oracle``. This is the same architectural role as
:class:`~reachagent.recon.mapper.SurfaceMapper` — a recon fact source, not an
Explorer/Validator/Coordinator tool — and this module mirrors its scope + audit
discipline.

Four safety properties are load-bearing here, enforced before any tool runs:

  * **Scope allowlist, at the execution layer (§10).** :meth:`ReconToolRunner.run`
    validates the target against a :class:`~reachagent.execution.scope.ScopeGuard`
    *before spawning anything*. An out-of-scope target raises / is refused with an
    audited ``refused_out_of_scope`` entry and **no process is spawned**.

  * **Command array, never a shell string (command-injection guard).** Every tool
    is invoked via :func:`subprocess.run` with an argument *list* and
    ``shell=False`` (subprocess default). The target is passed as a distinct list
    element, never interpolated into a shell string — so a hostile target value
    can never break out into a shell.

  * **Optional binary, graceful skip (§13).** Each tool is an optional recon
    source. A missing binary (``shutil.which`` returns ``None``, or the spawn
    raises ``FileNotFoundError``) is detected and skipped cleanly with a logged
    message and a ``skipped_missing_binary`` audit entry — it never crashes the run.

  * **Everything audited.** Every invocation — fired, refused, skipped, or errored
    — records one :class:`~reachagent.execution.audit.AuditEntry`, the same
    discipline as :class:`~reachagent.execution.firer.RequestFirer`.

**Live invocation is env-gated.** Real binaries are only ever spawned when
``REACHAGENT_RECON_LIVE`` is set in the environment. The default path (and every
unit test) parses recorded output *fixtures* through :meth:`ReconToolRunner.ingest`
— network-free and reproducible. ``run`` (the live path) is thin: scope-gate →
binary-check → spawn → hand stdout to ``ingest``.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # noqa: S404 — argument-array only, shell=False, never a shell string
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import ClassVar
from urllib.parse import urlsplit

import httpx

from reachagent.execution.audit import AuditLog
from reachagent.execution.scope import OutOfScopeError, ScopeGuard
from reachagent.graph.nodes import Endpoint, Host
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.tools._net import available_memory_mb as _available_memory_mb
from reachagent.recon.tools._net import (
    host_of as _recon_host_of,  # noqa: F401 — re-export for 8 callers
)
from reachagent.recon.tools._net import output_preview as _recon_output_preview
from reachagent.recon.tools._net import (
    path_of as _recon_path_of,  # noqa: F401 — re-export for 6 callers
)

__all__ = [
    "ReconToolRunner",
    "ReconOutcome",
    "ReconResult",
    "_recon_host_of",
    "_recon_path_of",
    "_truncate_output",
    "RECON_ENV_LIVE",
]

# Live binaries are spawned ONLY when this is set; unset (the default, and every
# unit test) parses fixtures via ``ingest`` and never touches a real tool/network.
RECON_ENV_LIVE = "REACHAGENT_RECON_LIVE"

# How long a live tool invocation may run before we abandon it (seconds). Recon
# tools can hang; a bounded timeout keeps the run from stalling.
_LIVE_TIMEOUT = 300.0

# Below this, the system is close to swapping hard — spawning another process
# (some of these are memory-heavy: katana, sqlmap) risks tipping it into a
# freeze rather than just running slowly. Advisory only; skipped when
# unmeasurable (see available_memory_mb()).
_MIN_FREE_MEMORY_MB = 300.0

# Output truncation (context-efficiency, reference-informed): a recon tool that
# emits huge output (minified JS bundles, verbose XML) would flood the LLM
# context. Cap at _OUTPUT_MAX_CHARS normally; when the content looks minified,
# cap tighter at _MINIFIED_MAX_CHARS. Detection is heuristic (avg line length).
_OUTPUT_MAX_CHARS = 50_000
_MINIFIED_MAX_CHARS = 10_000
_MINIFIED_AVG_LINE = 500  # avg chars/line above which content is "minified"


class ReconOutcome(StrEnum):
    """Why a recon-tool invocation landed where it did — audited on every run.

    Mirrors the firer's fired/refused vocabulary so a recon action is auditable to
    the same standard as a request fire (§10).
    """

    INGESTED = "ingested"  # output parsed into transport-tier graph facts
    REFUSED_OUT_OF_SCOPE = "refused_out_of_scope"  # scope gate refused — no spawn
    SKIPPED_MISSING_BINARY = "skipped_missing_binary"  # tool absent — graceful skip
    SKIPPED_NOT_LIVE = "skipped_not_live"  # live path off (REACHAGENT_RECON_LIVE unset)
    SKIPPED_LOW_MEMORY = "skipped_low_memory"  # system critically low on memory — no spawn
    ERRORED = "errored"  # spawn/parse error — audited, never crashes the run


@dataclass(frozen=True)
class ReconResult:
    """Outcome of one recon-tool invocation, plus the graph node ids it wrote.

    ``nodes`` are the transport-tier node ids the parse landed (hosts, services,
    endpoints). ``outcome`` records why — so a caller can distinguish a clean
    ingest from a scope refusal, a missing binary, or an error, without exceptions.
    ``output_preview`` is a short, bounded slice of the tool's raw stdout (GUI
    live-feed display only — never used for graph facts, which come from ``parse``).
    """

    tool: str
    target: str
    outcome: ReconOutcome
    nodes: tuple[str, ...] = ()
    detail: str = ""
    output_preview: str = ""
    command: tuple[str, ...] = ()


@dataclass
class ReconToolRunner:
    """Base for a recon-tier fact-emitter (§9). Subclasses implement parsing only.

    The base owns every safety gate (scope, missing-binary, command-array, audit)
    and the fixture/live split. A subclass supplies just three things: the tool's
    ``name``, the ``binary`` to look for, the ``command`` array to build, and the
    ``parse`` that turns raw tool output into transport-tier graph writes.
    """

    graph: ReachabilityGraph
    scope: ScopeGuard
    audit: AuditLog = field(default_factory=AuditLog)

    # -- subclass contract -------------------------------------------------
    #
    # ``name``/``binary`` are ClassVar constants, NOT dataclass fields: a subclass
    # sets them as plain class attributes, and ClassVar keeps the dataclass from
    # turning them into instance fields (which would shadow the override with the
    # base default at __init__ time).

    name: ClassVar[str] = "recon"  # overridden per tool
    binary: ClassVar[str] = ""  # the executable to look for on PATH (overridden per tool)

    def command(self, target: str) -> list[str]:
        """Build the argument array for a live invocation (subclass overrides).

        MUST return a list whose elements are passed to ``subprocess.run`` verbatim
        with ``shell=False``; the target is always a distinct element, never
        interpolated into a shell string. Implemented per tool.
        """
        raise NotImplementedError

    def parse(self, target: str, raw_output: str) -> tuple[str, ...]:
        """Parse ``raw_output`` into transport-tier graph writes; return node ids.

        The subclass writes only ``Host``/``Service``/``Endpoint`` nodes and
        ``runs_service``/``resolves_to`` edges — never a ``can_call``, candidate,
        ``Finding``, or ``run_oracle`` call. Returns the ids it wrote (for audit /
        tests). Implemented per tool.
        """
        raise NotImplementedError

    def endpoint_for_target(self, target: str, *, method: str = "GET") -> str:
        """Return the matching endpoint node, creating a scoped route if needed."""
        parsed = urlsplit(target if "://" in target else f"http://{target}")
        path = parsed.path or "/"
        verb = method.upper()
        for node, endpoint in self.graph.endpoints():
            if endpoint.method.upper() == verb and endpoint.path == path:
                return node
        host_address = _recon_host_of(target)
        host_node = self.graph.add_host(
            Host(address=host_address, hostname=host_address, source=self.name)
        )
        endpoint_node = self.graph.add_endpoint(
            Endpoint(
                method=verb,
                path=path,
                source=self.name,
                confidence=0.7,
            )
        )
        self.graph.add_resolves_to(host_node, endpoint_node)
        return endpoint_node

    # -- the network-free entry point: parse a recorded fixture ------------

    def ingest(self, target: str, raw_output: str) -> ReconResult:
        """Scope-gate ``target``, then parse ``raw_output`` into graph facts (no spawn).

        The primary, network-free path: unit tests and any in-process caller hand
        it recorded tool output. The scope gate still runs first — a fact about an
        out-of-scope target is refused and audited exactly as a live spawn would be,
        so scope discipline holds even when no process is launched. A parse error is
        caught, audited as ``errored``, and returned — never raised into the run.
        """
        try:
            self.scope.enforce(_scope_url(target))
        except OutOfScopeError:
            self.audit.record(self.name, "RECON", target, ReconOutcome.REFUSED_OUT_OF_SCOPE)
            return ReconResult(self.name, target, ReconOutcome.REFUSED_OUT_OF_SCOPE)

        try:
            nodes = self.parse(target, raw_output)
        except Exception as exc:  # noqa: BLE001 — a parse error must not crash the run
            self.audit.record(
                self.name, "RECON", target, f"{ReconOutcome.ERRORED}:{type(exc).__name__}"
            )
            # A parse failure is exactly when the raw output matters most for a
            # human to see — never withhold the preview just because parsing failed.
            return ReconResult(
                self.name,
                target,
                ReconOutcome.ERRORED,
                detail=type(exc).__name__,
                output_preview=_recon_output_preview(raw_output),
            )

        self.audit.record(self.name, "RECON", target, ReconOutcome.INGESTED)
        return ReconResult(
            self.name,
            target,
            ReconOutcome.INGESTED,
            nodes=tuple(nodes),
            output_preview=_recon_output_preview(raw_output),
        )

    # -- the live path: env-gated, scope-first, command-array, missing-binary skip --

    def run(self, target: str, *, environ: dict[str, str] | None = None) -> ReconResult:
        """Live invocation: scope-gate → binary-check → spawn (array) → ``ingest``.

        Off by default: unless ``REACHAGENT_RECON_LIVE`` is set, this spawns nothing
        and returns ``SKIPPED_NOT_LIVE`` — so a normal run (and every unit test)
        never launches a real tool. When live, the order is the safety contract:

          1. **scope** — refuse + audit an out-of-scope target *before any spawn*;
          2. **binary presence** — a missing binary is a clean, audited skip;
          3. **spawn** — ``subprocess.run(self.command(target), shell=False)`` with
             the target as a list element (never a shell string), bounded by a
             timeout; a ``FileNotFoundError`` at spawn is also treated as a missing
             binary, and any other spawn error is audited as ``errored``;
          4. **parse** — stdout is handed to :meth:`ingest`, which re-checks scope
             and writes the transport-tier facts.
        """
        env = os.environ if environ is None else environ

        # Gate 0: live path off → spawn nothing (the default).
        if not env.get(RECON_ENV_LIVE):
            self.audit.record(self.name, "RECON", target, ReconOutcome.SKIPPED_NOT_LIVE)
            return ReconResult(self.name, target, ReconOutcome.SKIPPED_NOT_LIVE)

        # Gate 1: scope, before anything is spawned (§10).
        try:
            self.scope.enforce(_scope_url(target))
        except OutOfScopeError:
            self.audit.record(self.name, "RECON", target, ReconOutcome.REFUSED_OUT_OF_SCOPE)
            return ReconResult(self.name, target, ReconOutcome.REFUSED_OUT_OF_SCOPE)

        # Gate 2: optional binary — a missing tool is a clean skip, never a crash.
        if shutil.which(self.binary) is None:
            self.audit.record(self.name, "RECON", target, ReconOutcome.SKIPPED_MISSING_BINARY)
            return ReconResult(self.name, target, ReconOutcome.SKIPPED_MISSING_BINARY)

        # Gate 2.5: system memory — spawning another process while critically
        # low risks a freeze rather than just a slow run (§9 resilience).
        free_mb = _available_memory_mb()
        if free_mb is not None and free_mb < _MIN_FREE_MEMORY_MB:
            self.audit.record(self.name, "RECON", target, ReconOutcome.SKIPPED_LOW_MEMORY)
            return ReconResult(self.name, target, ReconOutcome.SKIPPED_LOW_MEMORY)

        # Gate 3: spawn via an argument ARRAY, shell=False (command-injection guard).
        argv = self.command(target)
        # File-backed tools (arjun -oJ, ffuf -o file, etc.) write JSON to a file
        # path embedded in argv rather than stdout. Detect such file paths and
        # read them after spawn; otherwise fall back to stdout.
        file_output_arg: str | None = None
        for flag in ("-oJ", "-o", "-j", "--json_out", "--jsonfile"):
            if flag in argv:
                idx = argv.index(flag)
                if idx + 1 < len(argv):
                    cand = argv[idx + 1]
                    # Heuristic: looks like a file path (not "-" which means stdout)
                    if cand != "-" and cand.endswith(".json"):  # noqa: S108 — temp file path from mkstemp, not hardcoded /tmp use
                        file_output_arg = cand
                        break
        try:
            completed = subprocess.run(  # noqa: S603 — array args, shell=False, no interpolation
                argv,
                capture_output=True,
                text=True,
                timeout=_LIVE_TIMEOUT,
                check=False,
                shell=False,
            )
        except FileNotFoundError:
            # Race: binary vanished between which() and spawn — still a clean skip.
            self.audit.record(self.name, "RECON", target, ReconOutcome.SKIPPED_MISSING_BINARY)
            return ReconResult(self.name, target, ReconOutcome.SKIPPED_MISSING_BINARY)
        except (subprocess.SubprocessError, OSError) as exc:
            self.audit.record(
                self.name, "RECON", target, f"{ReconOutcome.ERRORED}:{type(exc).__name__}"
            )
            return ReconResult(
                self.name,
                target,
                ReconOutcome.ERRORED,
                detail=type(exc).__name__,
                command=tuple(argv),
            )

        # Gate 4: parse output into transport-tier facts (re-checks scope).
        raw = completed.stdout
        raw = _truncate_output(raw)
        if file_output_arg is not None:
            try:
                with open(file_output_arg, encoding="utf-8", errors="replace") as fh:
                    file_content = fh.read()
                if file_content.strip():
                    raw = file_content
            except OSError:
                pass
            try:
                import os as _os2

                _os2.unlink(file_output_arg)
            except OSError:
                pass
        return replace(self.ingest(target, raw), command=tuple(argv))


def _scope_url(target: str) -> httpx.URL:
    """Coerce a recon target (bare host, host:port, or URL) to a URL for scope check.

    ScopeGuard matches on an ``httpx.URL``'s host; a recon target is often a bare
    hostname or ``host:port``, so we wrap it in an ``http://`` URL when it carries
    no scheme, purely so the *host* can be scope-checked. This constructs no
    request and fires nothing — it only feeds the allowlist gate the host to judge.
    """
    if "://" in target:
        return httpx.URL(target)
    return httpx.URL(f"http://{target}")


def _truncate_output(raw: str) -> str:
    """Bound tool stdout for LLM context efficiency.

    Minified content (avg line length > threshold) is capped tighter — it is
    dense and mostly noise for fact extraction. A truncation marker is appended
    so downstream consumers know the parse saw partial output.
    """
    lines = raw.splitlines()
    avg_len = sum(len(line) for line in lines) / max(len(lines), 1)
    limit = _MINIFIED_MAX_CHARS if avg_len > _MINIFIED_AVG_LINE else _OUTPUT_MAX_CHARS
    if len(raw) <= limit:
        return raw
    marker = f"\n# [truncated: {len(raw)} -> {limit} chars]"
    return raw[:limit] + marker
