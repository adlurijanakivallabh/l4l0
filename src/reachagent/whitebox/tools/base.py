"""White-box tool-wrapper base: local-repo static fact-emitters (§9, §13, Build Order 7).

A parallel, deliberately SEPARATE base from :class:`reachagent.recon.tools.base.
ReconToolRunner` — that base's scope gate (:func:`_scope_url`) coerces its
``target`` into an ``httpx.URL`` and checks its *host* against a
:class:`ScopeGuard` allowlist; a local filesystem path (``/home/user/repo``)
has no host at all, so reusing it unchanged would either raise or always
refuse as "out of scope" for a fact that was never a network target to begin
with. There is no live network request anywhere in this mode: the "scope" for
white-box mode is simply the operator having typed this exact path into the
intake — no host allowlist question applies.

The genuinely reusable piece — the RLIMIT_AS/GOMEMLIMIT subprocess-memory
discipline hardened earlier this session against real freeze/OOM crashes — is
imported directly from ``recon/tools/_net.py`` (already generic, not
URL-specific) rather than re-implemented.

Same safety properties as the recon tier, adapted:

  * **Path exists, at the execution layer.** :meth:`SourceToolRunner.run`
    validates ``repo_path`` is a real, existing directory *before spawning
    anything*. A missing/non-directory path is refused with an audited
    ``refused_path_not_found`` entry and no process is spawned.
  * **Command array, never a shell string.** Same as the recon tier.
  * **Optional binary, graceful skip.** Same as the recon tier.
  * **Everything audited.** Same as the recon tier.

Live invocation is gated behind the SAME ``REACHAGENT_RECON_LIVE`` flag the
recon tier uses (one flag governs "spawn real external tools live"
project-wide, rather than a near-duplicate white-box-specific flag) — off by
default, so every unit test parses recorded fixtures through
:meth:`SourceToolRunner.ingest` and never touches a real tool or the real
filesystem beyond the path it's handed.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # noqa: S404 — argument-array only, shell=False, never a shell string
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import ClassVar

from reachagent.execution.audit import AuditLog
from reachagent.graph.store import ReachabilityGraph
from reachagent.recon.tools._net import GO_MEMORY_LIMIT_ENV as _GO_MEMORY_LIMIT_ENV
from reachagent.recon.tools._net import available_memory_mb as _available_memory_mb
from reachagent.recon.tools._net import limit_child_memory as _limit_child_memory
from reachagent.recon.tools.base import RECON_ENV_LIVE

__all__ = ["SourceToolRunner", "WhiteboxOutcome", "WhiteboxResult"]

# Same threshold/timeout constants the recon tier uses — one discipline,
# not a second copy tuned differently by accident.
_LIVE_TIMEOUT = 300.0
_MIN_FREE_MEMORY_MB = 300.0
_OUTPUT_MAX_CHARS = 200_000  # semgrep/trufflehog JSON can be large; still bounded


class WhiteboxOutcome(StrEnum):
    """Why a white-box tool invocation landed where it did — audited on every run."""

    INGESTED = "ingested"
    REFUSED_PATH_NOT_FOUND = "refused_path_not_found"
    SKIPPED_MISSING_BINARY = "skipped_missing_binary"
    SKIPPED_NOT_LIVE = "skipped_not_live"
    SKIPPED_LOW_MEMORY = "skipped_low_memory"
    ERRORED = "errored"


@dataclass(frozen=True)
class WhiteboxResult:
    """Outcome of one white-box tool invocation, plus the graph node ids it wrote."""

    tool: str
    repo_path: str
    outcome: WhiteboxOutcome
    nodes: tuple[str, ...] = ()
    detail: str = ""
    output_preview: str = ""
    command: tuple[str, ...] = ()


@dataclass
class SourceToolRunner:
    """Base for a white-box static fact-emitter. Subclasses implement parsing only."""

    graph: ReachabilityGraph
    audit: AuditLog = field(default_factory=AuditLog)

    name: ClassVar[str] = "whitebox"
    binary: ClassVar[str] = ""

    def command(self, repo_path: str) -> list[str]:
        """Build the argument array for a live invocation (subclass overrides)."""
        raise NotImplementedError

    def parse(self, repo_path: str, raw_output: str) -> tuple[str, ...]:
        """Parse ``raw_output`` into graph writes; return the node ids written.

        The subclass writes only ``SourceFile``/``Secret``/``PackageDependency``
        nodes — never a ``Finding``, never ``run_oracle``. Implemented per tool.
        """
        raise NotImplementedError

    def ingest(self, repo_path: str, raw_output: str) -> WhiteboxResult:
        """Parse recorded ``raw_output`` into graph facts (no spawn, no filesystem
        access beyond what the subclass's ``parse`` does with the label itself)."""
        try:
            nodes = self.parse(repo_path, raw_output)
        except Exception as exc:  # noqa: BLE001 — a parse error must not crash the run
            self.audit.record(
                self.name, "STATIC", repo_path, f"{WhiteboxOutcome.ERRORED}:{type(exc).__name__}"
            )
            return WhiteboxResult(
                self.name,
                repo_path,
                WhiteboxOutcome.ERRORED,
                detail=type(exc).__name__,
                output_preview=_truncate(raw_output),
            )
        self.audit.record(self.name, "STATIC", repo_path, WhiteboxOutcome.INGESTED)
        return WhiteboxResult(
            self.name,
            repo_path,
            WhiteboxOutcome.INGESTED,
            nodes=tuple(nodes),
            output_preview=_truncate(raw_output),
        )

    def run(self, repo_path: str, *, environ: dict[str, str] | None = None) -> WhiteboxResult:
        """Live invocation: path-check → binary-check → spawn (array) → ``ingest``."""
        env = os.environ if environ is None else environ

        if not env.get(RECON_ENV_LIVE):
            self.audit.record(self.name, "STATIC", repo_path, WhiteboxOutcome.SKIPPED_NOT_LIVE)
            return WhiteboxResult(self.name, repo_path, WhiteboxOutcome.SKIPPED_NOT_LIVE)

        # Gate 1: the path must be a real, existing directory before anything
        # is spawned — the white-box equivalent of the recon tier's scope gate.
        if not Path(repo_path).is_dir():
            self.audit.record(
                self.name, "STATIC", repo_path, WhiteboxOutcome.REFUSED_PATH_NOT_FOUND
            )
            return WhiteboxResult(self.name, repo_path, WhiteboxOutcome.REFUSED_PATH_NOT_FOUND)

        # Gate 2: optional binary — a missing tool is a clean skip, never a crash.
        if shutil.which(self.binary) is None:
            self.audit.record(
                self.name, "STATIC", repo_path, WhiteboxOutcome.SKIPPED_MISSING_BINARY
            )
            return WhiteboxResult(self.name, repo_path, WhiteboxOutcome.SKIPPED_MISSING_BINARY)

        # Gate 3: system memory — same advisory pre-check as the recon tier.
        free_mb = _available_memory_mb()
        if free_mb is not None and free_mb < _MIN_FREE_MEMORY_MB:
            self.audit.record(self.name, "STATIC", repo_path, WhiteboxOutcome.SKIPPED_LOW_MEMORY)
            return WhiteboxResult(self.name, repo_path, WhiteboxOutcome.SKIPPED_LOW_MEMORY)

        # Gate 4: spawn via an argument ARRAY, shell=False (command-injection guard).
        argv = self.command(repo_path)
        try:
            completed = subprocess.run(  # noqa: S603 — array args, shell=False, no interpolation
                argv,
                capture_output=True,
                text=True,
                timeout=_LIVE_TIMEOUT,
                check=False,
                shell=False,
                env={**os.environ, **_GO_MEMORY_LIMIT_ENV},
                preexec_fn=_limit_child_memory,  # noqa: PLW1509 — trivial setrlimit only, no locks
            )
        except FileNotFoundError:
            self.audit.record(
                self.name, "STATIC", repo_path, WhiteboxOutcome.SKIPPED_MISSING_BINARY
            )
            return WhiteboxResult(self.name, repo_path, WhiteboxOutcome.SKIPPED_MISSING_BINARY)
        except (subprocess.SubprocessError, OSError) as exc:
            self.audit.record(
                self.name, "STATIC", repo_path, f"{WhiteboxOutcome.ERRORED}:{type(exc).__name__}"
            )
            return WhiteboxResult(
                self.name,
                repo_path,
                WhiteboxOutcome.ERRORED,
                detail=type(exc).__name__,
                command=tuple(argv),
            )

        # Bound BEFORE parse, not just the returned preview (adversarial
        # review): subprocess.run's capture_output buffers the tool's full
        # stdout into THIS (parent) process — not the RLIMIT_AS-capped
        # child — so an unbounded string here is an unbounded parent-memory
        # cost regardless of how tightly the child itself is capped. Mirrors
        # ReconToolRunner.run()'s identical truncate-before-ingest ordering.
        # A truncated JSON/JSON-lines payload can fail to parse; that is a
        # clean, audited WhiteboxOutcome.ERRORED (ingest's own parse-error
        # handling), never a crash, and a smaller cost than buffering an
        # unbounded string twice (once here, once inside json.loads).
        return replace(self.ingest(repo_path, _truncate(completed.stdout)), command=tuple(argv))


def _truncate(raw: str) -> str:
    if len(raw) <= _OUTPUT_MAX_CHARS:
        return raw
    return raw[:_OUTPUT_MAX_CHARS] + f"\n# [truncated: {len(raw)} -> {_OUTPUT_MAX_CHARS} chars]"
