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

import math
import os
import re
import shutil
import subprocess  # noqa: S404 — argument-array only, shell=False, never a shell string
import time
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import ClassVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from reachagent.execution.audit import AuditLog
from reachagent.execution.scope import OutOfScopeError, ScopeGuard
from reachagent.graph.store import ReachabilityGraph
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import OracleVerdict
from reachagent.oracles.registry import UnknownOracleError, get_oracle
from reachagent.recon.tools._net import GO_MEMORY_LIMIT_ENV as _GO_MEMORY_LIMIT_ENV
from reachagent.recon.tools._net import available_memory_mb as _available_memory_mb
from reachagent.recon.tools._net import limit_child_memory as _limit_child_memory
from reachagent.recon.tools._net import output_preview as _recon_output_preview
from reachagent.recon.tools.base import RECON_ENV_LIVE, _scope_url
from reachagent.tools.candidate import Candidate, ResponseSignal

# Aggressive mode (Build Order v2 W4, opt-in, default off): when set, the signal gate is
# bypassed so a signal-gated tool (nuclei/sqlmap/dalfox) fires even without a prior class
# signal in the graph — "try much harder" like the reference tools. Every emitted candidate
# still passes the oracle reconfirm (or lands in the Suspected tier), and every OTHER gate
# (scope, binary presence, memory, read-only) is untouched. Read via the same contextvar/env
# flag mechanism the tuning flags use, so the GUI can turn it on per-scan.
_AGGRESSIVE_FLAG = "REACHAGENT_AGGRESSIVE"

_LIVE_TIMEOUT = 300.0
# Same rationale as base.py's _MIN_FREE_MEMORY_MB — this tier includes
# memory-heavy tools too (sqlmap).
_MIN_FREE_MEMORY_MB = 300.0
_MAX_CANDIDATES = 100
_MAX_CLAIM_OUTPUT_CHARS = 1_000_000
_MAX_CLAIM_TEXT_CHARS = 2_000
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_SECRET_TEXT = re.compile(
    r"(?i)(?P<key>bearer|password|passwd|secret|token|authorization|cookie|"
    r"api[_-]?key|access[_-]?token|id[_-]?token)\s*[:=]\s*(?P<value>[^,;\s}]+)"
)
_SECRET_NAME = re.compile(
    r"(?i)(?:password|passwd|secret|token|authorization|cookie|auth|api[_-]?key|"
    r"access[_-]?token|id[_-]?token|session|jwt|credential)"
)


@dataclass(frozen=True)
class SignalGatedMetadata:
    """Bounded execution metadata exposed to the GUI/audit stream."""

    command_policy: str = "argv:shell=false"
    tool_version: str | None = None
    duration_seconds: float = 0.0
    exit_code: int | None = None
    output_chars: int = 0
    partial_output: bool = False
    dropped_candidates: int = 0
    command: str = ""
    output_preview: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.command_policy, str) or not self.command_policy:
            raise ValueError("command_policy must be non-empty")
        if self.tool_version is not None and (
            not isinstance(self.tool_version, str) or len(self.tool_version) > 128
        ):
            raise ValueError("tool_version must be bounded text")
        for text_value, label in (
            (self.command, "command"),
            (self.output_preview, "output_preview"),
        ):
            if not isinstance(text_value, str) or len(text_value) > 2_000:
                raise ValueError(f"{label} must be bounded text")
        if (
            isinstance(self.duration_seconds, bool)
            or not isinstance(self.duration_seconds, (int, float))
            or not math.isfinite(float(self.duration_seconds))
            or self.duration_seconds < 0
        ):
            raise ValueError("duration_seconds must be finite and non-negative")
        for value, label in (
            (self.exit_code, "exit_code"),
            (self.output_chars, "output_chars"),
            (self.dropped_candidates, "dropped_candidates"),
        ):
            if value is not None and type(value) is not int:
                raise ValueError(f"{label} must be an integer")
            if label != "exit_code" and value is not None and value < 0:
                raise ValueError(f"{label} must be non-negative")
            if label == "exit_code" and value is not None and not -255 <= value <= 255:
                raise ValueError("exit_code is outside the supported range")

    def as_dict(self) -> dict[str, object]:
        return {
            "command_policy": self.command_policy,
            "tool_version": self.tool_version,
            "duration_seconds": round(max(0.0, self.duration_seconds), 3),
            "exit_code": self.exit_code,
            "output_chars": max(0, self.output_chars),
            "partial_output": self.partial_output,
            "dropped_candidates": max(0, self.dropped_candidates),
            "command": self.command,
            "output_preview": self.output_preview,
        }


def _safe_target(target: str) -> str:
    """Return host/path only so scanner claims cannot put query secrets in audit."""
    text = str(target or "")
    try:
        parsed = urlsplit(text if "://" in text else f"http://{text}")
        if parsed.hostname:
            host = parsed.hostname
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            netloc = host
            if parsed.port is not None:
                netloc += f":{parsed.port}"
            return urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", ""))
    except (TypeError, ValueError):
        pass
    return text.split("?", 1)[0].split("#", 1)[0][:512]


def _safe_claim_text(value: object, maximum: int = _MAX_CLAIM_TEXT_CHARS) -> str:
    text = (
        ("" if value is None else str(value))
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("\t", " ")
    )
    text = "".join(char for char in text if ord(char) >= 32 and ord(char) != 127)
    text = _SECRET_TEXT.sub(lambda match: f"{match.group('key')}=<redacted>", text)
    text = re.sub(r"(?i)\bBearer\s+[^\s,;}]+", "Bearer <redacted>", text)
    return text[:maximum]


def _safe_candidate_endpoint(value: str) -> str:
    """Keep a claim URL useful while redacting sensitive query values."""
    text = _safe_claim_text(value, 2_048)
    try:
        parsed = urlsplit(text)
        if not parsed.query:
            return text
        query = [
            (key, "<redacted>" if _SECRET_NAME.search(key) else val)
            for key, val in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))
    except ValueError:
        return text.split("?", 1)[0]


def _safe_label(value: object, maximum: int = 256) -> str | None:
    text = _safe_claim_text(value, maximum)
    if not text or not _SAFE_LABEL.fullmatch(text):
        return None
    return text


def _safe_signal(signal: object) -> ResponseSignal | None:
    if not isinstance(signal, ResponseSignal):
        return None
    if type(signal.status_code) is not int or not 0 <= signal.status_code <= 599:
        return None
    if type(signal.body_length) is not int or not 0 <= signal.body_length <= 100_000_000:
        return None
    if isinstance(signal.elapsed_seconds, bool) or not isinstance(
        signal.elapsed_seconds, (int, float)
    ):
        return None
    elapsed = float(signal.elapsed_seconds)
    if not math.isfinite(elapsed) or elapsed < 0 or elapsed > 86_400:
        return None
    if not isinstance(signal.error_strings, (tuple, list)) or len(signal.error_strings) > 32:
        return None
    errors = tuple(_safe_claim_text(item, 256) for item in signal.error_strings)
    return ResponseSignal(signal.status_code, signal.body_length, elapsed, errors)


def _normalize_candidates(
    candidates: object,
    *,
    scope: ScopeGuard,
) -> tuple[tuple[Candidate, ...], int]:
    """Validate, scope-check, redact, and cap tool claims before handoff."""
    if not isinstance(candidates, (tuple, list)):
        return (), 1
    normalized: list[Candidate] = []
    dropped = 0
    for candidate in candidates:
        if len(normalized) >= _MAX_CANDIDATES:
            dropped += 1
            continue
        if not isinstance(candidate, Candidate):
            dropped += 1
            continue
        if not isinstance(candidate.suggested_oracle, OracleMechanism):
            dropped += 1
            continue
        try:
            get_oracle(candidate.suggested_oracle)
        except (KeyError, UnknownOracleError, TypeError):
            dropped += 1
            continue
        identity = _safe_label(candidate.identity) if isinstance(candidate.identity, str) else None
        endpoint = (
            _safe_candidate_endpoint(candidate.endpoint_node)
            if isinstance(candidate.endpoint_node, str)
            else ""
        )
        vuln_class = (
            _safe_label(candidate.vuln_class) if isinstance(candidate.vuln_class, str) else None
        )
        if identity is None or endpoint == "" or vuln_class is None:
            dropped += 1
            continue
        if "://" in endpoint:
            try:
                scope.enforce(_scope_url(endpoint))
            except (OutOfScopeError, ValueError):
                dropped += 1
                continue
        param = None
        if candidate.param_node is not None:
            param = (
                _safe_label(candidate.param_node) if isinstance(candidate.param_node, str) else None
            )
            if param is None:
                dropped += 1
                continue
        payload_ref = None
        if candidate.payload_ref is not None:
            payload_ref = (
                _safe_label(candidate.payload_ref)
                if isinstance(candidate.payload_ref, str)
                else None
            )
            if payload_ref is None:
                dropped += 1
                continue
        signal = _safe_signal(candidate.signal)
        if signal is None:
            dropped += 1
            continue
        normalized.append(
            Candidate(
                identity=identity,
                endpoint_node=endpoint,
                param_node=param,
                vuln_class=vuln_class,
                suggested_oracle=candidate.suggested_oracle,
                payload_ref=payload_ref,
                signal=signal,
                notes=(
                    tuple(_safe_claim_text(note, 512) for note in candidate.notes[:16])
                    if isinstance(candidate.notes, (tuple, list))
                    else ()
                ),
            )
        )
    return tuple(normalized), dropped


def _bounded_output(raw_output: str) -> tuple[str, bool]:
    text = str(raw_output or "")
    if len(text) <= _MAX_CLAIM_OUTPUT_CHARS:
        return text, False
    # Keep both ends: JSONL scanners commonly append the most useful claims last.
    half = _MAX_CLAIM_OUTPUT_CHARS // 2
    return text[:half] + "\n# [output truncated]\n" + text[-half:], True


def _collect_output(stdout: object, output_path: str) -> tuple[str, bool]:
    """Read stdout/output files with a hard aggregate cap."""
    text = (
        stdout.decode("utf-8", errors="replace") if isinstance(stdout, bytes) else str(stdout or "")
    )
    partial = len(text) > _MAX_CLAIM_OUTPUT_CHARS
    chunks = [text[: _MAX_CLAIM_OUTPUT_CHARS + 1]]
    remaining = max(0, _MAX_CLAIM_OUTPUT_CHARS + 1 - len(chunks[0]))
    path = Path(output_path)
    paths = [path] if path.is_file() else sorted(path.rglob("*")) if path.is_dir() else []
    for child in paths:
        if not child.is_file() or remaining <= 0:
            if child.is_file():
                partial = True
            continue
        with child.open(encoding="utf-8", errors="replace") as stream:
            data = stream.read(remaining + 1)
        if len(data) > remaining:
            partial = True
            data = data[:remaining]
        chunks.append(data)
        remaining -= len(data)
    combined = "".join(chunks)
    bounded, cap_partial = _bounded_output(combined)
    return bounded, partial or cap_partial


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
    SKIPPED_LOW_MEMORY = "skipped_low_memory"  # system critically low on memory — no spawn
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
    metadata: SignalGatedMetadata = field(default_factory=SignalGatedMetadata)


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
    tool_version: ClassVar[str | None] = None

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

    def _audit(
        self,
        target: str,
        outcome: SignalGatedOutcome,
        metadata: SignalGatedMetadata,
        *,
        include_metadata: bool = False,
    ) -> None:
        suffix = ""
        if include_metadata:
            details = metadata.as_dict()
            suffix = "|" + "|".join(
                f"{key}={_safe_claim_text(value, 128)}" for key, value in details.items()
            )
        self.audit.record(
            _safe_label(self.name) or "signal-gated",
            "SIGNAL_GATED",
            _safe_target(target),
            f"{outcome.value}{suffix}",
        )

    def ingest(
        self,
        target: str,
        raw_output: str,
        *,
        metadata: SignalGatedMetadata | None = None,
    ) -> SignalGatedResult:
        """Signal-gate + scope-gate ``target``, then parse ``raw_output`` into candidates.

        The primary, network-free path (unit tests, in-process callers). Order is the
        invariant: **signal gate first** (no class signal → refuse, no parse), then
        scope, then parse. A candidate about an out-of-scope or unsignalled target is
        never produced. A parse error is caught, audited, and returned — never raised.
        """
        # Gate 1: the signal gate — the defining §9 precondition. No graph signal
        # for this tool's class → the tool is not a candidate source here at all.
        # Aggressive mode (opt-in, default off) bypasses this ONE gate so claims are parsed
        # even without a prior signal; every candidate still passes the oracle reconfirm
        # downstream, and the scope gate below is untouched. This must mirror run()'s bypass
        # because run() finishes by calling ingest() — otherwise an aggressive spawn would
        # parse to nothing. Read directly from os.environ (scan-scoped), matching run().
        base_metadata = metadata or SignalGatedMetadata(output_chars=len(raw_output or ""))
        if not self.has_signal(target) and os.environ.get(_AGGRESSIVE_FLAG) != "1":
            self._audit(target, SignalGatedOutcome.REFUSED_NO_SIGNAL, base_metadata)
            return SignalGatedResult(
                self.name,
                target,
                SignalGatedOutcome.REFUSED_NO_SIGNAL,
                metadata=base_metadata,
            )

        # Gate 2: scope — a claim about an out-of-scope target is refused, audited.
        try:
            self.scope.enforce(_scope_url(target))
        except (OutOfScopeError, TypeError, ValueError):
            self._audit(target, SignalGatedOutcome.REFUSED_OUT_OF_SCOPE, base_metadata)
            return SignalGatedResult(
                self.name,
                target,
                SignalGatedOutcome.REFUSED_OUT_OF_SCOPE,
                metadata=base_metadata,
            )

        try:
            candidates = self.parse(target, raw_output)
            safe_candidates, dropped = _normalize_candidates(candidates, scope=self.scope)
        except Exception as exc:  # noqa: BLE001 — a parse error must not crash the run
            self._audit(target, SignalGatedOutcome.ERRORED, base_metadata)
            return SignalGatedResult(
                self.name,
                target,
                SignalGatedOutcome.ERRORED,
                detail=type(exc).__name__,
                metadata=base_metadata,
            )

        result_metadata = replace(
            base_metadata,
            dropped_candidates=base_metadata.dropped_candidates + dropped,
            partial_output=base_metadata.partial_output or dropped > 0,
        )
        self._audit(
            target,
            SignalGatedOutcome.EMITTED_CANDIDATES,
            result_metadata,
            include_metadata=metadata is not None and metadata.exit_code is not None,
        )
        return SignalGatedResult(
            self.name,
            target,
            SignalGatedOutcome.EMITTED_CANDIDATES,
            candidates=safe_candidates,
            detail=(f"dropped_candidates={dropped}" if dropped else ""),
            metadata=result_metadata,
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
        started = time.monotonic()
        base_metadata = SignalGatedMetadata(tool_version=self.tool_version)

        if not env.get(RECON_ENV_LIVE):
            self._audit(target, SignalGatedOutcome.SKIPPED_NOT_LIVE, base_metadata)
            return SignalGatedResult(
                self.name, target, SignalGatedOutcome.SKIPPED_NOT_LIVE, metadata=base_metadata
            )

        # Signal gate before any spawn — the §9 precondition, even on the live path.
        # Aggressive mode (opt-in) bypasses THIS gate only: the tool fires broadly even with
        # no prior class signal. Every emitted candidate still passes the oracle reconfirm
        # (or → Suspected tier), and scope/binary/memory/read-only gates below are untouched.
        # Read directly from the (scan-scoped) env — the same mechanism the surface/signal/
        # transport tuning flags use — not flag_enabled, whose contextvar branch shadows env
        # with a fixed whitelist during an active scan.
        if not self.has_signal(target) and env.get(_AGGRESSIVE_FLAG) != "1":
            self._audit(target, SignalGatedOutcome.REFUSED_NO_SIGNAL, base_metadata)
            return SignalGatedResult(
                self.name, target, SignalGatedOutcome.REFUSED_NO_SIGNAL, metadata=base_metadata
            )

        try:
            self.scope.enforce(_scope_url(target))
        except (OutOfScopeError, TypeError, ValueError):
            self._audit(target, SignalGatedOutcome.REFUSED_OUT_OF_SCOPE, base_metadata)
            return SignalGatedResult(
                self.name,
                target,
                SignalGatedOutcome.REFUSED_OUT_OF_SCOPE,
                metadata=base_metadata,
            )

        if shutil.which(self.binary) is None:
            self._audit(target, SignalGatedOutcome.SKIPPED_MISSING_BINARY, base_metadata)
            return SignalGatedResult(
                self.name,
                target,
                SignalGatedOutcome.SKIPPED_MISSING_BINARY,
                metadata=base_metadata,
            )

        free_mb = _available_memory_mb()
        if free_mb is not None and free_mb < _MIN_FREE_MEMORY_MB:
            self._audit(target, SignalGatedOutcome.SKIPPED_LOW_MEMORY, base_metadata)
            return SignalGatedResult(
                self.name,
                target,
                SignalGatedOutcome.SKIPPED_LOW_MEMORY,
                metadata=base_metadata,
            )

        try:
            argv = self.command(target, output_path)
            if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
                raise TypeError("signal-gated command must be a list of strings")
            command_metadata = replace(base_metadata, command_policy="argv:shell=false")
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
            bounded_output, partial = _collect_output(getattr(completed, "stdout", ""), output_path)
            metadata = replace(
                command_metadata,
                duration_seconds=time.monotonic() - started,
                exit_code=(
                    int(completed.returncode)
                    if type(getattr(completed, "returncode", None)) is int
                    else None
                ),
                output_chars=len(bounded_output),
                partial_output=partial,
                # Redact before preview, not after: this tier's tools (sqlmap etc.)
                # can print extracted application data in their own stdout, and a
                # future wrapper could embed a header/cookie in argv — the same
                # secret-redaction pass every candidate claim already goes through
                # (_safe_claim_text) applies here too, never the raw bytes.
                command=_safe_claim_text(" ".join(argv), 2_000),
                output_preview=_recon_output_preview(_safe_claim_text(bounded_output, 4_000)),
            )
        except FileNotFoundError:
            metadata = replace(
                base_metadata, duration_seconds=time.monotonic() - started, exit_code=None
            )
            self._audit(target, SignalGatedOutcome.SKIPPED_MISSING_BINARY, metadata)
            return SignalGatedResult(
                self.name,
                target,
                SignalGatedOutcome.SKIPPED_MISSING_BINARY,
                metadata=metadata,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            metadata = replace(base_metadata, duration_seconds=time.monotonic() - started)
            self._audit(target, SignalGatedOutcome.ERRORED, metadata, include_metadata=True)
            return SignalGatedResult(
                self.name,
                target,
                SignalGatedOutcome.ERRORED,
                detail=type(exc).__name__,
                metadata=metadata,
            )
        except Exception as exc:  # noqa: BLE001 — command/output failure is audited
            metadata = replace(base_metadata, duration_seconds=time.monotonic() - started)
            self._audit(target, SignalGatedOutcome.ERRORED, metadata, include_metadata=True)
            return SignalGatedResult(
                self.name,
                target,
                SignalGatedOutcome.ERRORED,
                detail=type(exc).__name__,
                metadata=metadata,
            )

        return self.ingest(target, bounded_output, metadata=metadata)


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
    if not isinstance(candidate, Candidate):
        raise TypeError("reconfirm_candidate requires a Candidate")
    if not all(callable(item) for item in (run_oracle, write_finding, finding_factory)):
        raise TypeError("reconfirm_candidate requires callable oracle, writer, and factory")
    try:
        get_oracle(candidate.suggested_oracle)
    except (KeyError, UnknownOracleError, TypeError):
        return None
    verdict = run_oracle(candidate.suggested_oracle, evidence)  # type: ignore[operator]
    if not isinstance(verdict, OracleVerdict):
        return None
    if verdict.mechanism is not candidate.suggested_oracle:
        return None
    if not verdict.is_violation or verdict.status.value != "confirmed_violation":
        # The tool claimed it; ReachAgent's own oracle did not confirm it → dropped.
        return None
    finding = finding_factory(candidate, verdict)  # type: ignore[operator]
    return write_finding(graph, finding, verdict)  # type: ignore[operator, no-any-return]


__all__ = [
    "SignalGatedMetadata",
    "SignalGatedOutcome",
    "SignalGatedResult",
    "SignalGatedToolRunner",
    "reconfirm_candidate",
]
