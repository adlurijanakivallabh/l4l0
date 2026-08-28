"""Bounded, proposal-only control for the scan's adaptive phase loop.

The control layer snapshots facts, asks the model for one allowlisted
scheduling decision, and records that decision atomically.  It never owns a
request, an oracle, or a finding; those capabilities stay in the execution
layer.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Protocol

_log = logging.getLogger(__name__)

CONTROL_PHASES: tuple[str, ...] = (
    "recon",
    "endpoints",
    "payloads",
    "verification",
    "report",
)
REVISITABLE_PHASES: tuple[str, ...] = ("recon", "endpoints", "payloads", "verification")
MAX_REASSESSMENTS = 8
MAX_SNAPSHOT_ITEMS = 40
MAX_DECISION_TEXT = 300
_ACTIONS = frozenset({"continue", "skip", "revise", "revisit"})
_DEFAULT_ACTION = "continue"
_SECRET_TEXT = re.compile(
    r"(?i)(?P<key>pass(?:word|wd)?|token|bearer|secret|authorization|cookie|csrf|"
    r"api[_-]?key|access[_-]?token|id[_-]?token)\s*[=:]\s*(?P<value>[^,;\s}]+)"
)


class ControlError(RuntimeError):
    """Base class for a safely stopped control loop."""


class ScanCancelled(ControlError):
    """Raised when an operator cancels a running scan."""


class IdleTimeout(ControlError):
    """Raised when no progress is observed for the configured idle window."""


class LoopDetected(ControlError):
    """Raised when the model repeats an identical control decision."""


class ModelControlError(ControlError):
    """A provider or unusable model response, distinct from target failures."""


def _cancelled(value: object | None) -> bool:
    if value is None:
        return False
    if callable(value):
        try:
            return bool(value())
        except Exception:  # noqa: BLE001 - a broken callback fails closed below
            return True
    checker = getattr(value, "is_set", None)
    if callable(checker):
        try:
            return bool(checker())
        except Exception:  # noqa: BLE001
            return True
    return bool(value)


def check_cancel(cancel: object | None = None) -> None:
    """Fail closed when an operator cancellation token is set."""
    if _cancelled(cancel):
        raise ScanCancelled("scan cancelled by operator")


@dataclass(frozen=True)
class PhaseSnapshot:
    """Bounded deterministic state supplied to a model and the GUI."""

    run_id: str
    phase: str
    revision: int
    counts: Mapping[str, int]
    deltas: Mapping[str, int] = field(default_factory=dict)
    hosts: tuple[Mapping[str, object], ...] = ()
    services: tuple[Mapping[str, object], ...] = ()
    endpoints: tuple[Mapping[str, object], ...] = ()
    parameters: tuple[Mapping[str, object], ...] = ()
    findings: tuple[Mapping[str, object], ...] = ()
    tool_outcomes: tuple[Mapping[str, object], ...] = ()
    failed_payloads: tuple[Mapping[str, object], ...] = ()
    auth_state: Mapping[str, Mapping[str, object]] = field(default_factory=dict)
    digest: str = ""

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-safe snapshot; no response bodies or secret values."""
        return {
            "run_id": self.run_id,
            "phase": self.phase,
            "revision": self.revision,
            "counts": dict(self.counts),
            "deltas": dict(self.deltas),
            "hosts": [dict(item) for item in self.hosts],
            "services": [dict(item) for item in self.services],
            "endpoints": [dict(item) for item in self.endpoints],
            "parameters": [dict(item) for item in self.parameters],
            "findings": [dict(item) for item in self.findings],
            "tool_outcomes": [dict(item) for item in self.tool_outcomes],
            "failed_payloads": [dict(item) for item in self.failed_payloads],
            "auth_state": {str(k): dict(v) for k, v in self.auth_state.items()},
            "digest": self.digest,
        }

    def prompt_text(self) -> str:
        """Compact, deterministic JSON for the proposal-only model call."""
        return json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))


def _short(value: object, limit: int = 240) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = _SECRET_TEXT.sub(lambda match: f"{match.group('key')}=<redacted>", text)
    return re.sub(r"(?i)\bBearer\s+[^\s,;}]+", "Bearer <redacted>", text)[:limit]


def _safe_auth_state(identities: object | None) -> dict[str, Mapping[str, object]]:
    """Read only TokenStore.safe_summary() values, never private material."""
    if identities is None:
        return {}
    names = getattr(identities, "names", None)
    summary = getattr(identities, "safe_summary", None)
    token_store = getattr(identities, "token_store", None)
    if not callable(names):
        return {}
    result: dict[str, Mapping[str, object]] = {}
    for name in list(names())[:MAX_SNAPSHOT_ITEMS]:
        try:
            if callable(summary):
                value = summary(name)
            elif callable(token_store):
                store = token_store(name)
                safe = getattr(store, "safe_summary", None)
                value = safe() if callable(safe) else {}
            else:
                value = {}
            result[str(name)] = value if isinstance(value, Mapping) else {}
        except Exception:  # noqa: BLE001 - stale identity metadata is non-fatal
            result[str(name)] = {}
    return result


def build_phase_snapshot(
    graph: object,
    phase: str,
    *,
    audit: object | None = None,
    identities: object | None = None,
    run_id: str = "scan",
    revision: int = 0,
    failed_payloads: Sequence[Mapping[str, object]] = (),
) -> PhaseSnapshot:
    """Build bounded graph/audit/tool/auth facts without request data."""
    hosts_raw = list(getattr(graph, "hosts", lambda: ())())
    services_raw = list(getattr(graph, "services", lambda: ())())
    endpoints_raw = list(getattr(graph, "endpoints", lambda: ())())
    findings_raw = list(getattr(graph, "findings", lambda: ())())

    hosts = tuple(
        {
            "id": _short(node, 120),
            "hostname": _short(getattr(item, "hostname", ""), 160),
            "technology": _short(getattr(item, "technology", ""), 80),
            "version": _short(getattr(item, "detected_version", ""), 80),
        }
        for node, item in hosts_raw[:MAX_SNAPSHOT_ITEMS]
    )
    services = tuple(
        {
            "id": _short(node, 120),
            "port": int(getattr(item, "port", 0) or 0),
            "protocol": _short(getattr(item, "protocol", ""), 16),
            "name": _short(getattr(item, "service_name", ""), 80),
            "version": _short(getattr(item, "detected_version", ""), 80),
        }
        for node, item in services_raw[:MAX_SNAPSHOT_ITEMS]
    )
    endpoints = tuple(
        {
            "id": _short(node, 120),
            "method": _short(getattr(item, "method", ""), 12),
            "path": _short(getattr(item, "path", ""), 180),
            "protocol": _short(
                getattr(
                    getattr(item, "protocol", None),
                    "value",
                    getattr(item, "protocol", ""),
                ),
                20,
            ),
            "content_type": _short(getattr(item, "content_type", ""), 80),
            "restricted": _short(getattr(item, "access_restricted", ""), 16),
        }
        for node, item in endpoints_raw[:MAX_SNAPSHOT_ITEMS]
    )
    parameters: list[dict[str, object]] = []
    parameters_of = getattr(graph, "parameters_of", lambda _id: ())
    parameter_sink = getattr(graph, "parameter_sink", lambda _id: None)
    for endpoint_id, _endpoint in endpoints_raw[:MAX_SNAPSHOT_ITEMS]:
        for parameter_id, parameter in list(parameters_of(endpoint_id))[:8]:
            sink = parameter_sink(parameter_id)
            parameters.append(
                {
                    "endpoint_id": _short(endpoint_id, 120),
                    "id": _short(parameter_id, 120),
                    "name": _short(getattr(parameter, "name", ""), 80),
                    "location": _short(getattr(parameter, "location", ""), 24),
                    "sink": _short(getattr(sink, "value", sink), 32) if sink else None,
                }
            )
    findings = tuple(
        {
            "id": _short(node, 120),
            "class": _short(getattr(item, "vuln_class", ""), 80),
            "severity": _short(getattr(item, "severity", ""), 20),
            "status": _short(
                getattr(
                    getattr(item, "status", None),
                    "value",
                    getattr(item, "status", ""),
                ),
                32,
            ),
        }
        for node, item in findings_raw[:MAX_SNAPSHOT_ITEMS]
    )
    outcomes: list[dict[str, object]] = []
    audit_entries = list(getattr(audit, "entries", ()))[-MAX_SNAPSHOT_ITEMS:] if audit else []
    for entry in audit_entries:
        outcomes.append(
            {
                "identity": _short(getattr(entry, "identity", ""), 80),
                "method": _short(getattr(entry, "method", ""), 12),
                "target": _short(getattr(entry, "target", ""), 180),
                "outcome": _short(getattr(entry, "outcome", ""), 120),
            }
        )
    all_audit_entries = getattr(audit, "entries", ()) if audit else ()
    counts = {
        "hosts": len(hosts_raw),
        "services": len(services_raw),
        "endpoints": len(endpoints_raw),
        "parameters": len(parameters),
        "findings": len(findings_raw),
        "audit_entries": len(all_audit_entries),
    }
    base: dict[str, object] = {
        "run_id": run_id,
        "phase": phase,
        "revision": revision,
        "counts": counts,
        "hosts": hosts,
        "services": services,
        "endpoints": endpoints,
        "parameters": tuple(parameters[:MAX_SNAPSHOT_ITEMS]),
        "findings": findings,
        "tool_outcomes": tuple(outcomes),
        "failed_payloads": tuple(
            {str(k): _short(v, 180) for k, v in row.items()}
            for row in list(failed_payloads)[:MAX_SNAPSHOT_ITEMS]
        ),
        "auth_state": _safe_auth_state(identities),
    }
    digest = hashlib.sha256(
        json.dumps(base, sort_keys=True, default=list, separators=(",", ":")).encode()
    ).hexdigest()[:24]
    return PhaseSnapshot(**base, digest=digest)  # type: ignore[arg-type]


def build_phase_summary(graph: object, completed_phase: str) -> str:
    """Legacy compact summary retained for existing advisor callers."""
    snapshot = build_phase_snapshot(graph, completed_phase)
    if completed_phase == "recon":
        technologies = sorted(
            {
                str(row["technology"])
                for row in snapshot.hosts
                if row.get("technology") and not str(row["technology"]).startswith("wildcard")
            }
        )[:6]
        return (
            f"hosts={snapshot.counts['hosts']} endpoints={snapshot.counts['endpoints']} "
            f"technologies={technologies}"
        )
    if completed_phase == "endpoints":
        sinks = [
            f"{row.get('name')}->{row.get('sink')}"
            for row in snapshot.parameters
            if row.get("sink")
        ]
        return f"parameters-with-sinks={len(sinks)} [{'; '.join(sinks[:10])}]"
    classes = sorted(str(row.get("class", "?")) for row in snapshot.findings)
    return f"confirmed-findings={snapshot.counts['findings']} classes={classes}"


@dataclass(frozen=True)
class PhaseDecision:
    """A model proposal. It contains no execution or finding capability."""

    action: str  # continue | skip | revise | revisit
    rationale: str = ""
    hint: str = ""
    target_phase: str | None = None


class LoopAdvisorClient(Protocol):
    """Thin swappable LLM boundary for the agentic loop."""

    def advise(
        self,
        completed_phase: str,
        phase_summary: str,
        remaining_phases: tuple[str, ...],
        operator_prompt: str,
    ) -> dict[str, object]:
        """Return proposal JSON only."""
        ...


def validate_decision(raw: Mapping[str, object]) -> PhaseDecision | None:
    """Validate the model proposal; unsupported fields/actions are refused."""
    if set(raw) - {"action", "rationale", "hint", "target_phase"}:
        return None
    action = str(raw.get("action", "")).strip().lower()
    if action not in _ACTIONS:
        return None
    rationale = _short(raw.get("rationale", ""), MAX_DECISION_TEXT)
    hint = _short(raw.get("hint", ""), 200)
    target_raw = raw.get("target_phase")
    target = None if target_raw is None else str(target_raw).strip().lower()
    if target == "":
        target = None
    if target is not None and target not in CONTROL_PHASES:
        return None
    return PhaseDecision(action=action, rationale=rationale, hint=hint, target_phase=target)


class DefaultLoopAdvisor:
    """OpenAI-compatible proposal adapter."""

    def advise(
        self,
        completed_phase: str,
        phase_summary: str,
        remaining_phases: tuple[str, ...],
        operator_prompt: str,
    ) -> dict[str, object]:
        from reachagent.llm.client import build_openai_compatible_client, extract_json_object

        client = build_openai_compatible_client()
        if client is None:
            raise ModelControlError("no LLM provider configured for adaptive control")
        goal = operator_prompt[:400] if operator_prompt else "general coverage"
        prompt = (
            "You are the proposal-only control loop for an authorized security assessment. "
            f"Phase {completed_phase} just completed. Bounded state: {phase_summary}. "
            f"Remaining phases: {', '.join(remaining_phases)}. Objective: {goal}. "
            "Choose continue, skip, revise, or revisit. skip applies to target_phase (default "
            "the next phase); revise supplies a short hint; revisit requests one bounded re-check. "
            "Never emit commands, payloads, URLs, credentials, oracle statuses, findings, or "
            'request data. Return exactly {"action":"continue","rationale":"",'
            '"hint":"","target_phase":null}.'
        )
        try:
            text = client.complete(prompt, max_tokens=512)
            return extract_json_object(text)
        except ModelControlError:
            raise
        except Exception as exc:  # noqa: BLE001 - caller classifies provider failure
            raise ModelControlError(f"adaptive model failure: {type(exc).__name__}: {exc}") from exc
        finally:
            close = getattr(client, "close", None)
            if callable(close):
                close()


def reassess_after_phase(
    graph: object,
    completed_phase: str,
    remaining_phases: tuple[str, ...],
    *,
    operator_prompt: str | None = None,
    client: LoopAdvisorClient | None = None,
    strict: bool = False,
    snapshot: PhaseSnapshot | None = None,
) -> PhaseDecision | None:
    """Ask the model for a bounded proposal; target failures never become findings."""
    from reachagent.llm.runtime import llm_required

    if not os.environ.get("REACHAGENT_AGENTIC_LOOP") and not llm_required() and not strict:
        return None
    if not remaining_phases or completed_phase not in REVISITABLE_PHASES:
        return None
    try:
        summary = (
            snapshot.prompt_text()
            if snapshot is not None
            else build_phase_summary(graph, completed_phase)
        )
        advisor = client if client is not None else DefaultLoopAdvisor()
        raw = advisor.advise(completed_phase, summary, remaining_phases, operator_prompt or "")
        decision = validate_decision(raw)
        if decision is None:
            raise ModelControlError("adaptive model response failed strict decision validation")
        target = decision.target_phase
        if (
            target is not None
            and target not in remaining_phases
            and not (decision.action == "revisit" and target == completed_phase)
        ):
            raise ModelControlError(f"adaptive target phase is not remaining: {target!r}")
        return decision
    except Exception as exc:  # noqa: BLE001 - optional loop never stalls a non-strict scan
        if strict or llm_required():
            if isinstance(exc, ModelControlError):
                raise
            raise ModelControlError(f"adaptive model failure: {type(exc).__name__}: {exc}") from exc
        _log.debug("agentic-loop reassessment skipped (%s)", exc)
        return None


@dataclass
class AdaptiveControlState:
    """Durable scheduling state, independent from graph/oracle state."""

    run_id: str = "scan"
    phases: tuple[str, ...] = CONTROL_PHASES
    revision: int = 0
    completed: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    hints: dict[str, str] = field(default_factory=dict)
    revisit_counts: dict[str, int] = field(default_factory=dict)
    decisions: list[dict[str, object]] = field(default_factory=list)
    last_counts: dict[str, int] = field(default_factory=dict)
    max_decisions: int = MAX_REASSESSMENTS
    max_revisits: int = 2
    idle_timeout: float = 900.0
    checkpoint_path: str | None = None
    cancelled: bool = False
    _last_activity: float = field(default_factory=time.monotonic, repr=False)

    def __post_init__(self) -> None:
        self.phases = tuple(self.phases)
        if not self.phases or len(set(self.phases)) != len(self.phases):
            raise ValueError("control phases must be unique and non-empty")
        if self.max_decisions < 1 or self.max_revisits < 1:
            raise ValueError("control limits must be positive")
        if self.idle_timeout <= 0:
            raise ValueError("idle_timeout must be positive")
        for value in (*self.completed, *self.skipped):
            if value not in self.phases:
                raise ValueError(f"unknown control phase: {value!r}")

    @property
    def remaining(self) -> tuple[str, ...]:
        done = set(self.completed) | set(self.skipped)
        return tuple(phase for phase in self.phases if phase not in done)

    def touch(self) -> None:
        self._last_activity = time.monotonic()

    def check(self, cancel: object | None = None) -> None:
        if self.cancelled or _cancelled(cancel):
            self.cancelled = True
            raise ScanCancelled("scan cancelled by operator")
        if time.monotonic() - self._last_activity > self.idle_timeout:
            raise IdleTimeout(f"scan control loop idle for more than {self.idle_timeout:.1f}s")

    def mark_phase(self, phase: str) -> None:
        if phase not in self.phases:
            raise ValueError(f"unknown control phase: {phase!r}")
        if phase not in self.completed and phase not in self.skipped:
            self.completed.append(phase)
            self.revision += 1
        self.touch()

    def apply(self, current_phase: str, decision: PhaseDecision) -> str | None:
        """Apply scheduling-only effects and return the affected phase."""
        if current_phase not in self.phases:
            raise ValueError(f"unknown current phase: {current_phase!r}")
        if len(self.decisions) >= self.max_decisions:
            raise LoopDetected("adaptive decision budget exhausted")
        target = decision.target_phase
        if target is None:
            target = (
                current_phase
                if decision.action == "revisit"
                else (self.remaining[0] if self.remaining else current_phase)
            )
        if target not in self.phases:
            raise ValueError(f"unknown target phase: {target!r}")
        signature = (current_phase, decision.action, target, decision.hint[:100])
        if any(
            (
                item.get("phase"),
                item.get("action"),
                item.get("target_phase"),
                item.get("hint"),
            )
            == signature
            for item in self.decisions
        ):
            raise LoopDetected("repeated adaptive decision")
        if decision.action == "skip":
            if target == current_phase or target in self.completed:
                raise ValueError("skip target must be a remaining phase")
            if target not in self.skipped:
                self.skipped.append(target)
        elif decision.action == "revise":
            self.hints[target] = _short(decision.hint, 200)
        elif decision.action == "revisit":
            revisit_target = target if target in self.phases else current_phase
            count = self.revisit_counts.get(revisit_target, 0) + 1
            if count > self.max_revisits:
                raise LoopDetected(f"revisit budget exhausted for {revisit_target}")
            self.revisit_counts[revisit_target] = count
            target = revisit_target
        self.decisions.append(
            {
                "phase": current_phase,
                "action": decision.action,
                "target_phase": target,
                "rationale": _short(decision.rationale, MAX_DECISION_TEXT),
                "hint": _short(decision.hint, 200),
                "revision": self.revision,
                "timestamp": time.time(),
            }
        )
        self.revision += 1
        self.touch()
        self.save()
        return target

    def cancel(self) -> None:
        self.cancelled = True
        self.revision += 1
        self.touch()
        self.save()

    def safe_dict(self) -> dict[str, object]:
        """JSON state contains no graph bodies, headers, or authentication material."""
        return {
            "version": 1,
            "run_id": self.run_id,
            "phases": list(self.phases),
            "revision": self.revision,
            "completed": list(self.completed),
            "skipped": list(self.skipped),
            "hints": dict(self.hints),
            "revisit_counts": dict(self.revisit_counts),
            "decisions": list(self.decisions[-self.max_decisions :]),
            "last_counts": dict(self.last_counts),
            "max_decisions": self.max_decisions,
            "max_revisits": self.max_revisits,
            "idle_timeout": self.idle_timeout,
            "cancelled": self.cancelled,
        }

    def save(self, path: str | Path | None = None) -> None:
        raw_path = path if path is not None else self.checkpoint_path
        destination = Path(raw_path) if raw_path is not None else None
        if destination is None:
            return
        self.checkpoint_path = str(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            dir=str(destination.parent), prefix=f".{destination.name}.", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self.safe_dict(), handle, sort_keys=True, indent=2)
                handle.write("\n")
            os.replace(temp_name, destination)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    @classmethod
    def load(cls, path: str | Path) -> AdaptiveControlState:
        source = Path(path)
        raw = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("version") != 1:
            raise ControlError("unsupported control checkpoint")
        state = cls(
            run_id=str(raw.get("run_id", "scan")),
            phases=tuple(str(item) for item in raw.get("phases", CONTROL_PHASES)),
            revision=int(raw.get("revision", 0)),
            completed=[str(item) for item in raw.get("completed", [])],
            skipped=[str(item) for item in raw.get("skipped", [])],
            hints={str(k): str(v)[:200] for k, v in dict(raw.get("hints", {})).items()},
            revisit_counts={str(k): int(v) for k, v in dict(raw.get("revisit_counts", {})).items()},
            decisions=[dict(item) for item in raw.get("decisions", []) if isinstance(item, dict)],
            last_counts={str(k): int(v) for k, v in dict(raw.get("last_counts", {})).items()},
            max_decisions=int(raw.get("max_decisions", MAX_REASSESSMENTS)),
            max_revisits=int(raw.get("max_revisits", 2)),
            idle_timeout=float(raw.get("idle_timeout", 900.0)),
            checkpoint_path=str(source),
            cancelled=bool(raw.get("cancelled", False)),
        )
        state.touch()
        return state


class AdaptiveControlLoop:
    """Observe → propose → validate → apply, with deterministic side effects only."""

    def __init__(
        self,
        state: AdaptiveControlState,
        *,
        advisor: LoopAdvisorClient | None = None,
        operator_prompt: str = "",
        strict: bool = False,
        cancel: object | None = None,
        identities: object | None = None,
        audit: object | None = None,
    ) -> None:
        self.state = state
        self.advisor = advisor
        self.operator_prompt = operator_prompt
        self.strict = strict
        self.cancel = cancel
        self.identities = identities
        self.audit = audit

    def _safe_operator_prompt(self) -> str:
        text = self.operator_prompt
        names = getattr(self.identities, "names", None)
        redact = getattr(self.identities, "redact", None)
        if callable(names) and callable(redact):
            for name in list(names())[:MAX_SNAPSHOT_ITEMS]:
                try:
                    text = redact(name, text)
                except Exception:  # noqa: BLE001 - a redactor failure is fail-closed below
                    text = _short(text, 1_000)
        return _short(text, 1_000)

    def after_phase(
        self,
        graph: object,
        phase: str,
        *,
        failed_payloads: Sequence[Mapping[str, object]] = (),
    ) -> tuple[PhaseSnapshot, PhaseDecision | None]:
        self.state.check(self.cancel)
        snapshot = build_phase_snapshot(
            graph,
            phase,
            audit=self.audit,
            identities=self.identities,
            run_id=self.state.run_id,
            revision=self.state.revision,
            failed_payloads=failed_payloads,
        )
        deltas = {
            key: value - self.state.last_counts.get(key, 0)
            for key, value in snapshot.counts.items()
        }
        snapshot = replace(snapshot, deltas=deltas)
        self.state.last_counts = dict(snapshot.counts)
        self.state.mark_phase(phase)
        self.state.save()
        remaining = self.state.remaining
        if not remaining:
            return snapshot, None
        decision = reassess_after_phase(
            graph,
            phase,
            remaining,
            operator_prompt=self._safe_operator_prompt(),
            client=self.advisor,
            strict=self.strict,
            snapshot=snapshot,
        )
        if decision is not None:
            self.state.apply(phase, decision)
        return snapshot, decision


__all__ = [
    "AdaptiveControlLoop",
    "AdaptiveControlState",
    "CONTROL_PHASES",
    "DefaultLoopAdvisor",
    "IdleTimeout",
    "LoopAdvisorClient",
    "LoopDetected",
    "MAX_REASSESSMENTS",
    "ModelControlError",
    "PhaseDecision",
    "PhaseSnapshot",
    "REVISITABLE_PHASES",
    "ScanCancelled",
    "build_phase_snapshot",
    "build_phase_summary",
    "check_cancel",
    "reassess_after_phase",
    "validate_decision",
]
