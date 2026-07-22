"""Sequential replay runner for business-logic templates (plan §5, §7, §10).

Turns an instantiated :class:`~reachagent.business_logic.templates.TemplateCheck`
into :class:`~reachagent.oracles.business_rule.BusinessRuleEvidence` by firing its
steps and reducing the responses to the baseline/violating pair the oracle diffs.

Two §10 safety properties are load-bearing here, not incidental:

  * **Sequential-replay-first.** Steps are fired strictly one after another
    through the ordinary :class:`~reachagent.execution.firer.RequestFirer`. There
    is no concurrent or single-packet delivery — that race-condition escalation
    is the deferred Phase 6 module (§7/§15). The audit log therefore shows N
    separate sequential ``fired:`` entries, never a burst.
  * **Read-only-first-safe.** A state-changing step is fired only after the
    endpoint's read-only case is cleared: the runner fires a read-only probe of
    the endpoint first, and only on a safe (non-5xx) probe does it release the
    mutation. The firer is the backstop — it refuses an uncleared mutation before
    any packet leaves — so the runner cannot smuggle an ungated mutating request.

The runner never decides a verdict: it produces evidence and hands it to
``run_oracle`` (the Validator's sole confirmation path). No LLM is in the loop.
"""

from __future__ import annotations

from dataclasses import dataclass

from reachagent.business_logic.templates import ReplayStep, StepRole, TemplateCheck
from reachagent.execution.firer import ReadOnlyFirstError, RequestFirer
from reachagent.execution.scope import OutOfScopeError
from reachagent.oracles.business_rule import BusinessRuleEvidence, ReplayObservation

# A response we could not obtain (gate-refused, transport error) reads as this
# status: the oracle normalizes it to AMBIGUOUS, never a false accept/refuse.
_NO_RESPONSE = 0


@dataclass(frozen=True)
class ReplayOutcome:
    """The evidence a check produced, plus the raw per-step statuses for audit."""

    evidence: BusinessRuleEvidence
    step_statuses: tuple[tuple[str, int], ...]


class SequentialReplayRunner:
    """Fires a template check as a sequential replay and builds oracle evidence (§10)."""

    def __init__(self, firer: RequestFirer, base_url: str) -> None:
        self._firer = firer
        self._base_url = base_url.rstrip("/")

    def run(self, identity: str, check: TemplateCheck) -> ReplayOutcome:
        """Fire ``check``'s steps sequentially and reduce them to oracle evidence.

        Returns a :class:`ReplayOutcome` carrying the
        :class:`BusinessRuleEvidence` (fed to ``run_oracle`` by the caller) and the
        per-step statuses. The last ``BASELINE`` step becomes the oracle baseline;
        the single ``VIOLATING`` step becomes the violating observation. Steps
        fire in list order — the sequential-replay guarantee.
        """
        statuses: list[tuple[str, int]] = []
        baseline_obs: ReplayObservation | None = None
        violating_obs: ReplayObservation | None = None

        for step in check.steps:
            status, body = self._fire(identity, step)
            statuses.append((step.label, status))
            obs = ReplayObservation(label=step.label, status_code=status, body=body)
            if step.role is StepRole.BASELINE:
                baseline_obs = obs
            elif step.role is StepRole.VIOLATING:
                violating_obs = obs

        # A check with no explicit baseline (all SETUP then VIOLATING) treats the
        # last non-violating step as the legitimate reference the oracle diffs.
        if baseline_obs is None:
            baseline_obs = self._implied_baseline(check, statuses)

        evidence = BusinessRuleEvidence(
            rule=check.rule,
            baseline=baseline_obs,
            violating=violating_obs or ReplayObservation("violating-missing", _NO_RESPONSE),
            evidence_ref=check.evidence_ref,
        )
        return ReplayOutcome(evidence=evidence, step_statuses=tuple(statuses))

    def _fire(self, identity: str, step: ReplayStep) -> tuple[int, str]:
        """Fire one step read-only-first-safe; return (status_code, body).

        A state-changing step is preceded by a read-only probe of the same
        endpoint so the firer's read-only-first gate is satisfied by observation,
        not bypassed. A gate refusal or transport error yields ``_NO_RESPONSE`` so
        the oracle sees no accept/refuse signal, never a fabricated one.
        """
        url = f"{self._base_url}{step.path}"
        if step.state_changing:
            self._clear_read_only(identity, step.path)
        kwargs: dict[str, object] = {}
        if step.json_body is not None:
            kwargs["json"] = dict(step.json_body)
        try:
            result = self._firer.fire(
                identity, step.method, url, state_changing=step.state_changing, **kwargs
            )
        except (OutOfScopeError, ReadOnlyFirstError):
            return _NO_RESPONSE, ""
        except Exception:  # noqa: BLE001 — a transport error is not a business signal
            return _NO_RESPONSE, ""
        return result.status_code, result.body.decode("utf-8", errors="replace")

    def _clear_read_only(self, identity: str, path: str) -> None:
        """Fire a read-only probe of ``path`` so its mutation is read-only-first-cleared.

        Best-effort and side-effect-free: a GET of the endpoint. If it is refused
        (scope) or errors, the mutation stays gated and the firer refuses it — the
        safe failure mode, never an ungated mutation.
        """
        url = f"{self._base_url}{path}"
        try:
            self._firer.fire(identity, "GET", url)
        except (OutOfScopeError, ReadOnlyFirstError, Exception):  # noqa: BLE001
            return

    @staticmethod
    def _implied_baseline(
        check: TemplateCheck, statuses: list[tuple[str, int]]
    ) -> ReplayObservation:
        """The legitimate reference for a check with only SETUP steps before the break.

        The last SETUP step's observed status stands in as the baseline: if the
        prerequisites were reachable (2xx) the flow is live, so a served
        out-of-order jump is the violation the oracle then confirms.
        """
        setup_labels = [s.label for s in check.steps if s.role is StepRole.SETUP]
        by_label = dict(statuses)
        if setup_labels:
            last = setup_labels[-1]
            return ReplayObservation(last, by_label.get(last, _NO_RESPONSE))
        return ReplayObservation("baseline-missing", _NO_RESPONSE)
