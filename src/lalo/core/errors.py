"""Typed exception hierarchy for L4L0.

Every raised error carries a stable ``code`` so callers can map it to a fixed,
pre-approved user-facing message via :func:`lalo.core.redaction.safe_error_from_code`
without ever leaking a raw exception string.
"""

from __future__ import annotations


class LaloError(Exception):
    """Base class for every L4L0 error. Carries a stable, redaction-safe code."""

    code: str = "unknown"

    def __init__(self, message: str = "", *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class ConfigError(LaloError):
    """Configuration is missing, malformed, or internally inconsistent."""

    code = "config_error"


class ProviderError(LaloError):
    """Base for LLM-provider failures handled by the model router."""

    code = "provider_error"

    def __init__(self, message: str = "", *, provider: str = "", code: str | None = None) -> None:
        super().__init__(message, code=code)
        self.provider = provider


class ProviderRefusalError(ProviderError):
    """The provider declined the request (e.g. a safety classifier).

    The router treats this as failover-eligible: try the next provider in the
    role's chain rather than aborting the run.
    """

    code = "provider_refusal"


class ProviderUnavailableError(ProviderError):
    """The provider is unreachable / transiently failing (transport, 5xx, rate limit).

    Failover-eligible, like :class:`ProviderRefusalError`. ``retryable``
    (default True) is False for a failure no amount of waiting can fix -
    currently just an authentication/authorization failure (401/403): a
    revoked or invalid credential stays invalid no matter how long
    :meth:`~lalo.agent.loop.AgentLoop._retry_through_provider_outage` waits.
    """

    code = "provider_unavailable"

    def __init__(self, message: str = "", *, provider: str = "", retryable: bool = True) -> None:
        super().__init__(message, provider=provider)
        self.retryable = retryable


class AllProvidersFailedError(ProviderError):
    """Every provider in a role's failover chain failed.

    ``failures`` (per-provider ``(name, reason)`` pairs) is folded directly
    into the exception's own message, not just stored as an attribute: every
    raise site was building this list and then discarding it when the
    exception reached a plain ``str(exc)`` caller (the GUI's scan_failed
    status event, in particular) — an operator with a broken/expired
    credential saw only "every configured provider failed preflight
    verification" with zero indication of *why*, defeating the entire point
    of a preflight check that exists specifically to surface that early.
    """

    code = "all_providers_failed"

    def __init__(
        self,
        message: str = "",
        *,
        role: str = "",
        failures: list[tuple[str, str]] | None = None,
    ) -> None:
        self.role = role
        self.failures = failures or []
        if self.failures:
            detail = "; ".join(f"{name}: {reason}" for name, reason in self.failures)
            message = f"{message} ({detail})" if message else detail
        super().__init__(message, code=self.code)

    @property
    def all_non_retryable(self) -> bool:
        """True only if every single failure this run collected was
        non-retryable (see :class:`ProviderUnavailableError`'s own
        ``retryable`` flag) - used to skip the outer outage-retry wait
        entirely when nothing about it could possibly succeed, never to
        suppress or hide any failure detail. ``failures``' own ``code``
        element (see :meth:`~lalo.core.model_router.ModelRouter.complete`)
        carries this as a ``"_non_retryable"`` suffix rather than widening
        the tuple shape every existing consumer already destructures."""
        return bool(self.failures) and all(
            code.endswith("_non_retryable") for _name, code in self.failures
        )


class ScopeError(LaloError):
    """Base for target/engagement-scope problems."""

    code = "scope_error"


class TargetOutOfScopeError(ScopeError):
    """A request/action targets a host outside the declared engagement."""

    code = "scope_violation"


class TargetUnreachableError(LaloError):
    """A declared target failed its reachability preflight and the operator
    opted into treating that as fatal (``ScanConfig.fail_on_unreachable_targets``).

    Off by default: an in-engagement network/infra or raw-TCP target may
    simply not speak HTTP at all, which the HEAD-request preflight probe
    cannot distinguish from a genuine misconfiguration - see
    :func:`~lalo.execution.firer.probe_reachability`'s own docstring. This
    error exists only for an operator who knows their targets are
    HTTP-reachable and wants an unreachable one to hard-stop the scan rather
    than merely log a preflight warning and proceed.
    """

    code = "target_unreachable"


class ContainerError(LaloError):
    """The disposable runtime container failed to start, exec, or was misused."""

    code = "container_error"


class SpawnDepthExceededError(LaloError):
    """A spawn_agent call would exceed the multi-agent tree's hard depth ceiling."""

    code = "spawn_depth_exceeded"


class LoginFailedError(LaloError):
    """A login attempt for an identity did not produce a usable session."""

    code = "login_failed"


class SessionNotMirroredError(LaloError):
    """A session id has no corresponding graph node, so it cannot be retrieved.

    Enforces the invariant that no usable session exists without a visible
    graph node — closing a starvation-bug class where a session created but
    never mirrored onto the graph would be silently invisible to any later
    coverage check that only walks the graph.
    """

    code = "session_not_mirrored"


class JwtMalformedError(LaloError):
    """A JWT string did not have the expected header.payload.signature shape."""

    code = "jwt_malformed"


class TotpSecretError(LaloError):
    """A TOTP secret was not valid base32."""

    code = "totp_secret_invalid"


class ResumeConfigMismatchError(LaloError):
    """A resumed scan's config doesn't match the manifest recorded on first start.

    Informed by a reference agent's own ``--resume`` identity contract (hashes
    both roles' full prompt+schema, plus target list/effort, and refuses to
    resume on a mismatch): resuming a crashed scan against a *different*
    mission, target list, or budget ceiling than the one originally
    authorized would let scope/policy silently drift across a crash, exactly
    the risk that reference's own check exists to rule out. Raised before any
    step is replayed or any new work starts.
    """

    code = "resume_config_mismatch"


class CostLimitExceededError(LaloError):
    """A run's cumulative estimated spend has crossed an operator-set ceiling.

    Raised AFTER the triggering usage is persisted (see
    :func:`lalo.core.usage.record_usage`), never before — the API call that
    crossed the ceiling already happened and already cost real money, so the
    ledger must reflect that regardless of whether the caller then stops the
    run. A reference agent's own equivalent check runs before its ledger
    update, meaning the interaction that actually tipped it over is never
    recorded — an inaccurate ledger at the exact moment accuracy matters most.
    """

    code = "cost_limit_exceeded"

    def __init__(
        self, message: str = "", *, total_cost_usd: float = 0.0, limit_usd: float = 0.0
    ) -> None:
        super().__init__(message, code=self.code)
        self.total_cost_usd = total_cost_usd
        self.limit_usd = limit_usd
