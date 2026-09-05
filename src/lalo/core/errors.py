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

    Failover-eligible, like :class:`ProviderRefusalError`.
    """

    code = "provider_unavailable"


class AllProvidersFailedError(ProviderError):
    """Every provider in a role's failover chain failed."""

    code = "all_providers_failed"

    def __init__(self, message: str = "", *, role: str = "", failures: object = None) -> None:
        super().__init__(message, code=self.code)
        self.role = role
        self.failures = failures


class ScopeError(LaloError):
    """Base for target/engagement-scope problems."""

    code = "scope_error"


class TargetOutOfScopeError(ScopeError):
    """A request/action targets a host outside the declared engagement."""

    code = "scope_violation"


class ContainerError(LaloError):
    """The disposable runtime container failed to start, exec, or was misused."""

    code = "container_error"
