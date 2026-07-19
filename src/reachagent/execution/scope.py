"""Scope allowlist enforcement (plan §10, CLAUDE.md non-negotiables).

The allowlist is enforced at the execution layer at call time — not just
documented policy. Every request passes through :class:`ScopeGuard` before a
packet leaves the process; anything not explicitly allowed is rejected (§10).
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx


class OutOfScopeError(RuntimeError):
    """Raised when a request targets something not on the allowlist (§10).

    Raised *before* any network I/O, so an out-of-scope target never produces a
    packet.
    """


@dataclass(frozen=True)
class ScopeRule:
    """One allowlist entry: a host, optionally narrowed by port/path/scheme (§10).

    Matching is deny-by-default — a URL is in scope only if it satisfies a rule
    in full. ``path_prefix`` defaults to ``/`` (the whole host); set it to
    restrict to a subtree.
    """

    host: str
    path_prefix: str = "/"
    port: int | None = None
    allowed_schemes: frozenset[str] = frozenset({"https", "http"})

    def matches(self, url: httpx.URL) -> bool:
        # Host is compared case-insensitively; httpx already lowercases it, but
        # be explicit so the invariant does not depend on that.
        if url.scheme not in self.allowed_schemes:
            return False
        if url.host.lower() != self.host.lower():
            return False
        if self.port is not None and url.port != self.port:
            return False
        # Prefix match on path segments, so "/api" does not match "/apixyz".
        prefix = self.path_prefix.rstrip("/")
        if not prefix:
            return True
        path = url.path
        return path == prefix or path.startswith(prefix + "/")


class ScopeGuard:
    """Deny-by-default allowlist gate (§10).

    Load-bearing safety control: every request is checked here before it is
    fired, and no request bypasses this gate.
    """

    def __init__(self, rules: list[ScopeRule] | None = None) -> None:
        self._rules: list[ScopeRule] = list(rules or [])

    @classmethod
    def from_hosts(cls, hosts: list[str]) -> ScopeGuard:
        """Build a guard that allows the given hosts in full (any path)."""
        return cls([ScopeRule(host=h) for h in hosts])

    def is_in_scope(self, url: str | httpx.URL) -> bool:
        """True only if some rule allows this URL in full (deny-by-default)."""
        parsed = httpx.URL(url) if isinstance(url, str) else url
        if not parsed.host:
            return False
        return any(rule.matches(parsed) for rule in self._rules)

    def enforce(self, url: str | httpx.URL) -> None:
        """Raise :class:`OutOfScopeError` if the URL is not allowlisted (§10)."""
        if not self.is_in_scope(url):
            parsed = httpx.URL(url) if isinstance(url, str) else url
            # Report host/path only — never echo query/userinfo, which may carry
            # secrets (safety_guardrails).
            raise OutOfScopeError(f"target not in scope: {parsed.host}{parsed.path}")
