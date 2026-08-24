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
    restrict to a subtree. ``host`` may be ``*.example.com`` to match
    example.com and any sub-domain (ponytail: wildcard centralized here).
    """

    host: str
    path_prefix: str = "/"
    port: int | None = None
    allowed_schemes: frozenset[str] = frozenset({"https", "http"})

    def _host_matches(self, host: str) -> bool:
        pat = self.host.lower()
        h = host.lower()
        if pat.startswith("*."):
            base = pat[2:]
            if not base:
                return False
            return h == base or h.endswith("." + base)
        return h == pat

    def matches(self, url: httpx.URL) -> bool:
        # Host is compared case-insensitively; httpx already lowercases it, but
        # be explicit so the invariant does not depend on that.
        if url.scheme not in self.allowed_schemes:
            return False
        if not self._host_matches(url.host):
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
    fired, and no request bypasses this gate. Supports wildcard hosts
    (``*.example.com``) and an optional deny list with precedence.
    """

    def __init__(
        self,
        rules: list[ScopeRule] | None = None,
        deny_rules: list[ScopeRule] | None = None,
    ) -> None:
        self._rules: list[ScopeRule] = list(rules or [])
        self._deny: list[ScopeRule] = list(deny_rules or [])

    @classmethod
    def from_hosts(
        cls, hosts: list[str], deny_hosts: list[str] | None = None
    ) -> ScopeGuard:
        """Build a guard that allows the given hosts in full (any path).

        ``hosts`` and ``deny_hosts`` may contain ``*.example.com`` wildcards.
        """
        return cls(
            [ScopeRule(host=h) for h in hosts if h],
            [ScopeRule(host=h) for h in (deny_hosts or []) if h],
        )

    @classmethod
    def from_raw(
        cls, in_scope: str | None, out_of_scope: str | None = None
    ) -> ScopeGuard:
        """Comma-separated host patterns → guard (wildcard-aware)."""

        def _parse(raw: str | None) -> list[str]:
            if not raw:
                return []
            return [p.strip().lower() for p in raw.split(",") if p.strip()]

        return cls.from_hosts(_parse(in_scope), _parse(out_of_scope))

    def is_in_scope(self, url: str | httpx.URL) -> bool:
        """True only if some rule allows this URL in full (deny-by-default)."""
        parsed = httpx.URL(url) if isinstance(url, str) else url
        if not parsed.host:
            if isinstance(url, str):
                raw = url.strip()
                if raw and "://" not in raw:
                    authority = raw.split("/", 1)[0].strip()
                    if authority:
                        try:
                            dummy = httpx.URL(f"https://{authority}/")
                        except Exception:
                            return False
                        if any(r.matches(dummy) for r in self._deny):
                            return False
                        return any(r.matches(dummy) for r in self._rules)
            return False
        if any(rule.matches(parsed) for rule in self._deny):
            return False
        return any(rule.matches(parsed) for rule in self._rules)

    def enforce(self, url: str | httpx.URL) -> None:
        """Raise :class:`OutOfScopeError` if the URL is not allowlisted (§10)."""
        if not self.is_in_scope(url):
            parsed = httpx.URL(url) if isinstance(url, str) else url
            host = parsed.host
            path = parsed.path
            if not host and isinstance(url, str) and "://" not in url.strip():
                host = url.strip().split("/", 1)[0].split(":", 1)[0].lower()
                path = "/"
            # Report host/path only — never echo query/userinfo, which may carry
            # secrets (safety_guardrails).
            raise OutOfScopeError(f"target not in scope: {host}{path}")
