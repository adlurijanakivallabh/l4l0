"""The single shared secret-redaction module — used universally.

Two mechanisms in one instance, informed by a reference project's own
architecture-comparison notes on its redaction engine: it has both an
exact-match layer (its own configured credentials, by literal string) and a
pattern-based layer, built via a shared singleton — but the comparison explicitly
flags that engine as *inconsistently applied* (wired into one write path, not
universally). This module fixes that gap: every subsystem that renders text to a
human, a log, a report, or the graph imports these helpers instead of
maintaining its own regex set, so there is exactly one place redaction can drift
and exactly one place everything must route through.

- Pattern-based: catches secrets *discovered on the target* (an unknown API key
  shape, a leaked JWT) that were never configured anywhere.
- Exact-match: catches the operator's *own* configured credentials verbatim (an
  LLM provider key, a login password) even when they don't match any known shape.

Design: fail-closed and conservative. Over-redacting a high-entropy-but-harmless
token is fine; leaking a real secret is not.
"""

from __future__ import annotations

import math
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTION_PLACEHOLDER = "«REDACTED»"

# Known secret-shaped token patterns (checked first, before the entropy heuristic).
_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"),  # JWT
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),  # AWS temp access key id
    re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"),  # GitHub PAT
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),  # GitHub fine-grained PAT
    re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{20,}\b"),  # GitHub oauth/refresh/server tokens
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),  # Anthropic key (before generic sk-)
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),  # OpenAI-style secret key
    re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"),  # Stripe live secret
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),  # Google API key
    re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}\b"),  # Google OAuth access token
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),  # Slack token
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),  # PEM private key
    # key=value / key: value forms for obviously sensitive keys
    re.compile(
        r"(?i)\b(?:bearer|authorization|token|api[_-]?key|secret|client[_-]?secret"
        r"|password|passwd|pwd)\b\s*[=:]\s*\S+"
    ),
    # JSON-style "key": "value" forms for sensitive keys
    re.compile(
        r'(?i)"(?:password|passwd|pwd|secret|token|access_token|refresh_token'
        r'|api[_-]?key|client_secret|authorization)"\s*:\s*"[^"]+"'
    ),
)

# Query/param/form keys whose *values* are redacted by name.
_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "key",
        "authorization",
        "auth",
        "session",
        "sessionid",
        "sid",
        "code",
        "client_secret",
        "otp",
        "signature",
        "sig",
    }
)

# Fixed, pre-approved user-facing messages — mapped from an error code, never
# built from a raw exception string.
_ERROR_MESSAGES: dict[str, str] = {
    "config_error": "Configuration is invalid or incomplete.",
    "provider_error": "A model provider call failed.",
    "provider_refusal": "The model provider declined this request.",
    "provider_unavailable": "The model provider is currently unavailable.",
    "all_providers_failed": "All configured model providers failed.",
    "scope_error": "A scope check failed.",
    "scope_violation": "Target is outside the declared engagement scope.",
    "container_error": "The runtime container failed.",
    "resume_config_mismatch": "This scan's saved state doesn't match the current config.",
    "unknown": "An unexpected error occurred.",
}

_ENTROPY_CHARSET = re.compile(r"[A-Za-z0-9+/=_\-]+")
_HIGH_ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def looks_secret_shaped(value: str) -> bool:
    """Heuristic: does ``value`` look like a credential/token/secret?

    True for known token shapes (JWT, cloud keys, provider keys, ``bearer=...``)
    and for long, high-entropy, whitespace-free base64/hex-ish blobs.
    """
    candidate = value.strip()
    if len(candidate) < 16:
        return False
    for pattern in _TOKEN_PATTERNS:
        if pattern.search(candidate):
            return True
    return bool(
        len(candidate) >= 20
        and " " not in candidate
        and _ENTROPY_CHARSET.fullmatch(candidate) is not None
        and _shannon_entropy(candidate) >= 3.5
    )


class SecretRedactor:
    """Combines pattern-based detection with exact-match of registered secrets.

    One instance is the shared, universal entry point (see the module-level
    ``redact`` convenience below) — every subsystem routes through it rather than
    building its own partial coverage, which is precisely the gap a reference
    redaction engine's own comparison notes flagged (a single shared replacer
    that several call sites simply never wired themselves into).
    """

    def __init__(self) -> None:
        self._exact_secrets: set[str] = set()

    def register_secret(self, value: str) -> None:
        """Register an operator-configured credential for exact-match redaction.

        Catches secrets that don't match any known *shape* (a provider key with
        an unusual format, a login password) as long as they're at least 6 chars
        — short enough values are skipped to avoid redacting common words.
        """
        value = value.strip()
        if len(value) >= 6:
            self._exact_secrets.add(value)

    def redact(self, text: str) -> str:
        if not text:
            return text
        out = text
        # Longest first: if one registered secret is a substring of another
        # (e.g. a key and a truncated/rotated variant of it), redacting the
        # shorter one first would consume part of the longer one's own match,
        # leaking its remainder in plaintext. Set iteration order is otherwise
        # unspecified, so this isn't just a tidiness choice — without it the
        # leak is real but silently order-dependent (seen on most, not all,
        # hash seeds).
        for secret in sorted(self._exact_secrets, key=len, reverse=True):
            if secret in out:
                out = out.replace(secret, REDACTION_PLACEHOLDER)
        for pattern in _TOKEN_PATTERNS:
            out = pattern.sub(REDACTION_PLACEHOLDER, out)

        def _maybe_redact(match: re.Match[str]) -> str:
            token = match.group(0)
            return REDACTION_PLACEHOLDER if looks_secret_shaped(token) else token

        return _HIGH_ENTROPY_TOKEN.sub(_maybe_redact, out)


# The shared, universal instance. Register operator secrets onto this one object
# (e.g. from config loading) so every call site's `redact()` benefits immediately.
_SHARED = SecretRedactor()


def shared_redactor() -> SecretRedactor:
    """Return the one shared redactor instance — register secrets onto this."""
    return _SHARED


def redact(text: str) -> str:
    """Redact ``text`` through the shared instance. The universal entry point."""
    return _SHARED.redact(text)


def safe_target_url(url: str) -> str:
    """Return a URL safe to log/display: no userinfo, no fragment, sensitive
    query values redacted by key. Scheme/host/port/path are preserved so the
    target stays identifiable.
    """
    try:
        parts = urlsplit(url)
        port = parts.port  # lazily parsed/validated; raises ValueError on a non-numeric port
    except ValueError:
        return REDACTION_PLACEHOLDER
    host = parts.hostname or ""
    netloc = f"{host}:{port}" if port else host  # userinfo dropped
    query = urlencode(
        [
            (key, REDACTION_PLACEHOLDER if key.lower() in _SENSITIVE_KEYS else value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
        ]
    )
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def safe_error_from_code(code: str) -> str:
    """Map a stable error code to a fixed, pre-approved message.

    Never returns raw exception text — the whole point is that nothing derived
    from an untrusted source can leak through an error string.
    """
    return _ERROR_MESSAGES.get(code, _ERROR_MESSAGES["unknown"])


def normalize_semantic_label(label: str) -> str:
    """Normalize a free-text label into a stable, safe slug (``[a-z0-9_]+``)."""
    slug = re.sub(r"[^a-z0-9]+", "_", label.strip().lower()).strip("_")
    return slug or "unlabeled"
