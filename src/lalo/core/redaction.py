"""The single shared secret-redaction module.

Every subsystem that renders text to a human, a log, a report, or the graph
imports these helpers instead of maintaining its own regex set — this is the one
source of truth so the redaction vocabulary can never drift between call sites.

Design: fail-closed and conservative. It is fine to over-redact a
high-entropy-but-harmless token; it is never acceptable to leak a real secret.
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
    re.compile(r"\bocx_[A-Za-z0-9_]{20,}\b"),  # OpenCodex gateway key
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
        "password", "passwd", "pwd", "secret", "token", "access_token",
        "refresh_token", "id_token", "api_key", "apikey", "key", "authorization",
        "auth", "session", "sessionid", "sid", "code", "client_secret", "otp",
        "signature", "sig",
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
    if (
        len(candidate) >= 20
        and " " not in candidate
        and _ENTROPY_CHARSET.fullmatch(candidate) is not None
        and _shannon_entropy(candidate) >= 3.5
    ):
        return True
    return False


def redact(text: str) -> str:
    """Return ``text`` with secret-shaped substrings replaced by the placeholder."""
    if not text:
        return text
    out = text
    for pattern in _TOKEN_PATTERNS:
        out = pattern.sub(REDACTION_PLACEHOLDER, out)

    def _maybe_redact(match: re.Match[str]) -> str:
        token = match.group(0)
        return REDACTION_PLACEHOLDER if looks_secret_shaped(token) else token

    return _HIGH_ENTROPY_TOKEN.sub(_maybe_redact, out)


def safe_target_url(url: str) -> str:
    """Return a URL safe to log/display: no userinfo, no fragment, sensitive
    query values redacted by key. Scheme/host/port/path are preserved so the
    target stays identifiable.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return REDACTION_PLACEHOLDER
    host = parts.hostname or ""
    netloc = f"{host}:{parts.port}" if parts.port else host  # userinfo dropped
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
