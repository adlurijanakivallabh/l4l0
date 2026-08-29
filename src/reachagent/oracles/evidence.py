"""Typed, secret-free evidence metadata shared by deterministic oracles.

The response bodies used by the oracles may stay in the server-side fire store,
but provenance that leaves that store must be bounded and opaque.  This module
validates that small public projection: request/response handles, body
projection labels, non-sensitive headers, timing samples, and OOB channels.
It deliberately does not inspect or normalize raw response bodies; the oracle
needs those bytes for its deterministic decision and they never belong in a
verdict or UI payload.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any


class EvidenceValidationError(ValueError):
    """Raised when evidence metadata cannot be safely or deterministically used."""


_MAX_REF = 256
_MAX_PROJECTION = 2_048
_MAX_HEADER_COUNT = 64
_MAX_HEADER_VALUE = 1_024
_MAX_TIMING_SAMPLES = 2_000
_MAX_LATENCY_MS = 3_600_000.0
_MAX_CHANNELS = 128
_MAX_REASON = 256

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SENSITIVE_NAME = re.compile(
    r"(?i)(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|"
    r"api[_-]?key|access[_-]?token|id[_-]?token|csrf[_-]?token|bearer)"
)
_SENSITIVE_VALUE = re.compile(
    r"(?i)(?:bearer\s+[^\s,;]+|(?:password|passwd|secret|token|api[_-]?key|cookie|"
    r"authorization)\s*[:=]\s*[^\s,;]+)"
)
_OPAQUE_HANDLE = re.compile(
    r"(?i)(?:fire|request|response|verdict|token|session|identity|trace|req|res|resp)"
    r"(?:-|:)[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}"
)


def _is_opaque_handle(value: str) -> bool:
    return bool(_OPAQUE_HANDLE.fullmatch(value))


def _string(value: object, field: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise EvidenceValidationError(f"{field} must be a string")
    if len(value) > maximum:
        raise EvidenceValidationError(f"{field} exceeds {maximum} characters")
    if _CONTROL.search(value):
        raise EvidenceValidationError(f"{field} contains a control character")
    return value


def validate_evidence_ref(value: object, *, field: str = "evidence_ref") -> str:
    """Validate a provenance label while preserving legacy spaces and slashes."""
    text = _string(value, field, maximum=_MAX_REF)
    if text and _SENSITIVE_VALUE.search(text) and not _is_opaque_handle(text):
        raise EvidenceValidationError(f"{field} looks like it contains a secret")
    return text


def validate_reason(value: object, *, field: str = "reason") -> str:
    text = _string(value, field, maximum=_MAX_REASON)
    if text and _SENSITIVE_VALUE.search(text):
        raise EvidenceValidationError(f"{field} looks like it contains a secret")
    return text


def validate_status_code(value: object, *, field: str, allow_zero: bool = True) -> int:
    """Accept HTTP status codes plus 0 for a gate/transport refusal."""
    if type(value) is not int:  # bool is an int subclass but not a status code
        raise EvidenceValidationError(f"{field} must be an integer")
    if value == 0 and allow_zero:
        return value
    if not 100 <= value <= 599:
        raise EvidenceValidationError(f"{field} must be 0 or an HTTP status 100-599")
    return value


def validate_nonnegative_samples(
    values: object,
    *,
    field: str,
    maximum_count: int = _MAX_TIMING_SAMPLES,
    maximum_value: float = _MAX_LATENCY_MS,
) -> tuple[float, ...]:
    if not isinstance(values, (tuple, list)):
        raise EvidenceValidationError(f"{field} must be a list or tuple")
    if len(values) > maximum_count:
        raise EvidenceValidationError(f"{field} exceeds {maximum_count} samples")
    out: list[float] = []
    for index, value in enumerate(values):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise EvidenceValidationError(f"{field}[{index}] must be numeric")
        number = float(value)
        if not math.isfinite(number) or number < 0 or number > maximum_value:
            raise EvidenceValidationError(
                f"{field}[{index}] must be finite and between 0 and {maximum_value:g}"
            )
        out.append(number)
    return tuple(out)


def _validate_handle(value: object, field: str) -> str:
    text = _string(value, field, maximum=_MAX_REF)
    if text and (any(char.isspace() for char in text) or not _is_opaque_handle(text)):
        raise EvidenceValidationError(f"{field} must be an opaque, secret-free handle")
    return text


def _validate_identifier(value: object, field: str) -> str:
    text = _string(value, field, maximum=_MAX_REF)
    if text and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", text):
        raise EvidenceValidationError(f"{field} must be a bounded identifier")
    return text


def _validate_projection(value: object, field: str) -> str:
    text = _string(value, field, maximum=_MAX_PROJECTION)
    if text and _SENSITIVE_VALUE.search(text):
        raise EvidenceValidationError(f"{field} must not contain raw secret values")
    return text


def _validate_headers(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, (tuple, list)):
        raise EvidenceValidationError("headers must be a list or tuple of pairs")
    if len(value) > _MAX_HEADER_COUNT:
        raise EvidenceValidationError(f"headers exceeds {_MAX_HEADER_COUNT} entries")
    out: list[tuple[str, str]] = []
    for index, pair in enumerate(value):
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise EvidenceValidationError(f"headers[{index}] must be a name/value pair")
        name = _string(pair[0], f"headers[{index}].name", maximum=128).strip()
        header_value = _string(pair[1], f"headers[{index}].value", maximum=_MAX_HEADER_VALUE)
        if not name:
            raise EvidenceValidationError(f"headers[{index}].name cannot be empty")
        if _SENSITIVE_NAME.search(name) or _SENSITIVE_VALUE.search(header_value):
            raise EvidenceValidationError(
                f"headers[{index}] contains an authentication or secret value"
            )
        out.append((name.lower(), header_value))
    return tuple(sorted(out))


def _validate_channels(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, (tuple, list)):
        raise EvidenceValidationError("oob_channels must be a list or tuple of pairs")
    if len(value) > _MAX_CHANNELS:
        raise EvidenceValidationError(f"oob_channels exceeds {_MAX_CHANNELS} entries")
    out: list[tuple[str, str]] = []
    for index, pair in enumerate(value):
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise EvidenceValidationError(f"oob_channels[{index}] must be a nonce/channel pair")
        nonce = _validate_identifier(pair[0], f"oob_channels[{index}].nonce")
        channel = _string(pair[1], f"oob_channels[{index}].channel", maximum=64).strip().lower()
        if not channel or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", channel):
            raise EvidenceValidationError(
                f"oob_channels[{index}].channel must be a simple channel label"
            )
        out.append((nonce, channel))
    return tuple(sorted(out))


@dataclass(frozen=True)
class EvidenceMetadata:
    """Bounded provenance that is safe to expose with an oracle verdict.

    Handles are opaque references into a server-side evidence store.  Projections
    are labels/keys, not response values.  Header metadata is intentionally limited
    to non-secret response headers; raw cookies and authorization headers remain
    server-side and are never serialized here.
    """

    request_ref: str = ""
    response_ref: str = ""
    baseline_request_ref: str = ""
    baseline_response_ref: str = ""
    probe_request_ref: str = ""
    probe_response_ref: str = ""
    body_projection: str = ""
    baseline_body_projection: str = ""
    probe_body_projection: str = ""
    headers: tuple[tuple[str, str], ...] = ()
    timing_samples_ms: tuple[float, ...] = ()
    oob_channels: tuple[tuple[str, str], ...] = ()

    def validated(self) -> EvidenceMetadata:
        """Validate and normalize metadata without changing the oracle decision."""
        return EvidenceMetadata(
            request_ref=_validate_handle(self.request_ref, "request_ref"),
            response_ref=_validate_handle(self.response_ref, "response_ref"),
            baseline_request_ref=_validate_handle(
                self.baseline_request_ref, "baseline_request_ref"
            ),
            baseline_response_ref=_validate_handle(
                self.baseline_response_ref, "baseline_response_ref"
            ),
            probe_request_ref=_validate_handle(self.probe_request_ref, "probe_request_ref"),
            probe_response_ref=_validate_handle(self.probe_response_ref, "probe_response_ref"),
            body_projection=_validate_projection(self.body_projection, "body_projection"),
            baseline_body_projection=_validate_projection(
                self.baseline_body_projection, "baseline_body_projection"
            ),
            probe_body_projection=_validate_projection(
                self.probe_body_projection, "probe_body_projection"
            ),
            headers=_validate_headers(self.headers),
            timing_samples_ms=validate_nonnegative_samples(
                self.timing_samples_ms, field="timing_samples_ms"
            ),
            oob_channels=_validate_channels(self.oob_channels),
        )

    def as_dict(self) -> dict[str, Any]:
        """Return only non-empty, already validated fields for JSON/UI output."""
        item = self.validated()
        result: dict[str, Any] = {}
        for name in (
            "request_ref",
            "response_ref",
            "baseline_request_ref",
            "baseline_response_ref",
            "probe_request_ref",
            "probe_response_ref",
            "body_projection",
            "baseline_body_projection",
            "probe_body_projection",
        ):
            value = getattr(item, name)
            if value:
                result[name] = value
        if item.headers:
            result["headers"] = list(item.headers)
        if item.timing_samples_ms:
            result["timing_samples_ms"] = list(item.timing_samples_ms)
        if item.oob_channels:
            result["oob_channels"] = list(item.oob_channels)
        return result

    def as_json(self) -> str:
        return json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))


def validate_metadata_dict(metadata: object) -> dict[str, str]:
    """Validate finding metadata before it enters graph/report state."""
    if not isinstance(metadata, dict):
        raise EvidenceValidationError("finding metadata must be a dictionary")
    if len(metadata) > 32:
        raise EvidenceValidationError("finding metadata exceeds 32 fields")
    clean: dict[str, str] = {}
    for key, value in metadata.items():
        name = _string(key, "metadata key", maximum=128).strip()
        text = _string(value, f"metadata[{name!r}]", maximum=2_048)
        if not name:
            raise EvidenceValidationError("metadata key cannot be empty")
        # Opaque *_ref values are safe handles; all other secret-looking values
        # fail closed instead of relying on a best-effort redaction downstream.
        lowered_name = name.lower()
        if _SENSITIVE_NAME.search(name) and not lowered_name.endswith(("_ref", "_id")):
            raise EvidenceValidationError(f"metadata key {name!r} is secret-bearing")
        if (
            _SENSITIVE_NAME.search(name)
            and any(
                marker in lowered_name
                for marker in ("token", "password", "passwd", "secret", "bearer")
            )
            and not _is_opaque_handle(text)
        ):
            raise EvidenceValidationError(f"metadata[{name!r}] must be an opaque handle")
        if _SENSITIVE_VALUE.search(text) and not _is_opaque_handle(text):
            raise EvidenceValidationError(f"metadata[{name!r}] looks like a secret")
        clean[name] = text
    return clean


def validate_evidence_metadata(metadata: EvidenceMetadata) -> EvidenceMetadata:
    if not isinstance(metadata, EvidenceMetadata):
        raise EvidenceValidationError("evidence_metadata must be EvidenceMetadata")
    return metadata.validated()


__all__ = [
    "EvidenceMetadata",
    "EvidenceValidationError",
    "validate_evidence_metadata",
    "validate_evidence_ref",
    "validate_metadata_dict",
    "validate_nonnegative_samples",
    "validate_reason",
    "validate_status_code",
]
