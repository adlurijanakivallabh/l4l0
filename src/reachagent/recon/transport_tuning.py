"""LLM-driven transport selection - which mechanism fires each probe.

Given an insertion point's shape, the LLM reasons about whether the probe
should fire through:
  - http: the default RequestFirer path (query/body/path/header injection)
  - browser: Playwright for form interaction / DOM insertion points
    (login forms with CSRF tokens, SPA endpoints requiring JS rendering,
    click-dependent flows)
  - proxy: a repeater-style proxy for header manipulation (auth bypass via
    header tampering, request smuggling probes)

The selected transport is advisory — it changes WHICH mechanism fires, never
WHAT is confirmed. The deterministic oracle remains the sole authority on
whether a response constitutes a finding. No oracle logic in this module.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Protocol

_log = logging.getLogger(__name__)

# The three firing mechanisms this project supports (or plans to support).
TRANSPORT_ALLOWLIST: tuple[str, ...] = ("http", "browser", "proxy")
_DEFAULT_TRANSPORT = "http"


@dataclass(frozen=True)
class TransportChoice:
    """Which mechanism should fire this probe."""

    transport: str  # one of TRANSPORT_ALLOWLIST
    rationale: str = ""


class TransportTunerClient(Protocol):
    """Thin swappable LLM boundary."""

    def propose(
        self,
        signals: dict[str, str],
        allowlist: tuple[str, ...],
    ) -> dict[str, object]:
        """Return raw JSON with transport (str) and rationale (str)."""
        ...


def build_transport_signals(graph: object, endpoint_node: str) -> dict[str, str]:
    """Collect insertion-point signals relevant to transport selection."""
    signals: dict[str, str] = {}
    try:
        ep = graph.endpoint(endpoint_node)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return {"transport_hint": _DEFAULT_TRANSPORT}
    signals["method"] = ep.method
    signals["path"] = ep.path[:120]
    content_type = ep.content_type or ""
    if content_type:
        signals["content_type"] = content_type[:60]
    params = []
    for _, p in graph.parameters_of(endpoint_node):  # type: ignore[attr-defined]
        sink = p.inferred_sink_type.value if p.inferred_sink_type else ""
        params.append(f"{p.name}({p.location}){('->' + sink) if sink else ''}")
    if params:
        signals["params"] = "; ".join(params)[:200]
    return signals


class OpenAITransportClient:
    """OpenAI-compatible implementation of the transport tuner protocol."""

    def propose(
        self,
        signals: dict[str, str],
        allowlist: tuple[str, ...],
    ) -> dict[str, object]:
        from reachagent.llm.client import build_openai_compatible_client, extract_json_object

        client = build_openai_compatible_client(tier="grunt")
        if client is None:
            raise RuntimeError("no LLM provider configured")
        sig_text = "\n".join(f"  {k}: {v}" for k, v in sorted(signals.items()))
        prompt = (
            "You are selecting a request-firing transport for an authorized"
            " security assessment. Given the insertion point's shape, choose"
            " the best mechanism:\n"
            "- http: standard query/body/path/header injection (the default)"
            "\n- browser: Playwright form interaction or DOM manipulation"
            " (for CSRF-protected forms, JS-rendered SPAs, click flows)"
            "\n- proxy: repeater-style header manipulation (for auth bypass"
            " via header tampering, X-Forwarded-For spoofing)"
            f"\nAllowed values: {', '.join(allowlist)}."
            ' Return JSON: {"transport": "http", "rationale": "why"}.'
            f"\nInsertion point:\n{sig_text}"
        )
        text = client.complete(prompt, max_tokens=1024)
        return extract_json_object(text)


def validate_transport(raw: dict[str, object]) -> TransportChoice | None:
    """Validate that raw JSON contains a valid transport name."""
    val = raw.get("transport")
    if not isinstance(val, str):
        return None
    name = val.strip().lower()
    if name not in TRANSPORT_ALLOWLIST:
        return None
    rationale = str(raw.get("rationale", ""))[:300]
    return TransportChoice(transport=name, rationale=rationale)


def propose_transport(
    graph: object,
    endpoint_node: str,
    *,
    client: TransportTunerClient | None = None,
) -> TransportChoice:
    """Select a transport for one insertion point; defaults to http on failure.

    Flag-gated (REACHAGENT_TRANSPORT_TUNING). Never crashes the scan; always
    returns a valid TransportChoice.
    """
    if not os.environ.get("REACHAGENT_TRANSPORT_TUNING"):
        return TransportChoice(transport=_DEFAULT_TRANSPORT, rationale="flag off")
    try:
        signals = build_transport_signals(graph, endpoint_node)
        tuner = client if client is not None else OpenAITransportClient()
        raw = tuner.propose(signals, TRANSPORT_ALLOWLIST)
        validated = validate_transport(raw)
        if validated is not None:
            return validated
        return TransportChoice(transport=_DEFAULT_TRANSPORT, rationale="validation fell back")
    except Exception as exc:  # noqa: BLE001 — must never crash the scan
        _log.debug("transport-tuning skipped (%s)", exc)
        return TransportChoice(transport=_DEFAULT_TRANSPORT, rationale="error fallback")
