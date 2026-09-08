"""Turn a free-form operator request into a structured scan launch.

Mirrors findings/review.py's own _compute_review retry/fallback shape
exactly: a system prompt, a JSON-only reply, a bounded retry on a
malformed response, and a graceful (never-crashing) degrade to "found
nothing" rather than raising on a bad-but-non-fatal model reply. The one
deliberate divergence from review.py: AllProvidersFailedError propagates
here instead of degrading to a fallback value, because this runs inside
an HTTP request handler (gui/app.py's start_scan) that has a real,
structured way to surface it as an error response - review.py's own
_compute_review has no such caller and must degrade internally instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .core.json_response import extract_json_object
from .core.model_router import CompletionRequest, ModelRouter
from .prompts import render_prompt

_MAX_ATTEMPTS = 2


@dataclass(frozen=True)
class ParsedIntent:
    targets: list[str]
    exclude_targets: list[str]
    rules_of_engagement: str


_EMPTY_INTENT = ParsedIntent(targets=[], exclude_targets=[], rules_of_engagement="")


def _coerce_str_list(raw: object) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(item).strip() for item in raw if str(item).strip()]


def _parse_response(text: str) -> ParsedIntent | None:
    parsed = extract_json_object(text)
    if parsed is None:
        return None
    return ParsedIntent(
        targets=_coerce_str_list(parsed.get("targets")),
        exclude_targets=_coerce_str_list(parsed.get("exclude_targets")),
        rules_of_engagement=str(parsed.get("rules_of_engagement", "")).strip(),
    )


def parse_scan_intent(
    mission_text: str,
    router: ModelRouter,
    *,
    prompt_overrides_dir: Path | None = None,
) -> ParsedIntent:
    """Derive targets/exclusions/rules-of-engagement from ``mission_text``
    via one LLM completion. Never raises for a malformed or empty model
    reply (returns an empty :class:`ParsedIntent` instead, indistinguishable
    from "the operator named no target"); ``AllProvidersFailedError``
    propagates uncaught - see the module docstring for why.
    """
    system_prompt = render_prompt("intake", overrides_dir=prompt_overrides_dir)
    for _attempt in range(_MAX_ATTEMPTS):
        response = router.complete(
            "intake", CompletionRequest(system=system_prompt, prompt=mission_text)
        )
        parsed = _parse_response(response.text)
        if parsed is not None:
            return parsed
    return _EMPTY_INTENT
