"""Pull one JSON object out of an LLM completion's free-form reply text.

Promoted from findings/review.py's own private _extract_json_object -
every LLM call site that asks for "reply with a single JSON object and
nothing else" still has to tolerate a model wrapping that object in a
sentence or two of prose, so this is shared rather than reimplemented per
call site.
"""

from __future__ import annotations

import json


def extract_json_object(text: str) -> dict[str, object] | None:
    stripped = text.strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        parsed = json.loads(stripped[start : end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None
