"""Pure payload-string mutations: encoding variants a skill can apply mechanically.

Zero judgment: these functions transform a string, they never decide whether
a target is vulnerable or which technique to try — that reasoning belongs to
the agent (Phase 5) and the skill library (Phase 11). See the package
docstring for why this phase stops here rather than building a structured
payload corpus.
"""

from __future__ import annotations

import urllib.parse


def url_encode(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def double_url_encode(value: str) -> str:
    return url_encode(url_encode(value))


def unicode_escape(value: str) -> str:
    """Each character as a JS-style ``\\uXXXX`` escape — a common WAF-bypass encoding."""
    return "".join(f"\\u{ord(c):04x}" for c in value)


def html_entity_encode(value: str) -> str:
    """Each character as a decimal HTML numeric character reference."""
    return "".join(f"&#{ord(c)};" for c in value)
