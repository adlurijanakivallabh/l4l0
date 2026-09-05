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
    """Each character as a JS-style ``\\uXXXX`` escape — a common WAF-bypass encoding.

    A character outside the Basic Multilingual Plane (code point > 0xFFFF)
    becomes a UTF-16 surrogate pair (two escapes), matching how a JS string
    actually represents it — ``:04x``'s minimum-width formatting would
    otherwise emit a 5-digit escape for a single such character, which is not
    valid JS and silently corrupts the payload.
    """
    parts: list[str] = []
    for char in value:
        code = ord(char)
        if code <= 0xFFFF:
            parts.append(f"\\u{code:04x}")
        else:
            code -= 0x10000
            high = 0xD800 + (code >> 10)
            low = 0xDC00 + (code & 0x3FF)
            parts.append(f"\\u{high:04x}\\u{low:04x}")
    return "".join(parts)


def html_entity_encode(value: str) -> str:
    """Each character as a decimal HTML numeric character reference."""
    return "".join(f"&#{ord(c)};" for c in value)
