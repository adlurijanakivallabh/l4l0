"""JS / source-map mining — extract endpoints and secret-shaped strings.

Pure and dependency-free. Endpoints: quoted absolute URLs and root-relative paths
(the shapes that show up in `fetch`/`axios`/route tables). Secrets: quoted tokens
that the shared redaction heuristic flags as secret-shaped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core.redaction import looks_secret_shaped

_QUOTED = re.compile(r"""['"`]([^'"`\s]{2,2048})['"`]""")
_URL = re.compile(r"^https?://[^\s]+$")
_PATH = re.compile(r"^/(?:[A-Za-z0-9_\-./%{}:]+)?$")


@dataclass
class JsFindings:
    endpoints: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)


def mine_javascript(js_text: str) -> JsFindings:
    endpoints: list[str] = []
    secrets: list[str] = []
    seen_ep: set[str] = set()
    seen_secret: set[str] = set()
    for match in _QUOTED.finditer(js_text):
        value = match.group(1)
        if (_URL.match(value) or (_PATH.match(value) and len(value) > 1)) and value not in seen_ep:
            seen_ep.add(value)
            endpoints.append(value)
        elif looks_secret_shaped(value) and value not in seen_secret:
            seen_secret.add(value)
            secrets.append(value)
    return JsFindings(endpoints=endpoints, secrets=secrets)
