"""Multi-scheme login and the session-mirrors-onto-the-graph invariant.

Reads for this phase confirmed there is no reference analog for the second
half of this module (a mechanical "no usable session without a graph node"
invariant is an original L4L0 mechanism) — every reference either has no
graph at all (Phase 7's finding) or, per `exploit-auth.txt`'s own workflow,
tracks session/exploitation state purely through prose deliverables and a
`todo_write` scratchpad the model itself maintains, with nothing enforcing
that a session an agent obtained is ever recorded anywhere durable. This
closes that starvation-bug class by construction: :class:`SessionRegistry`
is the only way to make a session retrievable, and it writes the session's
graph node in the same call that stores it — there is no code path that
hands back a usable session without a corresponding node an agent's own
coverage check would see.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from http.cookies import SimpleCookie
from urllib.parse import urlencode

from ..core.errors import LoginFailedError, SessionNotMirroredError, TotpSecretError
from ..execution.firer import HttpFirer
from ..graph import NodeKind, ReachabilityGraph
from .credentials import Identity
from .totp import generate_totp


class BodyEncoding(StrEnum):
    FORM = "form"
    JSON = "json"


class SessionSource(StrEnum):
    COOKIE = "cookie"  # session material comes from a Set-Cookie response header
    JSON_FIELD = "json_field"  # session material is a field in the JSON response body
    HEADER = "header"  # a static credential sent as a header — no login request at all


@dataclass(frozen=True)
class LoginScheme:
    """How to authenticate one identity and where its session material lands."""

    login_url: str | None = None
    method: str = "POST"
    body_encoding: BodyEncoding = BodyEncoding.JSON
    username_field: str = "username"
    password_field: str = "password"  # noqa: S105 - a JSON/form field name, not a literal secret
    session_source: SessionSource = SessionSource.COOKIE
    # Cookie name / JSON field name / static header name, per session_source.
    session_field: str = "session"
    # A base32 TOTP secret, when the target's login flow requires a second
    # factor -- operator/engagement-setup knowledge (the enrolled secret),
    # exactly like username_field/password_field above, never something an
    # agent supplies or guesses at per call.
    totp_secret: str | None = None  # noqa: S105 - a field name, not a literal secret
    totp_field: str = "otp"


@dataclass(frozen=True)
class Session:
    id: str
    identity_id: str
    kind: SessionSource
    name: str
    value: str

    def auth_header(self) -> tuple[str, str]:
        """The ``(header_name, header_value)`` a later request attaches to act as this session."""
        if self.kind is SessionSource.COOKIE:
            return "Cookie", f"{self.name}={self.value}"
        if self.kind is SessionSource.HEADER:
            return self.name, self.value
        return "Authorization", f"Bearer {self.value}"


def _extract_cookie(headers: dict[str, str], name: str) -> str | None:
    raw = headers.get("set-cookie")
    if not raw:
        return None
    # ponytail: comma-split cookie parsing via stdlib SimpleCookie is correct for
    # the common case but can misparse if a cookie's own Expires attribute (which
    # contains a comma, e.g. "Wed, 21 Oct...") collides with a second joined
    # cookie -- httpx's dict() view already collapses multiple Set-Cookie headers
    # into one comma-joined string before this ever sees it. Upgrade path: read
    # the raw multi-value header list directly instead of the collapsed dict.
    jar: SimpleCookie = SimpleCookie()
    jar.load(raw)
    morsel = jar.get(name)
    return morsel.value if morsel else None


def _extract_json_field(body: bytes, field: str) -> str | None:
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    value = data.get(field) if isinstance(data, dict) else None
    return value if isinstance(value, str) else None


def login(firer: HttpFirer, identity: Identity, scheme: LoginScheme) -> Session:
    """Authenticate ``identity`` per ``scheme`` and return its session.

    Fires the real login request through the same scope-checked, pinned-IP
    :class:`~lalo.execution.firer.HttpFirer` every other request uses — login
    is not a bypass of the scope guard.
    """
    session_id = f"session-{identity.id}"

    if scheme.session_source is SessionSource.HEADER:
        return Session(
            id=session_id,
            identity_id=identity.id,
            kind=SessionSource.HEADER,
            name=scheme.session_field,
            value=identity.credential.value,
        )

    if scheme.login_url is None:
        raise LoginFailedError(f"login scheme for identity {identity.id} has no login_url")

    fields = {
        scheme.username_field: identity.username,
        scheme.password_field: identity.credential.value,
    }
    if scheme.totp_secret is not None:
        try:
            fields[scheme.totp_field] = generate_totp(scheme.totp_secret)
        except TotpSecretError as exc:
            raise LoginFailedError(
                f"login scheme for identity {identity.id} has an invalid totp_secret: {exc}"
            ) from exc
    if scheme.body_encoding is BodyEncoding.JSON:
        content = json.dumps(fields).encode("utf-8")
        headers = {"Content-Type": "application/json"}
    else:
        content = urlencode(fields).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

    result = firer.fire(scheme.method, scheme.login_url, headers=headers, content=content)
    if not result.fired or result.status is None or result.status >= 400:
        raise LoginFailedError(
            f"login for identity {identity.id} failed: fired={result.fired} status={result.status}"
        )

    if scheme.session_source is SessionSource.COOKIE:
        material = _extract_cookie(result.headers, scheme.session_field)
    else:
        material = _extract_json_field(result.body, scheme.session_field)

    if not material:
        # Rejects an empty string, not just an absent field — a common failed-
        # login response shape is a 200 with the session cookie/field cleared
        # to "" (e.g. Set-Cookie: session=;), which `is None` alone would let
        # through as a "successful" login with a useless empty credential.
        raise LoginFailedError(
            f"login for identity {identity.id} succeeded but no session material was found"
        )

    return Session(
        id=session_id,
        identity_id=identity.id,
        kind=scheme.session_source,
        name=scheme.session_field,
        value=material,
    )


class SessionRegistry:
    """The only way to make a :class:`Session` retrievable elsewhere in the system.

    ``register`` writes the session's node to the graph in the same call that
    stores the session itself, so there is no window where a session exists
    only in memory and not on the graph. ``get`` re-checks the graph node
    still exists before returning — a session removed from the graph becomes
    unusable, never a stale side-channel handle.
    """

    def __init__(self, graph: ReachabilityGraph) -> None:
        self._graph = graph
        self._sessions: dict[str, Session] = {}

    def register(self, session: Session) -> None:
        self._graph.add_node(
            session.id,
            NodeKind.SESSION,
            identity_id=session.identity_id,
            session_kind=session.kind.value,
        )
        self._sessions[session.id] = session

    def get(self, session_id: str) -> Session:
        if not self._graph.has_node(session_id):
            raise SessionNotMirroredError(f"session {session_id} has no graph node")
        return self._sessions[session_id]
