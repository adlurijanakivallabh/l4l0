"""``login``/``jwt`` agent tools — the missing wiring between Phase 8's library
code and an actual agent's tool registry.

``login_as`` deliberately does not let the agent construct a
:class:`~lalo.identity.login.LoginScheme` from scratch: a scheme encodes exactly
how one specific target authenticates (field names, encoding, where the session
material lands) — operator/engagement-setup knowledge, not something an LLM
should be guessing at per call. The tool instead dispatches by name against a
pre-registered ``schemes`` map, so the agent's own decision is only ever "log in
as identity X using scheme Y" - matching how ``mcp_*`` tools dispatch by name
against a pre-registered allowlist rather than accepting an arbitrary
connection spec. A successful login is registered via
:class:`~lalo.identity.login.SessionRegistry` in the same call, preserving the
"no usable session without a graph node" invariant :mod:`lalo.identity.login`
was built around - this tool is the only agent-facing path to a session, so
there is no way to route around that invariant.

``jwt`` wraps the three pure tamper primitives behind one dispatch-by-``op``
tool (mirroring :mod:`lalo.integrations.mcp_client`'s
dispatch-by-``tool``-name shape) rather than three separate tools for three
one-line functions.

``check_session_valid`` closes a real gap a reference platform's own
cross-agent session-sharing design named but L4L0 never had any equivalent
of: :class:`~lalo.identity.login.SessionRegistry.get` only ever confirms a
session's graph node still exists, never that the target server still
honors the session material itself — a silently-expired session currently
just surfaces as ordinary 401s on whatever `http` call happens to hit it
next, with nothing telling the agent to treat that as staleness rather than
a new finding. Deliberately NOT a pre-configured field on
:class:`~lalo.identity.login.LoginScheme` (no universal "am I still logged
in" endpoint exists across targets) and NOT automatic (no silent background
network call hidden from the agent) — the agent supplies its own
already-discovered validate_url per call, matching this project's own
agent-judgment-over-fixed-pipeline design rather than a studied reference
agent's own config-driven revalidation.
"""

from __future__ import annotations

from ..agent.tools import FunctionTool, ToolResult, str_arg
from ..core.errors import JwtMalformedError, LoginFailedError, SessionNotMirroredError
from ..core.redaction import shared_redactor
from ..execution.firer import HttpFirer
from .credentials import IdentityStore
from .jwt_tools import jwt_alg_none, jwt_crack_secret, jwt_decode, jwt_with_claim
from .login import LoginScheme, SessionRegistry, login


def build_login_tool(
    firer: HttpFirer,
    identities: IdentityStore,
    sessions: SessionRegistry,
    schemes: dict[str, LoginScheme],
) -> FunctionTool:
    def _login(args: dict[str, object]) -> ToolResult:
        identity_id = str_arg(args, "identity_id").strip()
        scheme_name = str_arg(args, "scheme").strip()
        if not identity_id or not scheme_name:
            return ToolResult(
                observation="error: 'identity_id' and 'scheme' are required", ok=False
            )
        scheme = schemes.get(scheme_name)
        if scheme is None:
            return ToolResult(
                observation=f"error: unknown scheme {scheme_name!r} (known: {sorted(schemes)})",
                ok=False,
            )
        try:
            identity = identities.get(identity_id)
        except KeyError:
            return ToolResult(
                observation=f"error: unknown identity {identity_id!r} (known: {identities.ids()})",
                ok=False,
            )
        try:
            session = login(firer, identity, scheme)
        except LoginFailedError as exc:
            return ToolResult(observation=f"error: {exc}", ok=False)
        # The session material is the agent's own captured credential to
        # actively reuse in subsequent `http` calls, not a third-party secret
        # to withhold from it - but it must never leak into a LOG line if one
        # is ever printed, so it joins the same shared redactor
        # IdentityStore.add() already registers the underlying password/token
        # into.
        shared_redactor().register_secret(session.value)
        sessions.register(session)
        header_name, header_value = session.auth_header()
        return ToolResult(
            observation=(
                f"logged in as {identity_id} (session {session.id}). Attach this header to "
                f"subsequent http calls to act as this session: {header_name}: {header_value}"
            )
        )

    return FunctionTool(
        name="login_as",
        description=(
            "Authenticate a pre-configured identity using a pre-configured login scheme, "
            "and register the resulting session on the graph. Returns the header to attach "
            'to subsequent http calls. args: {"identity_id": str, "scheme": str}'
        ),
        func=_login,
    )


def build_session_check_tool(firer: HttpFirer, sessions: SessionRegistry) -> FunctionTool:
    def _check(args: dict[str, object]) -> ToolResult:
        session_id = str_arg(args, "session_id").strip()
        validate_url = str_arg(args, "validate_url").strip()
        if not session_id or not validate_url:
            return ToolResult(
                observation="error: 'session_id' and 'validate_url' are required", ok=False
            )
        try:
            session = sessions.get(session_id)
        except SessionNotMirroredError:
            return ToolResult(observation=f"error: unknown session {session_id!r}", ok=False)
        header_name, header_value = session.auth_header()
        result = firer.fire("GET", validate_url, headers={header_name: header_value})
        if not result.fired:
            reason = result.scope_reason + (f" ({result.error})" if result.error else "")
            return ToolResult(observation=f"could not check: {reason}", ok=False)
        valid = result.status is not None and result.status < 400
        return ToolResult(
            observation=(
                f"session {session_id} looks "
                f"{'valid' if valid else 'stale'} (validate_url responded {result.status})"
            ),
            ok=valid,
        )

    return FunctionTool(
        name="check_session_valid",
        description=(
            "Fire a request to validate_url (a URL you know only succeeds while "
            "authenticated, e.g. a profile/whoami endpoint) using an already-registered "
            "session's own auth header, to check whether the session is still accepted "
            "before relying on it further. A non-2xx/3xx response is reported as stale, "
            'not proof of anything else. args: {"session_id": str, "validate_url": str}'
        ),
        func=_check,
    )


def build_jwt_tool() -> FunctionTool:
    def _jwt(args: dict[str, object]) -> ToolResult:
        op = str_arg(args, "op").strip()
        token = str_arg(args, "token").strip()
        if not op or not token:
            return ToolResult(observation="error: 'op' and 'token' are required", ok=False)
        try:
            if op == "decode":
                decoded = jwt_decode(token)
                return ToolResult(observation=f"header={decoded.header} payload={decoded.payload}")
            if op == "alg_none":
                return ToolResult(observation=jwt_alg_none(token))
            if op == "with_claim":
                claim = str_arg(args, "claim").strip()
                if not claim:
                    return ToolResult(
                        observation="error: 'claim' is required for op=with_claim", ok=False
                    )
                return ToolResult(observation=jwt_with_claim(token, claim, args.get("value")))
            if op == "crack_secret":
                raw_candidates = args.get("candidates")
                if not isinstance(raw_candidates, list) or not raw_candidates:
                    return ToolResult(
                        observation=(
                            "error: 'candidates' (a non-empty list of strings) is required "
                            "for op=crack_secret"
                        ),
                        ok=False,
                    )
                candidates = [str(c) for c in raw_candidates]
                algorithm = str_arg(args, "algorithm", "HS256").strip() or "HS256"
                try:
                    found = jwt_crack_secret(token, candidates, algorithm=algorithm)
                except ValueError as exc:
                    return ToolResult(observation=f"error: {exc}", ok=False)
                if found is None:
                    return ToolResult(observation=f"no match among {len(candidates)} candidate(s)")
                return ToolResult(observation=f"MATCH: secret is {found!r}")
        except JwtMalformedError as exc:
            return ToolResult(observation=f"error: {exc}", ok=False)
        return ToolResult(
            observation=(
                f"error: unknown op {op!r} (valid: decode, alg_none, with_claim, crack_secret)"
            ),
            ok=False,
        )

    return FunctionTool(
        name="jwt",
        description=(
            "Decode or tamper a JWT (no signature verification for decode/alg_none/with_claim "
            "- those are pure helpers, you decide what to do with the result via the http "
            "tool). crack_secret DOES verify: it HMACs each candidate against the token's own "
            "signing input and reports a real match. args: "
            '{"op": "decode"|"alg_none"|"with_claim"|"crack_secret", "token": str, '
            '"claim": str (required for with_claim), "value": any (required for with_claim), '
            '"candidates": list[str] (required for crack_secret - a SMALL, curated list of '
            "likely weak/default secrets, e.g. a dozen common defaults or ones seen in this "
            "engagement's own source/config - never load an entire wordlist file into one "
            "list: that both defeats the point of a curated guess and risks exhausting "
            'container memory), "algorithm": "HS256"|"HS384"|"HS512" (optional for '
            "crack_secret, default HS256)}"
        ),
        func=_jwt,
    )
