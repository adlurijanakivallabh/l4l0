"""``fetch_email_code`` agent tool -- IMAP mailbox read for magic-link/OTP login flows.

A target that emails a one-time code or a magic link instead of returning it in the HTTP
response has no way to be automated through ``login_as`` (identity/tool.py), which only ever
handles session material the target hands back in its own HTTP response. This closes that gap
the same narrow way totp.py closes the TOTP-second-factor gap: one small, stdlib-only primitive
wired in as its own tool, not a new pipeline stage.

Deliberately stdlib-only (``imaplib``/``email``): basic IMAP4-over-SSL login/search/fetch needs
nothing a third-party client would add for this tool's one job (most-recent-message-matching-a-
filter), matching this project's own preference for the smallest dependency that does the job.

Connects fresh per call and always logs out in a ``finally`` -- there is no long-lived mailbox
session worth keeping around, unlike login.py's ``Session`` (which IS meant to be reused across
many subsequent calls).
"""

from __future__ import annotations

import email
import imaplib
import re
from email.message import Message

from ..agent.tools import FunctionTool, ToolResult, str_arg
from .credentials import EmailAccount


def _plain_text_body(msg: Message) -> str:
    """The message's text/plain body, joining every such part of a multipart message (a real
    MIME message routinely carries both a text/plain and a text/html alternative -- only the
    former is worth regex-matching)."""
    if not msg.is_multipart():
        payload = msg.get_payload(decode=True)
        if not isinstance(payload, bytes):
            return ""
        return payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
    parts = []
    for part in msg.walk():
        if part.get_content_type() != "text/plain":
            continue
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
    return "\n".join(parts)


def build_email_fetch_tool(accounts: dict[str, EmailAccount]) -> FunctionTool:
    def _fetch(args: dict[str, object]) -> ToolResult:
        account_name = str_arg(args, "account").strip()
        pattern = str_arg(args, "pattern").strip()
        if not account_name or not pattern:
            return ToolResult(observation="error: 'account' and 'pattern' are required", ok=False)
        account = accounts.get(account_name)
        if account is None:
            return ToolResult(
                observation=(
                    f"error: unknown email account {account_name!r} (known: {sorted(accounts)})"
                ),
                ok=False,
            )
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            return ToolResult(observation=f"error: invalid 'pattern' regex: {exc}", ok=False)

        subject_contains = str_arg(args, "subject_contains").strip()
        from_contains = str_arg(args, "from_contains").strip()
        criteria: list[str] = []
        if subject_contains:
            criteria += ["SUBJECT", f'"{subject_contains}"']
        if from_contains:
            criteria += ["FROM", f'"{from_contains}"']
        if not criteria:
            criteria = ["ALL"]

        conn: imaplib.IMAP4_SSL | None = None
        try:
            conn = imaplib.IMAP4_SSL(account.imap_host, account.imap_port)
            conn.login(account.address, account.password)
            conn.select("INBOX")
            status, data = conn.search(None, *criteria)
            if status != "OK" or not data or not data[0]:
                return ToolResult(observation="no messages matched the filter", ok=False)
            # ponytail: takes the highest sequence number as "most recent" --
            # correct for every server returning SEARCH results in mailbox
            # (delivery) order, the common case; upgrade to sorting by each
            # message's own Date header if a target server ever doesn't.
            latest_id = data[0].split()[-1]
            status, msg_data = conn.fetch(latest_id, "(RFC822)")
            if status != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
                return ToolResult(
                    observation="error: could not fetch the matched message", ok=False
                )
            raw = msg_data[0][1]
            body = _plain_text_body(email.message_from_bytes(raw))
        except Exception as exc:  # noqa: BLE001 - report every IMAP failure, never crash the agent
            return ToolResult(observation=f"error: {type(exc).__name__}: {exc}", ok=False)
        finally:
            if conn is not None:
                try:
                    conn.logout()
                except Exception:  # noqa: BLE001, S110 - best-effort cleanup, must never mask the real result
                    pass  # nothing to log: the real result (or error) is already decided above

        match = regex.search(body)
        if match is None:
            return ToolResult(
                observation=f"message found but pattern {pattern!r} did not match its body",
                ok=False,
            )
        extracted = match.group(1) if match.groups() else match.group(0)
        return ToolResult(observation=f"extracted: {extracted}")

    return FunctionTool(
        name="fetch_email_code",
        description=(
            "Read the most recent message in a pre-configured IMAP mailbox and extract a "
            "magic-link/OTP code or URL via your own regex, run against the message's "
            "plain-text body -- for target login flows that email a code instead of "
            "returning it in the HTTP response. Connects fresh per call and always logs "
            'out. args: {"account": str, "pattern": str (a regex; its first capture group '
            'is returned, or the whole match if it has none), "subject_contains": str '
            '(optional, an IMAP SUBJECT filter), "from_contains": str (optional, an IMAP '
            "FROM filter)}"
        ),
        func=_fetch,
    )
