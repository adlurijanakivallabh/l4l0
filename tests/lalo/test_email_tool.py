"""Tests for the fetch_email_code agent tool: IMAP read for magic-link/OTP flows."""

from __future__ import annotations

import pytest

from lalo.identity.credentials import EmailAccount
from lalo.identity.email_tool import build_email_fetch_tool

_RAW_MESSAGE = (
    b"From: noreply@example.com\r\n"
    b"To: victim@example.com\r\n"
    b"Subject: Your verification code\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Your one-time code is 482913. It expires in 10 minutes.\r\n"
)


class _FakeImap4Ssl:
    """Stands in for imaplib.IMAP4_SSL -- same call surface, no real socket."""

    instances: list[_FakeImap4Ssl] = []
    search_result: tuple[str, list[bytes]] = ("OK", [b"1 2 3"])

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.logged_in: tuple[str, str] | None = None
        self.logged_out = False
        type(self).instances.append(self)

    def login(self, user: str, password: str) -> tuple[str, list[bytes]]:
        self.logged_in = (user, password)
        return "OK", [b"LOGIN completed"]

    def select(self, mailbox: str) -> tuple[str, list[bytes]]:
        return "OK", [b"1"]

    def search(self, charset: str | None, *criteria: str) -> tuple[str, list[bytes]]:
        return type(self).search_result

    def fetch(self, msg_id: bytes, parts: str) -> tuple[str, list[object]]:
        return "OK", [(b"3 (RFC822 {%d}" % len(_RAW_MESSAGE), _RAW_MESSAGE)]

    def logout(self) -> tuple[str, list[bytes]]:
        self.logged_out = True
        return "BYE", [b"logging out"]


class _EmptyMailboxImap4Ssl(_FakeImap4Ssl):
    search_result = ("OK", [b""])


def _account() -> EmailAccount:
    return EmailAccount(
        address="victim@example.com",
        password="MailboxSecretPass123456",
        imap_host="imap.example.com",
    )


@pytest.fixture(autouse=True)
def _reset_fake_instances():
    _FakeImap4Ssl.instances.clear()
    yield


def test_fetch_email_code_extracts_the_regex_match(monkeypatch: pytest.MonkeyPatch) -> None:
    import lalo.identity.email_tool as email_tool_module

    monkeypatch.setattr(email_tool_module.imaplib, "IMAP4_SSL", _FakeImap4Ssl)
    tool = build_email_fetch_tool({"victim": _account()})

    result = tool.run(
        {
            "account": "victim",
            "subject_contains": "verification",
            "pattern": r"one-time code is (\d+)",
        }
    )

    assert result.ok is True
    assert result.observation == "extracted: 482913"
    assert _FakeImap4Ssl.instances[0].logged_in == (
        "victim@example.com",
        "MailboxSecretPass123456",
    )
    assert _FakeImap4Ssl.instances[0].logged_out is True


def test_fetch_email_code_reports_no_match_without_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import lalo.identity.email_tool as email_tool_module

    monkeypatch.setattr(email_tool_module.imaplib, "IMAP4_SSL", _FakeImap4Ssl)
    tool = build_email_fetch_tool({"victim": _account()})

    result = tool.run({"account": "victim", "pattern": r"NOPE-(\d+)"})

    assert result.ok is False
    assert "did not match" in result.observation


def test_fetch_email_code_reports_no_messages_matched(monkeypatch: pytest.MonkeyPatch) -> None:
    import lalo.identity.email_tool as email_tool_module

    monkeypatch.setattr(email_tool_module.imaplib, "IMAP4_SSL", _EmptyMailboxImap4Ssl)
    tool = build_email_fetch_tool({"victim": _account()})

    result = tool.run({"account": "victim", "pattern": r"(\d+)"})

    assert result.ok is False
    assert "no messages matched" in result.observation


def test_fetch_email_code_rejects_an_unknown_account(monkeypatch: pytest.MonkeyPatch) -> None:
    import lalo.identity.email_tool as email_tool_module

    monkeypatch.setattr(email_tool_module.imaplib, "IMAP4_SSL", _FakeImap4Ssl)
    tool = build_email_fetch_tool({"victim": _account()})

    result = tool.run({"account": "nope", "pattern": r"(\d+)"})

    assert result.ok is False
    assert "unknown email account" in result.observation


def test_fetch_email_code_requires_account_and_pattern() -> None:
    tool = build_email_fetch_tool({"victim": _account()})
    assert tool.run({"pattern": r"(\d+)"}).ok is False
    assert tool.run({"account": "victim"}).ok is False


def test_fetch_email_code_rejects_an_invalid_regex() -> None:
    tool = build_email_fetch_tool({"victim": _account()})
    result = tool.run({"account": "victim", "pattern": "("})
    assert result.ok is False
    assert "invalid" in result.observation.lower()
