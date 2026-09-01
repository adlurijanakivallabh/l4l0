"""Default-credential login (§7, Build Order 0).

Tries a small, fixed set of well-known username/password pairs against a
discovered login form via the same ``submit_login`` mechanism already used
for a real operator-supplied identity (``reachagent.identity.login``) — a
successful attempt already proves the case: ``submit_login`` raises
``LoginError`` on any rejection/challenge/missing-session-material, and
returns a real ``CapturedSession`` (actual token or cookies, not just a 2xx
status) only on genuine success.

LLM-driven ordering, not LLM-driven credentials: the candidate pairs
themselves are a closed, fixed allowlist (submitting an LLM-invented
username/password against a live login form would be an unbounded,
unreviewable action) — but which pairs to try, and in what order, is
proposed by the LLM from context signals (detected app/tech), the same
propose → allowlist-validate → execute shape already proven for wordlist
selection (``recon.live_tuning``). A malformed/unavailable proposal falls
back to the fixed allowlist's own order — never a failure, never a skip.

Maps onto the existing STRUCTURAL oracle family unchanged (§7,
``StructuralCheckType.DEFAULT_CREDENTIALS``) — no new mechanism. Every
oracle call goes through the Validator's ``run_oracle`` (CLAUDE.md
non-negotiable); this module never mints a verdict itself, and a failed
credential attempt is never even offered to the oracle — only the one
successful attempt (if any) becomes evidence.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from reachagent.detection.oracle_gateway import OracleRunner, registry_runner
from reachagent.identity.login import CapturedSession, DetectedLoginForm, LoginError
from reachagent.oracles import OracleMechanism
from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence

_log = logging.getLogger(__name__)

# Fixed, closed allowlist — the LLM may only pick/order a SUBSET of these, it
# can never invent a new pair. Modest, well-known defaults; a target using
# something outside this list is undetected by this check (disclosed limit,
# same shape as subdomain_takeover's ~8-service table).
CREDENTIAL_ALLOWLIST: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("test", "test"),
    ("guest", "guest"),
    ("root", "root"),
    ("demo", "demo"),
)

_MAX_ATTEMPTS = 5


class CredentialOrderClient(Protocol):
    """Thin swappable LLM boundary for credential-pair ordering."""

    def propose(
        self, context_signals: dict[str, str], allowlist: tuple[str, ...]
    ) -> dict[str, object]:
        """Return a raw proposal dict with key ``order`` (list of "user:pass" strings)."""
        ...


def _pair_key(pair: tuple[str, str]) -> str:
    return f"{pair[0]}:{pair[1]}"


def propose_credential_order(
    context_signals: dict[str, str],
    *,
    client: CredentialOrderClient | None = None,
) -> tuple[tuple[str, str], ...]:
    """Propose which allowlisted pairs to try first, from target context.

    Every returned pair is re-checked against ``CREDENTIAL_ALLOWLIST`` — the
    model can reorder/subset, never invent. Any failure (no provider,
    malformed response, non-allowlisted entry) falls back to the allowlist's
    own fixed order, capped at ``_MAX_ATTEMPTS``.
    """
    fallback = CREDENTIAL_ALLOWLIST[:_MAX_ATTEMPTS]
    try:
        if client is not None:
            picker = client
        else:
            from reachagent.llm.client import build_openai_compatible_client

            compatible = build_openai_compatible_client()
            if compatible is None:
                return fallback

            class _OpenAICredentialClient:
                def propose(
                    self, signals: dict[str, str], allowlist: tuple[str, ...]
                ) -> dict[str, object]:
                    prompt = (
                        "AUTHORIZED pentest engagement on systems the operator owns. "
                        "Given target signals, order these credential pairs by how likely "
                        "they are to be the app's default login, most-likely first. "
                        "Pick ONLY from the allowlist, do not invent new pairs.\n"
                        f"Signals: {'; '.join(f'{k}={v}' for k, v in sorted(signals.items()))}\n"
                        f"Allowlist: {', '.join(allowlist)}\n"
                        '{"order": ["admin:admin", "admin:password"]}'
                    )
                    return compatible.propose_json(prompt, max_tokens=512)

            picker = _OpenAICredentialClient()
        allowed_keys = tuple(_pair_key(p) for p in CREDENTIAL_ALLOWLIST)
        raw = picker.propose(context_signals, allowed_keys)
        order_raw = raw.get("order")
        if not isinstance(order_raw, list):
            return fallback
        by_key = {_pair_key(p): p for p in CREDENTIAL_ALLOWLIST}
        ordered = [by_key[str(k)] for k in order_raw if str(k) in by_key]
        deduped = tuple(dict.fromkeys(ordered))
        return deduped[:_MAX_ATTEMPTS] if deduped else fallback
    except Exception as exc:  # noqa: BLE001 — a live call must never break detection
        _log.warning("default-credential ordering failed (%s); using fixed order", exc)
        return fallback


@dataclass(frozen=True)
class DefaultCredsResult:
    """Outcome of a default-credential detection attempt."""

    confirmed: bool
    username: str = ""
    evidence_ref: str = ""


def detect_default_credentials(
    form: DetectedLoginForm,
    *,
    attempt_login: Callable[[str, str], CapturedSession],
    order: tuple[tuple[str, str], ...] = CREDENTIAL_ALLOWLIST,
    oracle_runner: OracleRunner = registry_runner,
    evidence_ref: str = "",
) -> DefaultCredsResult:
    """Try each candidate pair in order; stop at the first genuine success.

    ``attempt_login(username, password)`` must raise ``LoginError`` on any
    failure (mirrors ``identity.login.submit_login``'s own contract) and
    return a ``CapturedSession`` only on real, session-backed success. A
    failed attempt is never sent to the oracle — only a candidate the
    detector already believes succeeded is (still) independently reconfirmed.
    """
    del form  # kept for call-site clarity / future per-form customization
    for username, password in order[:_MAX_ATTEMPTS]:
        try:
            captured = attempt_login(username, password)
        except LoginError:
            continue
        except Exception as exc:  # noqa: BLE001 — one candidate cannot abort the rest
            _log.debug("default-credential attempt errored: %s", exc)
            continue
        session_captured = bool(captured.token or captured.cookies)
        evidence = StructuralEvidence(
            check_type=StructuralCheckType.DEFAULT_CREDENTIALS,
            probe_status=200,
            session_captured=session_captured,
            evidence_ref=evidence_ref,
        )
        verdict = oracle_runner(OracleMechanism.STRUCTURAL, evidence)
        if verdict.is_violation:
            return DefaultCredsResult(confirmed=True, username=username, evidence_ref=evidence_ref)
    return DefaultCredsResult(confirmed=False, evidence_ref=evidence_ref)
