"""Deterministic verification oracles (plan §7).

Six oracle mechanisms, no more — adding a seventh requires updating the plan
first (CLAUDE.md). Only a ``confirmed`` result from one of these families
unlocks ``write_finding`` (§13). The LLM proposes candidates; only a
Validator-run deterministic check produces a ``Finding`` (§7, unconditional).

Phase 1 (§15) implements the differential cross-identity diff oracle; Phase 2
adds ``business_rule_invariant``; Phase 3 adds ``timing_statistical`` (the
paired-trial oracle backing blind SQLi/NoSQLi/LDAP extraction). The remaining
families are stubbed until their phase builds them.
"""

from __future__ import annotations

from enum import StrEnum


class OracleMechanism(StrEnum):
    """The six deterministic families (§7). Not extended without a plan change."""

    DIFFERENTIAL = "differential"  # BOLA/BFLA/mass-assign/boolean-blind/NoSQLi/LDAP/price
    EXECUTION_CONFIRMATION = "execution_confirmation"  # SSTI, XSS (reflected/stored/DOM)
    OOB_CALLBACK = "oob_callback"  # blind SSRF, command injection, OOB-first blind SQLi
    TIMING_STATISTICAL = "timing_statistical"  # time-based blind, GraphQL complexity regression
    STRUCTURAL = "structural"  # JWT forgeries, file upload / path traversal
    BUSINESS_RULE_INVARIANT = "business_rule_invariant"  # 4-template library + race conditions
