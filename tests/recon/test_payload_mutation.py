"""Failure-context-aware payload ranking - hermetic tests."""

from __future__ import annotations


class TestPayloadAttemptContext:
    """The failure-context dataclass for mutation reasoning."""

    def test_context_creation(self) -> None:
        from reachagent.recon.payload_tuning import PayloadAttemptContext

        ctx = PayloadAttemptContext(
            tried_ref="sqli/error-based/quote-break",
            outcome="no_reflection",
            status_code=200,
            detail="payload reflected verbatim, no SQL error",
        )
        assert ctx.outcome == "no_reflection"
        assert ctx.status_code == 200
