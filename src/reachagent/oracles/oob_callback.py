"""Out-of-band callback oracle (plan §7, Phase 3 Task 1).

The ``oob_callback`` §7 oracle family. Confirms a blind injection when a
payload-triggered out-of-band callback (DNS or HTTP to a self-hosted
collaborator) is actually received, carrying the exact per-request nonce the
probe embedded. A definitive signal — a callback fired or it didn't — with no
statistical noise, which is why it ranks above timing (§9).

Decision path contains **zero LLM input**: pure membership test of the probe's
nonce against the set of nonces the collaborator observed. Same evidence in,
same verdict out, every time.

Nonce attribution is the safety-relevant part: each probe embeds a unique nonce
in its callback subdomain, so two concurrent probes on different parameters
never cross-attribute a callback. The oracle confirms only the probe whose own
nonce was seen — a callback for a *different* nonce is not a confirmation for
this one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import Oracle, OracleVerdict


@dataclass(frozen=True)
class OOBCallbackEvidence:
    """A probe's nonce and the callback nonces the collaborator actually observed.

    ``probe_nonce``: the unique token this probe embedded in its OOB payload's
    callback subdomain (e.g. ``<nonce>.oob.example.net``).
    ``observed_nonces``: the set of nonces the collaborator received during the
    probe window — read from the self-hosted interact.sh instance, never guessed.
    ``observed_channels``: ADDITIVE enrichment only — ``(nonce, channel)`` pairs
    the collaborator observed (D1 multi-channel, parsing-only). The oracle's
    :func:`decide` reads ONLY ``observed_nonces``; this field surfaces in
    audit/report so a callback is attributable to its channel (blind-XXE → http,
    Log4Shell → ldap). A hit on ANY channel confirms exactly as today.
    ``evidence_ref``: short, secret-free provenance handle (§13).
    """

    probe_nonce: str
    observed_nonces: frozenset[str] = field(default_factory=frozenset)
    observed_channels: frozenset[tuple[str, str]] = frozenset()
    evidence_ref: str = ""


def decide(evidence: OOBCallbackEvidence) -> FindingStatus:
    """Map OOB evidence to exactly one verdict — the whole decision (§7).

    Pure and total: a callback carrying this probe's own nonce is a confirmed
    violation; anything else is inconclusive. There is no ``confirmed_denied``
    here — the absence of a callback does not *prove* the parameter is safe (the
    payload may not have reached the sink, the channel may be firewalled), so a
    no-callback result is inconclusive, and the caller falls back to timing.

    An empty ``probe_nonce`` is refused as inconclusive rather than matching an
    empty observed set — a probe with no nonce is a caller error, but confirming
    on it would be worse (it would match any bare callback), so it never confirms.
    """
    if not evidence.probe_nonce:
        return FindingStatus.INCONCLUSIVE
    if evidence.probe_nonce in evidence.observed_nonces:
        return FindingStatus.CONFIRMED_VIOLATION
    return FindingStatus.INCONCLUSIVE


class OOBCallbackOracle(Oracle):
    """Confirms via out-of-band callback — one of the six §7 families."""

    mechanism = OracleMechanism.OOB_CALLBACK

    def run(self, evidence: object) -> OracleVerdict:
        """Return the deterministic verdict for ``evidence`` (must be OOBCallbackEvidence).

        Raises ``TypeError`` on wrong evidence type — a mis-wired caller is a
        bug, not an inconclusive result (mirrors the differential oracle).
        """
        if not isinstance(evidence, OOBCallbackEvidence):
            raise TypeError(
                f"OOBCallbackOracle needs OOBCallbackEvidence, got {type(evidence).__name__}"
            )
        status = decide(evidence)
        return OracleVerdict(
            mechanism=self.mechanism,
            status=status,
            evidence_ref=evidence.evidence_ref,
        )
