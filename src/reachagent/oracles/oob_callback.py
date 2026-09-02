"""Out-of-band callback oracle evidence shape (plan §7, Phase 3 Task 1).

The ``oob_callback`` §7 oracle family. Confirms a blind injection when a
payload-triggered out-of-band callback (DNS or HTTP to a self-hosted
collaborator) is actually received, carrying the exact per-request nonce the
probe embedded. A definitive signal — a callback fired or it didn't — with no
statistical noise, which is why it ranks above timing (§9).

v3 architecture decision: the fixed ``decide()`` if/elif verdict logic has been
REMOVED. Live verdicts for this family are now produced by LLM judgment
(``reachagent.oracles.llm_judgment``), wired into ``tools/validator.py::run_oracle``
and ``detection/oracle_gateway.py::registry_runner``. ``OOBCallbackEvidence``
below remains in use purely as evidence-shape vocabulary — the fields an OOB
probe/collaborator pairing produces, consumed by the LLM judgment module.
``OOBCallbackOracle`` is kept only as an inert shim (see its docstring).

Nonce attribution is the safety-relevant part: each probe embeds a unique nonce
in its callback subdomain, so two concurrent probes on different parameters
never cross-attribute a callback. A callback for a *different* nonce is not a
confirmation for this one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import Oracle, OracleVerdict
from reachagent.oracles.evidence import EvidenceMetadata


@dataclass(frozen=True)
class OOBCallbackEvidence:
    """A probe's nonce and the callback nonces the collaborator actually observed.

    ``probe_nonce``: the unique token this probe embedded in its OOB payload's
    callback subdomain (e.g. ``<nonce>.oob.example.net``).
    ``observed_nonces``: the set of nonces the collaborator received during the
    probe window — read from the self-hosted interact.sh instance, never guessed.
    ``observed_channels``: ADDITIVE enrichment only — ``(nonce, channel)`` pairs
    the collaborator observed (D1 multi-channel, parsing-only). Surfaces in
    audit/report so a callback is attributable to its channel (blind-XXE → http,
    Log4Shell → ldap). A hit on ANY channel confirms exactly as today.
    ``evidence_ref``: short, secret-free provenance handle (§13).
    """

    probe_nonce: str
    observed_nonces: frozenset[str] = field(default_factory=frozenset)
    observed_channels: frozenset[tuple[str, str]] = frozenset()
    evidence_ref: str = ""
    metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)


class OOBCallbackOracle(Oracle):
    """Inert v3 shim — kept only so ``oracles.registry`` can still register
    ``OracleMechanism.OOB_CALLBACK`` (and so ``get_oracle(OOB_CALLBACK)`` keeps
    validating as a known mechanism for callers like
    ``recon/tools/signal_gated.py``, which only checks that the lookup does
    not raise and never calls ``.run()``).

    The fixed ``decide()`` chain that used to back this class is gone; no
    caller on the live confirmation path invokes ``run()`` any more
    (``tools/validator.py::run_oracle`` goes straight to
    ``oracles.llm_judgment.judge`` instead), so this raises rather than
    pretend to decide anything.
    """

    mechanism = OracleMechanism.OOB_CALLBACK

    def run(self, evidence: object) -> OracleVerdict:
        """No longer decides a verdict — see the class docstring.

        The type guard below predates ``decide()`` and is independent of it
        (a mis-wired caller passing the wrong evidence type is still a bug,
        not a removed-feature question), so it is kept. Before v3, ``run()``
        also auto-filled ``evidence_metadata.oob_channels`` from
        ``evidence.observed_channels`` when the metadata didn't already carry
        it:

            metadata = validate_evidence_metadata(evidence.metadata)
            if evidence.observed_channels and not metadata.oob_channels:
                metadata = replace(
                    metadata,
                    oob_channels=tuple(evidence.observed_channels),
                ).validated()

        That auto-fill logic was independent of ``decide()`` too and is not
        dead by necessity — it is preserved verbatim in this task's report for
        a human to relocate (e.g. into ``oracles/llm_judgment.py``'s own
        verdict construction) rather than silently lost.
        """
        if not isinstance(evidence, OOBCallbackEvidence):
            raise TypeError(
                f"OOBCallbackOracle needs OOBCallbackEvidence, got {type(evidence).__name__}"
            )
        raise NotImplementedError(
            "OOBCallbackOracle.run() was removed in v3 — confirmation now goes "
            "through reachagent.oracles.llm_judgment.judge"
        )
