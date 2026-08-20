"""sqlmap signal-gated candidate emitter (§9 signal-gated tier; v1.7/v1.8).

sqlmap is invoked ONLY after ReachAgent's own probe raised a SQLi-class signal in
the graph — a ``Parameter`` whose ``inferred_sink_type`` is ``sql`` (set by
``fingerprint_parameter``, §9 step 1). No SQL signal → sqlmap is not a candidate
source here at all (:meth:`has_signal` returns False → refused, no spawn). sqlmap's
own "is it SQLi?" verdict is never trusted: its results become an inert SQLi
``Candidate`` that the Validator's ``run_oracle`` must independently re-confirm
before any ``Finding`` is written.

Output parsed: the ``--output-dir`` **results CSV**. sqlmap logs a row per tested
target; a *confirmed injection* row has both the ``Parameter`` and ``Technique``
columns populated (the empty-technique rows are untested/failed targets — filtered
out). The technique letters map to the §7 oracle family that can re-confirm the
claim: ``B``/``E``/``U`` (boolean/error/union) → differential; ``T`` (time-based)
→ timing_statistical; ``S``/``Q`` (stacked/inline, OOB-capable) → oob_callback.
"""

from __future__ import annotations

import csv
import io

from reachagent.graph.nodes import SinkType
from reachagent.oracles import OracleMechanism
from reachagent.recon.tools.signal_gated import SignalGatedToolRunner
from reachagent.tools.candidate import Candidate, ResponseSignal

# sqlmap technique letter → the §7 oracle family that can independently re-confirm
# a claim made with that technique. This is the routing the Candidate carries so
# the Validator runs the RIGHT oracle, not sqlmap's own say-so.
_TECHNIQUE_ORACLE: dict[str, OracleMechanism] = {
    "B": OracleMechanism.DIFFERENTIAL,  # boolean-based blind → differential
    "E": OracleMechanism.DIFFERENTIAL,  # error-based → differential (DB error signature)
    "U": OracleMechanism.DIFFERENTIAL,  # UNION query → differential
    "T": OracleMechanism.TIMING_STATISTICAL,  # time-based blind → paired-trial timing
    "S": OracleMechanism.OOB_CALLBACK,  # stacked queries (often OOB-capable) → OOB
    "Q": OracleMechanism.OOB_CALLBACK,  # inline queries → OOB
}


class SqlmapRunner(SignalGatedToolRunner):
    """Emit inert SQLi candidates from sqlmap CSV — gated on a graph SQL signal (§9)."""

    name = "sqlmap"
    binary = "sqlmap"

    def has_signal(self, target: str) -> bool:
        """True iff the graph already holds a SQLi-class signal (§9 gate).

        The signal is ReachAgent's OWN probe result — a ``Parameter`` fingerprinted
        with ``inferred_sink_type == sql`` (a boolean/timing SQLi lead sets the same
        sink). Reads only graph facts, never sqlmap's output. No such parameter →
        sqlmap is not invoked.
        """
        return any(
            param.inferred_sink_type is SinkType.SQL
            for _ep_node, _ep in self.graph.endpoints()
            for _p_node, param in self.graph.parameters_of(_ep_node)
        )

    def command(self, target: str, output_path: str) -> list[str]:
        """``sqlmap -u <target> --batch --output-dir=<dir>`` [+ --level/--risk]."""
        import os

        argv: list[str] = ["sqlmap", "-u", target, "--batch", "--output-dir", output_path]
        level = os.environ.get("REACHAGENT_SQLMAP_LEVEL", "1")
        risk = os.environ.get("REACHAGENT_SQLMAP_RISK", "1")
        if level in ("1", "2", "3", "4", "5"):
            argv += ["--level", level]
        if risk in ("1", "2", "3"):
            argv += ["--risk", risk]
        return argv

    def parse(self, target: str, raw_output: str) -> tuple[Candidate, ...]:
        """Parse the sqlmap results CSV into inert SQLi candidates (never a finding).

        Only rows with BOTH ``Parameter`` and ``Technique`` populated are confirmed
        injections in sqlmap's own log; empty-technique rows are untested/failed and
        are skipped. Each surviving row → one SQLi ``Candidate`` routed to the §7
        oracle its technique maps to. The candidate is inert: it carries sqlmap's
        claim as provenance, never a verdict.
        """
        candidates: list[Candidate] = []
        reader = csv.DictReader(io.StringIO(raw_output))
        for row in reader:
            parameter = (row.get("Parameter") or "").strip()
            # sqlmap's results CSV names this column ``Technique(s)`` in recent
            # releases and ``Technique`` in older ones — accept either.
            technique = (row.get("Technique(s)") or row.get("Technique") or "").strip()
            if not parameter or not technique:
                continue  # untested/failed target row — not a confirmed injection
            oracle = _oracle_for_techniques(technique)
            candidates.append(
                Candidate(
                    identity="sqlmap-signal-gated",
                    endpoint_node=str(row.get("Target URL") or target),
                    param_node=parameter,
                    vuln_class="sqli",
                    suggested_oracle=oracle,
                    payload_ref=None,
                    signal=ResponseSignal(status_code=0, body_length=0, elapsed_seconds=0.0),
                    notes=(
                        f"sqlmap CLAIM (unverified): param={parameter} technique={technique}",
                        "requires independent run_oracle re-confirmation before any Finding",
                    ),
                )
            )
        return tuple(candidates)


def _oracle_for_techniques(techniques: str) -> OracleMechanism:
    """Map sqlmap technique letter(s) to the §7 oracle that must re-confirm the claim.

    A row may list several technique letters (e.g. ``BEU``); the first *recognised*
    letter picks the oracle, defaulting to differential (the SQLi workhorse) when a
    letter is unknown — so an unfamiliar technique is still routed to a real §7
    family for independent re-confirmation, never auto-trusted.
    """
    for letter in techniques:
        if letter in _TECHNIQUE_ORACLE:
            return _TECHNIQUE_ORACLE[letter]
    return OracleMechanism.DIFFERENTIAL
