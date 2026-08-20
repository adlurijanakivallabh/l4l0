"""gobuster recon wrapper — discovered HTTP paths as Endpoint facts (§9 recon tier).

gobuster's ``dir`` mode emits one discovered path per line. Per §6/§9 (v1.8) a
discovered path is an ordinary ``Endpoint`` node (no new type), attached to the
target ``Host`` by a ``resolves_to`` edge. Facts only: gobuster asserts that a
path *exists* (a fact), never that it is *vulnerable* (a claim) — so nothing here
is a candidate or a ``Finding``. The HTTP status it reports is provenance in the
audit trail, not a ``can_call`` verdict (recon never writes ``can_call``).

Default gobuster stdout lines look like::

    /admin                (Status: 200) [Size: 1234]
    /login                (Status: 301) [Size: 0] [--> /login/]
"""

from __future__ import annotations

import os
import re

from reachagent.graph.nodes import Endpoint, Host
from reachagent.recon.calibration import CalibrationResult
from reachagent.recon.tools._wordlist import preferred_wordlist
from reachagent.recon.tools.base import ReconToolRunner

# A gobuster result line: a path token, then a "(Status: NNN)" marker. Anything
# without both is banner/progress noise and is skipped. The path token may lack a
# leading "/" (real `-q` output emits "console              (Status: 200)" with no
# slash); the optional-slash capture accepts both, and parse normalizes to a
# leading "/" so endpoint ids stay endpoint-shaped (live-run divergence #2).
_RESULT = re.compile(r"^(?P<path>/?\S*)\s+\(Status:\s*(?P<status>\d{3})\)")


# ---------------------------------------------------------------------------
# 401/403 ACL-surface classification — the deferred Phase-2 gap audit item
# (comprehensive-reference-audit D5 "403-bypass decision" row; recon-gap-audit
# ffuf 401/403 ACL-surface TODO). Shared by the four content-discovery wrappers.
#
# # DECISION BLOCK (D1-D4)
#
# D1. What a 403 means.
#     In content discovery, a 403 response to a discovered path is a REAL, HONEST
#     FACT: the path EXISTS but is ACL-restricted — distinct from a 2xx path
#     (exists, served) and a 404 (missing). It is NOT a bypass and is never
#     auto-exploited. The honest fact is "restricted surface exists", not "this
#     endpoint is vulnerable" and not "nothing here". A bypass probe (method
#     override, X-Original-URL, path normalization) is NEVER fired — that is the
#     Validator's oracle judgment under read-only-first (§10); this is a recon-
#     tier classifier with no authority to attempt access.
#
# D2. Classification shape — third state, not two.
#     A 403-response path is still asserted as an Endpoint (the path exists), but
#     tagged ``access_restricted: "403"`` (an Endpoint attribute; no new node
#     type). The audit/report reader sees three honest states: exists-served
#     (2xx/3xx), exists-restricted (401/403), missing (404/omitted). 401 is the
#     same restricted state (unauthenticated-reach) — both classify as
#     ``access_restricted``. 404/405/5xx unchanged.
#
# D3. Wiring — minimal, one shared predicate.
#     :func:`_restricted_status` is the single guard the four wrappers import —
#     one root-cause fix, not four copies. Each wrapper consults it when building
#     the Endpoint and sets the attribute + audits ``discovered_restricted:<status>``
#     once per line. Tool command arrays are NOT changed (ffuf ``-mc`` stays as
#     is — the classifier handles whichever statuses the tool reports; it does
#     not force the tool to report more). Wildcard calibration is orthogonal: a
#     catch-all still suppresses paths entirely (a "403" under a catch-all is the
#     tool's own noise — the target returns 200 for everything).
#
# D4. No oracle, no bypass, no new node/edge type, no Finding/can_call.
#     Read-only-first holds — no state-changing or access-escalation probe
#     anywhere. Six families held.
# ---------------------------------------------------------------------------


def _restricted_status(status: int) -> bool:
    """True iff ``status`` marks an existing-but-access-restricted path.

    401 (unauthenticated-reach) and 403 (forbidden) both mean the surface exists
    but is ACL-gated — the honest "restricted surface exists" fact (D1). A
    bypass probe is never fired from here.
    """
    return status in (401, 403)


class GobusterRunner(ReconToolRunner):
    """Emit an ``Endpoint`` per gobuster-discovered path + ``resolves_to`` edge (§9)."""

    name = "gobuster"
    binary = "gobuster"

    # Set by the scan entrypoint before ingest (D3 pass-through — base.py's
    # parse contract is overridden by ~20 wrappers, so the calibration result is
    # handed over per-instance, not through base).
    calibration: CalibrationResult | None = None

    def command(self, target: str) -> list[str]:
        """``gobuster dir -q -u <target> -w <wordlist>`` — quiet, results to stdout.

        Target is a distinct list element (``shell=False`` in the base). The
        wordlist path comes from ``REACHAGENT_GOBUSTER_WORDLIST`` or a common
        default; it is a fixed path element, never the target, so it is not an
        injection surface.
        """
        wordlist = preferred_wordlist("REACHAGENT_GOBUSTER_WORDLIST")
        argv: list[str] = ["gobuster", "dir", "-q", "-u", target, "-w", wordlist]
        # ponytail: env-only tuning, no config file until env count >12
        threads = os.environ.get("REACHAGENT_GOBUSTER_THREADS")
        if threads and threads.isdigit():
            argv += ["-t", threads]
        timeout = os.environ.get("REACHAGENT_GOBUSTER_TIMEOUT")
        if timeout and timeout.isdigit():
            argv += ["--timeout", f"{timeout}s"]
        return argv

    def parse(
        self, target: str, raw_output: str, calibration: CalibrationResult | None = None
    ) -> tuple[str, ...]:
        """Parse gobuster result lines into ``Endpoint`` nodes + ``resolves_to`` edges.

        When a calibration result marks the target as a wildcard catch-all
        (D2), discovered paths are untrustworthy facts — no Endpoint is asserted,
        each result line is audited ``refused_wildcard_catchall``, and only the
        Host (carrying the ``wildcard_shape`` fact) is returned.
        """
        cal = calibration if calibration is not None else self.calibration
        technology = f"wildcard_shape:{cal.shape_label}" if cal is not None else None
        written: list[str] = []
        host_node = self.graph.add_host(
            Host(address=_host_of(target), source=self.name, technology=technology)
        )
        written.append(host_node)
        if cal is not None and cal.wildcard:
            for line in raw_output.splitlines():
                if _RESULT.match(line.strip()):
                    self.audit.record(self.name, "RECON", target, "refused_wildcard_catchall")
            return tuple(written)
        for line in raw_output.splitlines():
            match = _RESULT.match(line.strip())
            if match is None:
                continue
            path = match.group("path")
            # Normalize to a leading "/" so a slashless `-q` token keeps the
            # endpoint-shaped node id (live-run divergence #2).
            if not path.startswith("/"):
                path = "/" + path
            status = match.group("status")
            # A discovered path is an ordinary GET Endpoint (recon asserts it
            # exists; it never assigns a can_call or a method beyond the probe verb).
            # A 401/403 path is still asserted — the path EXISTS — but tagged
            # access_restricted (D2 third state), audited per line.
            access = status if _restricted_status(int(status)) else None
            if access is not None:
                self.audit.record(self.name, "RECON", target, f"discovered_restricted:{status}")
            endpoint_node = self.graph.add_endpoint(
                Endpoint(method="GET", path=path, access_restricted=access)
            )
            self.graph.add_resolves_to(host_node, endpoint_node)
            written.append(endpoint_node)
        return tuple(written)


def _host_of(target: str) -> str:
    """The bare host of a recon target (strip scheme + any path), for the Host node."""
    stripped = target.split("://", 1)[-1]
    return stripped.split("/", 1)[0]
