#!/usr/bin/env python3
"""Non-interactive CI/CD wrapper around L4L0's GUI HTTP API - launches a
scan, waits for completion, copies the SARIF output to a caller-specified
path, and exits non-zero only when the worst CONFIRMED finding meets or
exceeds a caller-supplied severity threshold. Never gated on an
unconfirmed/open-proof-gap finding - only a real, adversarially-reviewed
confirmation fails a build, matching CLAUDE.md's own "neither layer ever
removes a finding" stance applied here to a build gate instead of a report.

Deliberately outside src/lalo/: automation glue for a DIFFERENT tool's
pipeline (a GitHub Action, a GitLab CI job) to invoke non-interactively,
the same category as lalo-setup's own already-accepted narrow exception
to this project's no-CLI/no-TUI design center - not a new interactive
mode of L4L0 itself. Drives the existing GUI HTTP API as an ordinary
external client (POST /scan, GET /runs, GET /runs/{id}/report/sarif) -
never imports lalo internals, since lalo-gui is the thing actually
running the scan.

Severity thresholds mirror findings/cvss.py's own CVSS v3.1 qualitative
rating scale exactly (the same scale report/sarif.py's own
security-severity property already encodes as a raw score): critical
>= 9.0, high >= 7.0, medium >= 4.0, low > 0.0, else info.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

import httpx

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_from_security_severity(score_str: str) -> str:
    score = float(score_str)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "info"


def _worst_confirmed_severity(sarif_doc: dict[str, object]) -> str | None:
    worst: str | None = None
    run = sarif_doc["runs"][0]  # type: ignore[index]
    for result in run["results"]:
        props = result.get("properties", {}).get("lalo", {})
        if props.get("review_verdict") != "confirmed":
            continue
        severity = _severity_from_security_severity(result["properties"]["security-severity"])
        if worst is None or _SEVERITY_ORDER[severity] < _SEVERITY_ORDER[worst]:
            worst = severity
    return worst


def main(argv: list[str] | None = None, *, client: httpx.Client | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--target", required=True, action="append")
    parser.add_argument("--mission", default="find and prove any exploitable vulnerability")
    parser.add_argument("--fail-on-severity", choices=sorted(_SEVERITY_ORDER), default=None)
    parser.add_argument("--sarif-out", default="l4l0-results.sarif")
    parser.add_argument("--poll-interval-s", type=float, default=5.0)
    parser.add_argument("--timeout-s", type=float, default=3600.0)
    args = parser.parse_args(argv)

    owns_client = client is None
    client = client or httpx.Client(base_url=args.base_url, timeout=30.0)
    try:
        response = client.post("/scan", json={"mission": args.mission, "targets": args.target})
        response.raise_for_status()
        run_id = response.json()["run_id"]

        deadline = time.monotonic() + args.timeout_s
        while time.monotonic() < deadline:
            runs = client.get("/runs").json()["runs"]
            run = next((r for r in runs if r["run_id"] == run_id), None)
            if run is not None and not run["running"]:
                break
            time.sleep(args.poll_interval_s)
        else:
            print(f"error: scan {run_id} did not finish within {args.timeout_s}s", file=sys.stderr)
            return 2

        sarif_response = client.get(f"/runs/{run_id}/report/sarif")
        sarif_response.raise_for_status()
        with open(args.sarif_out, "wb") as f:
            f.write(sarif_response.content)

        if args.fail_on_severity is None:
            return 0
        worst = _worst_confirmed_severity(json.loads(sarif_response.content))
        if worst is not None and _SEVERITY_ORDER[worst] <= _SEVERITY_ORDER[args.fail_on_severity]:
            print(
                f"L4L0 found a confirmed {worst} finding (threshold: {args.fail_on_severity})",
                file=sys.stderr,
            )
            return 1
        return 0
    finally:
        if owns_client:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())
