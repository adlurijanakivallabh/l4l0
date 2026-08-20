"""CLI for the generic scope-driven autonomous scan (plan §13).

No per-target YAML — just --target, --in-scope, --out-of-scope, --dry-run/--live.

Default is dry-run: no requests fired. Pass --live to actually fire. Without
--live the tool prints "dry-run: no requests fired — pass --live to fire".
"""

from __future__ import annotations

import argparse
import sys
import urllib.parse


def _absolute_url(value: str) -> str:
    v = value.strip()
    parsed = urllib.parse.urlparse(v)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise argparse.ArgumentTypeError(f"--target must be absolute http/https URL, got {value!r}")
    return v


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reachagent-scan",
        description="Generic scope-driven autonomous scan (dry-run by default).",
    )
    p.add_argument(
        "--target",
        required=True,
        type=_absolute_url,
        help="Absolute http/https URL of the target (e.g. https://example.com)",
    )
    p.add_argument(
        "--in-scope",
        required=True,
        help='Comma-separated allowlist, e.g. "*.example.com,example.com"',
    )
    p.add_argument(
        "--out-of-scope",
        default=None,
        help='Comma-separated denylist, e.g. "admin.example.com"',
    )
    p.add_argument(
        "--dry-run",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Dry-run toggle (default true); ignored unless paired with --live",
    )
    p.add_argument(
        "--live",
        action="store_true",
        help="Actually fire (requires --target + --live)",
    )
    p.add_argument(
        "--state",
        default=None,
        metavar="FILE",
        help="Persist run state (graph + solver + audit) to FILE at the end of a live run",
    )
    p.add_argument(
        "--resume",
        default=None,
        metavar="FILE",
        help="Resume from a persisted state FILE (continue-not-replay)",
    )
    p.add_argument(
        "--surface",
        default=None,
        metavar="FILE",
        help="Optional declared-surface YAML to seed endpoints/parameters before cold-start recon",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    in_scope = args.in_scope
    out_of_scope = args.out_of_scope
    target: str = args.target
    dry_run = not args.live

    print(f"target: {target}")
    print(f"in-scope: {in_scope}")
    if out_of_scope:
        print(f"out-of-scope: {out_of_scope}")
    if args.resume:
        print(f"resume: {args.resume}")
    print(f"mode: {'dry-run' if dry_run else 'live'}")

    if dry_run:
        print("dry-run: no requests fired — pass --live to fire")
        return 0

    if not in_scope.strip():
        print("error: --in-scope is required and must not be empty", file=sys.stderr)
        return 2

    from reachagent.scan.entrypoint import scan_target

    result = scan_target(
        base_url=target,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        dry_run=False,
        resume_path=args.resume,
        state_path=args.state,
        surface_path=args.surface,
    )
    findings = result.get("findings", [])
    print(f"findings: {len(findings)}")
    for node in findings:
        print(f"  - {node}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
