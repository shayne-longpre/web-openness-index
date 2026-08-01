import argparse
import asyncio
from collections.abc import Sequence
from pathlib import Path

from web_openness.config import DEFAULT_USER_AGENT, ScanConfig
from web_openness.models import DomainSnapshot
from web_openness.pipeline import Scanner
from web_openness.smoke import collect_smoke_run, load_targets, render_markdown, write_run_reports
from web_openness.storage import write_snapshot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web-openness",
        description="Collect a policy-aware Web Openness Observatory snapshot.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="scan one or more public domains")
    scan.add_argument("targets", nargs="+", help="domains or HTTP(S) origins")
    _add_scan_options(scan)
    scan.add_argument("--json", action="store_true", help="also print snapshots as JSON")

    smoke = subparsers.add_parser(
        "smoke", help="scan a small domain set and summarize measurement coverage"
    )
    smoke.add_argument("targets", nargs="*", help="domains or HTTP(S) origins")
    smoke.add_argument(
        "--domains-file",
        type=Path,
        help="UTF-8 file containing one domain or origin per line",
    )
    smoke.add_argument(
        "--concurrency",
        type=int,
        default=3,
        help="maximum domains scanned at once (default: 3)",
    )
    smoke.add_argument(
        "--report-output",
        type=Path,
        default=Path("data/smoke-runs"),
        help="run report root (default: data/smoke-runs)",
    )
    _add_scan_options(smoke)
    return parser


def _add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/snapshots"),
        help="snapshot root (default: data/snapshots)",
    )
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    parser.add_argument("--request-budget", type=int, default=8)
    parser.add_argument("--request-delay", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--max-response-bytes", type=int, default=1_000_000)


async def run_scans(args: argparse.Namespace) -> list[tuple[DomainSnapshot, Path]]:
    config = _scan_config(args)
    scanner = Scanner(config)
    results: list[tuple[DomainSnapshot, Path]] = []
    for target in args.targets:
        snapshot = await scanner.scan(target)
        results.append((snapshot, write_snapshot(snapshot, args.output)))
    return results


def _scan_config(args: argparse.Namespace) -> ScanConfig:
    return ScanConfig(
        user_agent=args.user_agent,
        request_budget=args.request_budget,
        request_delay_seconds=args.request_delay,
        timeout_seconds=args.timeout,
        max_response_bytes=args.max_response_bytes,
    )


async def run_smoke(args: argparse.Namespace) -> tuple[str, Path, Path]:
    targets = list(args.targets)
    if args.domains_file is not None:
        targets.extend(load_targets(args.domains_file))
    # Preserve the user's ordering while avoiding accidental duplicate scans.
    targets = list(dict.fromkeys(targets))
    run = await collect_smoke_run(
        targets,
        config=_scan_config(args),
        snapshot_root=args.output,
        concurrency=args.concurrency,
    )
    json_path, markdown_path = write_run_reports(run, args.report_output)
    return render_markdown(run), json_path, markdown_path


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            results = asyncio.run(run_scans(args))
        else:
            markdown, json_path, markdown_path = asyncio.run(run_smoke(args))
            print(markdown, end="")
            print(f"JSON report: {json_path}")
            print(f"Markdown report: {markdown_path}")
            return 0
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    for snapshot, path in results:
        print(f"{snapshot.domain}: {path}")
        if args.json:
            print(snapshot.model_dump_json(indent=2))
    return 0
