import argparse
import asyncio
import json
import signal
from collections.abc import Sequence
from pathlib import Path

from web_openness.browser_policy import BrowserPolicy
from web_openness.config import DEFAULT_USER_AGENT, ScanConfig
from web_openness.models import DomainSnapshot
from web_openness.pipeline import Scanner
from web_openness.runner import RunProgress, RunStore, execute_run
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

    batch = subparsers.add_parser(
        "batch", help="run or resume a persistent multi-domain collection"
    )
    batch.add_argument("targets", nargs="*", help="domains or HTTP(S) origins for a new run")
    batch.add_argument("--domains-file", type=Path, help="one domain or origin per line")
    batch.add_argument("--run-id", help="resume an existing run instead of creating one")
    batch.add_argument(
        "--state",
        type=Path,
        default=Path("data/runner.sqlite3"),
        help="persistent runner database (default: data/runner.sqlite3)",
    )
    batch.add_argument("--concurrency", type=int, default=3)
    batch.add_argument(
        "--json-progress", action="store_true", help="print structured progress as JSON lines"
    )
    _add_scan_options(batch)

    status = subparsers.add_parser("batch-status", help="show persistent batch progress")
    status.add_argument("run_id")
    status.add_argument("--state", type=Path, default=Path("data/runner.sqlite3"))

    stop = subparsers.add_parser("batch-stop", help="request a graceful batch stop")
    stop.add_argument("run_id")
    stop.add_argument("--state", type=Path, default=Path("data/runner.sqlite3"))

    stop_all = subparsers.add_parser("batch-stop-all", help="stop every batch in this state store")
    stop_all.add_argument("--state", type=Path, default=Path("data/runner.sqlite3"))

    clear_stop = subparsers.add_parser(
        "batch-clear-stop", help="clear the database-wide batch stop"
    )
    clear_stop.add_argument("--state", type=Path, default=Path("data/runner.sqlite3"))
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
    parser.add_argument(
        "--domain-timeout",
        type=float,
        default=120.0,
        help="total wall-clock seconds allowed per domain (default: 120)",
    )
    parser.add_argument(
        "--max-politeness-wait",
        type=float,
        default=5.0,
        help="maximum seconds to wait for a reserved request slot (default: 5)",
    )
    parser.add_argument("--max-response-bytes", type=int, default=1_000_000)
    parser.add_argument(
        "--cease-list",
        type=Path,
        help="canonical domains excluded before DNS, TLS, HTTP, or browser work",
    )
    parser.add_argument(
        "--browser",
        action="store_true",
        help="enable one bounded, non-interactive Chromium render per domain",
    )


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
        domain_timeout_seconds=args.domain_timeout,
        max_politeness_wait_seconds=args.max_politeness_wait,
        max_response_bytes=args.max_response_bytes,
        cease_list_path=args.cease_list,
        browser_policy=BrowserPolicy(enabled=args.browser),
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


async def run_batch(args: argparse.Namespace) -> RunProgress:
    config = _scan_config(args)
    with RunStore(args.state) as store:
        resume = args.run_id is not None
        if args.run_id is not None:
            if args.targets or args.domains_file is not None:
                raise ValueError("targets cannot be added when resuming an existing run")
            run_id = args.run_id
        else:
            targets = list(args.targets)
            if args.domains_file is not None:
                targets.extend(load_targets(args.domains_file))
            scanner = Scanner(config)
            for target in targets:
                scanner.require_target_allowed(target)
            run_id = store.create_run(targets)

        print(f"Batch run: {run_id}", flush=True)
        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        installed_signals: list[signal.Signals] = []
        for signal_name in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(signal_name, stop_event.set)
            except (NotImplementedError, RuntimeError):
                continue
            installed_signals.append(signal_name)

        def show_progress(progress: RunProgress) -> None:
            if args.json_progress:
                print(json.dumps(progress.as_dict(), sort_keys=True), flush=True)

        try:
            return await execute_run(
                store,
                run_id,
                config=config,
                snapshot_root=args.output,
                concurrency=args.concurrency,
                stop_event=stop_event,
                on_progress=show_progress,
                resume=resume,
            )
        finally:
            for signal_name in installed_signals:
                loop.remove_signal_handler(signal_name)


def _stored_progress(args: argparse.Namespace, *, stop: bool) -> RunProgress:
    with RunStore(args.state) as store:
        if stop:
            store.request_stop(args.run_id)
        return store.progress(args.run_id)


def _set_global_stop(args: argparse.Namespace, *, requested: bool) -> dict[str, bool]:
    with RunStore(args.state) as store:
        store.set_global_stop(requested)
        return {"global_stop_requested": store.global_stop_requested()}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            results = asyncio.run(run_scans(args))
        elif args.command == "smoke":
            markdown, json_path, markdown_path = asyncio.run(run_smoke(args))
            print(markdown, end="")
            print(f"JSON report: {json_path}")
            print(f"Markdown report: {markdown_path}")
            return 0
        elif args.command == "batch":
            progress = asyncio.run(run_batch(args))
            print(json.dumps(progress.as_dict(), sort_keys=True))
            return 0
        elif args.command in {"batch-status", "batch-stop"}:
            progress = _stored_progress(args, stop=args.command == "batch-stop")
            print(json.dumps(progress.as_dict(), sort_keys=True))
            return 0
        else:
            control = _set_global_stop(args, requested=args.command == "batch-stop-all")
            print(json.dumps(control, sort_keys=True))
            return 0
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    for snapshot, path in results:
        print(f"{snapshot.domain}: {path}")
        if args.json:
            print(snapshot.model_dump_json(indent=2))
    return 0
