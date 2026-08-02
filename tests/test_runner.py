import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from web_openness.cli import build_parser, main
from web_openness.config import ScanConfig
from web_openness.domains import registrable_domain
from web_openness.governance import CollectionCeased
from web_openness.models import DomainSnapshot, ProbeError
from web_openness.pipeline import normalize_target
from web_openness.runner import (
    JobStatus,
    RunLeaseActive,
    RunProgress,
    RunStatus,
    RunStore,
    StoredScanOutcome,
    execute_run,
)
from web_openness.storage import write_snapshot


def _snapshot(target: str) -> DomainSnapshot:
    timestamp = datetime.now(UTC)
    domain = target.removeprefix("https://")
    return DomainSnapshot(
        run_id=str(uuid4()),
        domain=domain,
        origin=f"https://{domain}",
        started_at=timestamp,
        completed_at=timestamp,
        collector_version="test",
        request_count=2,
        observations={},
        requests=[],
    )


@pytest.mark.asyncio
async def test_resume_does_not_rescan_completed_domains(tmp_path: Path) -> None:
    state = tmp_path / "runner.sqlite3"
    snapshots = tmp_path / "snapshots"
    first_calls: list[str] = []
    stop_event = asyncio.Event()

    async def first_scan(target: str) -> DomainSnapshot:
        first_calls.append(target)
        return _snapshot(target)

    with RunStore(state) as store:
        run_id = store.create_run(["one.example.com", "two.example.org", "three.example.net"])

        def stop_after_first(progress: RunProgress) -> None:
            if progress.completed == 1:
                stop_event.set()

        stopped = await execute_run(
            store,
            run_id,
            config=ScanConfig(request_delay_seconds=0),
            snapshot_root=snapshots,
            concurrency=1,
            scan=first_scan,
            stop_event=stop_event,
            on_progress=stop_after_first,
        )

    assert stopped.status == RunStatus.STOPPED
    assert len(first_calls) == 1

    resumed_calls: list[str] = []

    async def resumed_scan(target: str) -> DomainSnapshot:
        resumed_calls.append(target)
        return _snapshot(target)

    with RunStore(state) as store:
        completed_before_resume = store.completed_targets(run_id)
        finished = await execute_run(
            store,
            run_id,
            config=ScanConfig(request_delay_seconds=0),
            snapshot_root=snapshots,
            concurrency=2,
            scan=resumed_scan,
            resume=True,
        )

    assert finished.status == RunStatus.COMPLETED
    assert finished.completed == 3
    assert completed_before_resume == first_calls
    assert not set(completed_before_resume) & set(resumed_calls)


@pytest.mark.asyncio
async def test_registrable_domain_never_has_two_active_scans(tmp_path: Path) -> None:
    active_domains: set[str] = set()
    maximum_active = 0
    updates: list[RunProgress] = []

    async def scan(target: str) -> DomainSnapshot:
        nonlocal maximum_active
        hostname, _origin = normalize_target(target)
        registrable = registrable_domain(hostname)
        assert registrable not in active_domains
        active_domains.add(registrable)
        maximum_active = max(maximum_active, len(active_domains))
        await asyncio.sleep(0.01)
        active_domains.remove(registrable)
        return _snapshot(target)

    with RunStore(tmp_path / "runner.sqlite3") as store:
        run_id = store.create_run(["a.example.com", "b.example.com", "example.org"])
        result = await execute_run(
            store,
            run_id,
            config=ScanConfig(request_delay_seconds=0),
            snapshot_root=tmp_path / "snapshots",
            concurrency=3,
            scan=scan,
            on_progress=updates.append,
        )

    assert result.completed == 3
    assert maximum_active == 2
    assert any(update.running == 2 for update in updates)
    assert updates[-1].status == RunStatus.COMPLETED


def test_domain_claim_is_exclusive_across_runs_in_same_store(tmp_path: Path) -> None:
    with RunStore(tmp_path / "runner.sqlite3") as store:
        first_run = store.create_run(["www.example.com"])
        second_run = store.create_run(["docs.example.com"])
        first_job = store.pending_jobs(first_run)[0]
        second_job = store.pending_jobs(second_run)[0]
        store.acquire_lease(first_run, "first")
        store.acquire_lease(second_run, "second")

        assert store.claim(first_run, first_job, "first")
        assert not store.claim(second_run, second_job, "second")


@pytest.mark.asyncio
async def test_persistent_stop_prevents_new_jobs(tmp_path: Path) -> None:
    calls: list[str] = []

    async def scan(target: str) -> DomainSnapshot:
        calls.append(target)
        return _snapshot(target)

    with RunStore(tmp_path / "runner.sqlite3") as store:
        run_id = store.create_run(["example.com"])
        store.request_stop(run_id)
        result = await execute_run(
            store,
            run_id,
            config=ScanConfig(request_delay_seconds=0),
            snapshot_root=tmp_path / "snapshots",
            scan=scan,
        )

    assert result.status == RunStatus.STOPPED
    assert result.pending == 1
    assert calls == []


@pytest.mark.asyncio
async def test_resume_recovers_job_left_running_by_interruption(tmp_path: Path) -> None:
    state = tmp_path / "runner.sqlite3"
    with RunStore(state) as store:
        run_id = store.create_run(["example.com"])
        job = store.pending_jobs(run_id)[0]
        store.acquire_lease(run_id, "crashed")
        assert store.claim(run_id, job, "crashed")
        store.connection.execute(
            "UPDATE runs SET lease_expires_at = ? WHERE run_id = ?",
            ("2000-01-01T00:00:00+00:00", run_id),
        )
        store.connection.commit()

    calls: list[str] = []

    async def scan(target: str) -> DomainSnapshot:
        calls.append(target)
        return _snapshot(target)

    with RunStore(state) as store:
        result = await execute_run(
            store,
            run_id,
            config=ScanConfig(request_delay_seconds=0),
            snapshot_root=tmp_path / "snapshots",
            scan=scan,
            resume=True,
        )

    assert result.status == RunStatus.COMPLETED
    assert calls == ["https://example.com"]


@pytest.mark.asyncio
async def test_live_coordinator_lease_refuses_resume(tmp_path: Path) -> None:
    calls: list[str] = []

    async def scan(target: str) -> DomainSnapshot:
        calls.append(target)
        return _snapshot(target)

    with RunStore(tmp_path / "runner.sqlite3") as store:
        run_id = store.create_run(["example.com"])
        store.acquire_lease(run_id, "live-owner")
        with pytest.raises(RunLeaseActive, match="live coordinator"):
            await execute_run(
                store,
                run_id,
                config=ScanConfig(request_delay_seconds=0),
                snapshot_root=tmp_path / "snapshots",
                scan=scan,
                resume=True,
            )

    assert calls == []


def test_expired_coordinator_cannot_overwrite_reclaimed_job(tmp_path: Path) -> None:
    with RunStore(tmp_path / "runner.sqlite3") as store:
        run_id = store.create_run(["example.com"])
        job = store.pending_jobs(run_id)[0]
        store.acquire_lease(run_id, "expired-owner")
        assert store.claim(run_id, job, "expired-owner")
        store.connection.execute(
            "UPDATE runs SET lease_expires_at = ? WHERE run_id = ?",
            ("2000-01-01T00:00:00+00:00", run_id),
        )
        store.connection.commit()

        store.prepare_resume(run_id, "new-owner")
        reclaimed = store.pending_jobs(run_id)[0]
        assert store.claim(run_id, reclaimed, "new-owner")
        snapshot = _snapshot(job.target)
        path = write_snapshot(snapshot, tmp_path / "snapshots")

        with pytest.raises(RunLeaseActive, match="no longer owns"):
            store.complete(run_id, "expired-owner", job.job_id, snapshot, path)

        status = store.connection.execute(
            "SELECT status FROM jobs WHERE job_id = ?", (job.job_id,)
        ).fetchone()[0]
        assert status == JobStatus.RUNNING.value


def test_deferred_job_is_persisted_until_not_before(tmp_path: Path) -> None:
    with RunStore(tmp_path / "runner.sqlite3") as store:
        run_id = store.create_run(["example.com"])
        store.acquire_lease(run_id, "owner")
        job = store.pending_jobs(run_id)[0]
        assert store.claim(run_id, job, "owner")
        snapshot = _snapshot(job.target)
        path = write_snapshot(snapshot, tmp_path / "snapshots")
        store.defer(
            run_id,
            "owner",
            job.job_id,
            StoredScanOutcome(
                snapshot=snapshot,
                path=path,
                deferred_until=datetime(2099, 1, 1, tzinfo=UTC),
            ),
        )

        progress = store.progress(run_id)
        assert progress.deferred == 1
        assert progress.completed == 0
        assert store.pending_jobs(run_id) == []
        store.release_lease(run_id, "owner")

        store.connection.execute(
            "UPDATE jobs SET not_before = ? WHERE job_id = ?",
            ("2000-01-01T00:00:00+00:00", job.job_id),
        )
        store.connection.commit()
        store.prepare_resume(run_id, "resume-owner")
        assert [due.job_id for due in store.pending_jobs(run_id)] == [job.job_id]


@pytest.mark.asyncio
async def test_snapshot_errors_are_completed_with_notes(tmp_path: Path) -> None:
    async def scan(target: str) -> DomainSnapshot:
        snapshot = _snapshot(target)
        return snapshot.model_copy(
            update={"errors": [ProbeError(probe="metadata", message="fixture note")]}
        )

    with RunStore(tmp_path / "runner.sqlite3") as store:
        run_id = store.create_run(["example.com"])
        result = await execute_run(
            store,
            run_id,
            config=ScanConfig(request_delay_seconds=0),
            snapshot_root=tmp_path / "snapshots",
            scan=scan,
        )

    assert result.status == RunStatus.COMPLETED_WITH_NOTES
    assert result.completed_with_notes == 1
    assert result.completed == 0


@pytest.mark.asyncio
async def test_global_stop_prevents_every_run_from_starting(tmp_path: Path) -> None:
    calls: list[str] = []

    async def scan(target: str) -> DomainSnapshot:
        calls.append(target)
        return _snapshot(target)

    with RunStore(tmp_path / "runner.sqlite3") as store:
        run_id = store.create_run(["example.com"])
        store.set_global_stop(True)
        result = await execute_run(
            store,
            run_id,
            config=ScanConfig(request_delay_seconds=0),
            snapshot_root=tmp_path / "snapshots",
            scan=scan,
        )

    assert result.status == RunStatus.STOPPED
    assert result.global_stop_requested is True
    assert calls == []


@pytest.mark.asyncio
async def test_domain_wall_clock_timeout_fails_job(tmp_path: Path) -> None:
    async def scan(_target: str) -> DomainSnapshot:
        await asyncio.sleep(1)
        raise AssertionError("timeout should cancel the scan")

    with RunStore(tmp_path / "runner.sqlite3") as store:
        run_id = store.create_run(["example.com"])
        result = await execute_run(
            store,
            run_id,
            config=ScanConfig(request_delay_seconds=0, domain_timeout_seconds=0.01),
            snapshot_root=tmp_path / "snapshots",
            scan=scan,
        )

    assert result.status == RunStatus.COMPLETED_WITH_ERRORS
    assert result.failed == 1


def test_batch_cli_surface() -> None:
    parser = build_parser()

    batch = parser.parse_args(["batch", "--domains-file", "domains.txt", "--concurrency", "2"])
    browser_scan = parser.parse_args(["scan", "example.org", "--browser"])
    status = parser.parse_args(["batch-status", "run-123"])
    stop = parser.parse_args(["batch-stop", "run-123"])
    stop_all = parser.parse_args(["batch-stop-all"])

    assert batch.command == "batch"
    assert batch.concurrency == 2
    assert browser_scan.browser is True
    assert status.run_id == "run-123"
    assert stop.command == "batch-stop"
    assert stop_all.command == "batch-stop-all"


def test_batch_status_and_stop_commands_are_offline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    state = tmp_path / "runner.sqlite3"
    with RunStore(state) as store:
        run_id = store.create_run(["example.com"])

    assert main(["batch-status", run_id, "--state", str(state)]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["pending"] == 1
    assert status["stop_requested"] is False

    assert main(["batch-stop", run_id, "--state", str(state)]) == 0
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["stop_requested"] is True

    assert main(["batch-stop-all", "--state", str(state)]) == 0
    global_stop = json.loads(capsys.readouterr().out)
    assert global_stop["global_stop_requested"] is True

    assert main(["batch-clear-stop", "--state", str(state)]) == 0
    cleared = json.loads(capsys.readouterr().out)
    assert cleared["global_stop_requested"] is False


@pytest.mark.asyncio
async def test_updated_cease_list_gets_a_distinct_job_disposition(tmp_path: Path) -> None:
    async def scan(_target: str) -> DomainSnapshot:
        raise CollectionCeased("collection ceased for example.org")

    with RunStore(tmp_path / "runner.sqlite3") as store:
        run_id = store.create_run(["example.org"])
        result = await execute_run(
            store,
            run_id,
            config=ScanConfig(request_delay_seconds=0),
            snapshot_root=tmp_path / "snapshots",
            scan=scan,
        )
        status = store.connection.execute(
            "SELECT status FROM jobs WHERE run_id = ?", (run_id,)
        ).fetchone()[0]

    assert result.status == RunStatus.COMPLETED
    assert result.ceased == 1
    assert result.failed == 0
    assert status == JobStatus.CEASED.value
