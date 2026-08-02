import asyncio
import sqlite3
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import cast
from uuid import uuid4

from web_openness.config import ScanConfig
from web_openness.domains import registrable_domain
from web_openness.governance import CollectionCeased
from web_openness.models import DomainSnapshot
from web_openness.pipeline import Scanner, normalize_target
from web_openness.pipeline import ScanOutcome as PipelineScanOutcome
from web_openness.storage import write_snapshot


class RunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    COMPLETED = "completed"
    COMPLETED_WITH_NOTES = "completed_with_notes"
    COMPLETED_WITH_DEFERRED = "completed_with_deferred"
    COMPLETED_WITH_ERRORS = "completed_with_errors"


class JobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_NOTES = "completed_with_notes"
    FAILED = "failed"
    CEASED = "ceased"
    DEFERRED = "deferred"


DEFAULT_LEASE_SECONDS = 60.0


class RunLeaseActive(ValueError):
    """Raised when a live coordinator already owns a run."""


@dataclass(frozen=True, slots=True)
class ScanJob:
    job_id: int
    target: str
    registrable_domain: str
    attempts: int


@dataclass(frozen=True, slots=True)
class StoredScanOutcome:
    snapshot: DomainSnapshot
    path: Path
    deferred_until: datetime | None = None


@dataclass(frozen=True, slots=True)
class RunProgress:
    run_id: str
    status: RunStatus
    total: int
    pending: int
    running: int
    completed: int
    completed_with_notes: int
    failed: int
    ceased: int
    deferred: int
    request_count: int
    stop_requested: bool
    global_stop_requested: bool

    def as_dict(self) -> dict[str, object]:
        finished = (
            self.completed + self.completed_with_notes + self.failed + self.ceased + self.deferred
        )
        return {
            "run_id": self.run_id,
            "status": self.status.value,
            "total": self.total,
            "pending": self.pending,
            "running": self.running,
            "completed": self.completed,
            "completed_with_notes": self.completed_with_notes,
            "failed": self.failed,
            "ceased": self.ceased,
            "deferred": self.deferred,
            "request_count": self.request_count,
            "stop_requested": self.stop_requested,
            "global_stop_requested": self.global_stop_requested,
            "fraction_finished": finished / self.total if self.total else 1.0,
        }


ProgressCallback = Callable[[RunProgress], None]
ScanCallable = Callable[[str], Awaitable[DomainSnapshot]]
OutcomeCallable = Callable[[str], Awaitable[PipelineScanOutcome]]


class RunStore:
    """Small persistent run queue; collection evidence remains in snapshot storage."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, timeout=5.0)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self._initialize()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "RunStore":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _initialize(self) -> None:
        with self.connection:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    stop_requested INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    owner_id TEXT,
                    lease_expires_at TEXT
                );

                CREATE TABLE IF NOT EXISTS jobs (
                    job_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    ordinal INTEGER NOT NULL,
                    target TEXT NOT NULL,
                    registrable_domain TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    request_count INTEGER NOT NULL DEFAULT 0,
                    snapshot_path TEXT,
                    error TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    not_before TEXT,
                    UNIQUE(run_id, target)
                );

                CREATE TABLE IF NOT EXISTS runner_control (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    global_stop_requested INTEGER NOT NULL DEFAULT 0
                );

                INSERT OR IGNORE INTO runner_control(singleton) VALUES (1);

                CREATE INDEX IF NOT EXISTS jobs_run_status
                    ON jobs(run_id, status, ordinal);
                CREATE INDEX IF NOT EXISTS jobs_run_domain_status
                    ON jobs(run_id, registrable_domain, status);
                CREATE INDEX IF NOT EXISTS jobs_domain_status
                    ON jobs(registrable_domain, status);
                """
            )
            self._ensure_column("runs", "owner_id", "TEXT")
            self._ensure_column("runs", "lease_expires_at", "TEXT")
            self._ensure_column("jobs", "not_before", "TEXT")

    def _ensure_column(self, table: str, column: str, definition: str) -> None:
        columns = {str(row[1]) for row in self.connection.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            self.connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def create_run(self, targets: Iterable[str]) -> str:
        jobs: list[tuple[str, str]] = []
        seen: set[str] = set()
        for target in targets:
            hostname, origin = normalize_target(target)
            if origin in seen:
                continue
            seen.add(origin)
            try:
                domain_key = registrable_domain(hostname)
            except ValueError:
                # Public IP literals have no registrable domain but remain valid targets.
                domain_key = hostname
            jobs.append((origin, domain_key))
        if not jobs:
            raise ValueError("batch run requires at least one target")

        run_id = str(uuid4())
        created_at = _now()
        with self.connection:
            self.connection.execute(
                "INSERT INTO runs(run_id, status, created_at) VALUES (?, ?, ?)",
                (run_id, RunStatus.PENDING.value, created_at),
            )
            self.connection.executemany(
                """
                INSERT INTO jobs(
                    run_id, ordinal, target, registrable_domain, status
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    (run_id, ordinal, target, domain, JobStatus.PENDING.value)
                    for ordinal, (target, domain) in enumerate(jobs)
                ),
            )
        return run_id

    def acquire_lease(
        self,
        run_id: str,
        owner_id: str,
        *,
        lease_seconds: float = DEFAULT_LEASE_SECONDS,
    ) -> None:
        self._require_run(run_id)
        now = _now()
        expires_at = _after(lease_seconds)
        with self.connection:
            cursor = self.connection.execute(
                """
                UPDATE runs
                SET owner_id = ?, lease_expires_at = ?
                WHERE run_id = ? AND (
                    owner_id IS NULL OR owner_id = ? OR lease_expires_at <= ?
                )
                """,
                (owner_id, expires_at, run_id, owner_id, now),
            )
        if cursor.rowcount != 1:
            raise RunLeaseActive(f"run {run_id} already has a live coordinator")

    def renew_lease(
        self,
        run_id: str,
        owner_id: str,
        *,
        lease_seconds: float = DEFAULT_LEASE_SECONDS,
    ) -> None:
        with self.connection:
            cursor = self.connection.execute(
                """
                UPDATE runs SET lease_expires_at = ?
                WHERE run_id = ? AND owner_id = ?
                """,
                (_after(lease_seconds), run_id, owner_id),
            )
        if cursor.rowcount != 1:
            raise RunLeaseActive(f"coordinator lease was lost for run {run_id}")

    def release_lease(self, run_id: str, owner_id: str) -> None:
        with self.connection:
            self.connection.execute(
                """
                UPDATE runs SET owner_id = NULL, lease_expires_at = NULL
                WHERE run_id = ? AND owner_id = ?
                """,
                (run_id, owner_id),
            )

    def prepare_resume(
        self,
        run_id: str,
        owner_id: str,
        *,
        lease_seconds: float = DEFAULT_LEASE_SECONDS,
    ) -> None:
        self._require_run(run_id)
        self.acquire_lease(run_id, owner_id, lease_seconds=lease_seconds)
        with self.connection:
            # A process can disappear while a scan is in flight. Only unfinished jobs
            # are made eligible again; completed domains remain untouched.
            self.connection.execute(
                """
                UPDATE jobs
                SET status = ?, error = NULL, started_at = NULL, completed_at = NULL,
                    not_before = NULL
                WHERE run_id = ? AND status IN (?, ?)
                """,
                (
                    JobStatus.PENDING.value,
                    run_id,
                    JobStatus.RUNNING.value,
                    JobStatus.FAILED.value,
                ),
            )
            self.connection.execute(
                """
                UPDATE runs
                SET status = ?, stop_requested = 0, completed_at = NULL
                WHERE run_id = ?
                """,
                (RunStatus.PENDING.value, run_id),
            )
            self.connection.execute(
                """
                UPDATE jobs
                SET status = ?, error = NULL, started_at = NULL, completed_at = NULL,
                    not_before = NULL
                WHERE run_id = ? AND status = ? AND not_before <= ?
                """,
                (
                    JobStatus.PENDING.value,
                    run_id,
                    JobStatus.DEFERRED.value,
                    _now(),
                ),
            )

    def start(self, run_id: str, owner_id: str) -> None:
        self._require_run(run_id)
        with self.connection:
            cursor = self.connection.execute(
                """
                UPDATE runs
                SET status = ?, started_at = COALESCE(started_at, ?)
                WHERE run_id = ? AND owner_id = ?
                """,
                (RunStatus.RUNNING.value, _now(), run_id, owner_id),
            )
        if cursor.rowcount != 1:
            raise RunLeaseActive(f"coordinator does not own run {run_id}")

    def pending_jobs(self, run_id: str) -> list[ScanJob]:
        rows = self.connection.execute(
            """
            SELECT job_id, target, registrable_domain, attempts
            FROM jobs
            WHERE run_id = ? AND status = ?
            ORDER BY ordinal
            """,
            (run_id, JobStatus.PENDING.value),
        ).fetchall()
        return [
            ScanJob(
                job_id=int(row["job_id"]),
                target=str(row["target"]),
                registrable_domain=str(row["registrable_domain"]),
                attempts=int(row["attempts"]),
            )
            for row in rows
        ]

    def claim(self, run_id: str, job: ScanJob, owner_id: str) -> bool:
        """Atomically claim a job if its registrable domain is not already active."""

        with self.connection:
            cursor = self.connection.execute(
                """
                UPDATE jobs
                SET status = ?, attempts = attempts + 1, started_at = ?, error = NULL
                WHERE job_id = ? AND run_id = ?
                  AND status = ?
                  AND EXISTS (
                    SELECT 1 FROM runs AS owned_run
                    WHERE owned_run.run_id = ? AND owned_run.owner_id = ?
                      AND owned_run.lease_expires_at > ?
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM jobs AS active
                    JOIN runs AS active_run ON active_run.run_id = active.run_id
                    WHERE active.registrable_domain = ?
                      AND active.status = ?
                      AND active_run.lease_expires_at > ?
                  )
                """,
                (
                    JobStatus.RUNNING.value,
                    _now(),
                    job.job_id,
                    run_id,
                    JobStatus.PENDING.value,
                    run_id,
                    owner_id,
                    _now(),
                    job.registrable_domain,
                    JobStatus.RUNNING.value,
                    _now(),
                ),
            )
        return cursor.rowcount == 1

    def complete(
        self,
        run_id: str,
        owner_id: str,
        job_id: int,
        snapshot: DomainSnapshot,
        path: Path,
    ) -> None:
        status = JobStatus.COMPLETED_WITH_NOTES if snapshot.errors else JobStatus.COMPLETED
        notes = "; ".join(f"{error.probe}: {error.message}" for error in snapshot.errors)[:2_048]
        with self.connection:
            cursor = self.connection.execute(
                """
                UPDATE jobs
                SET status = ?, request_count = request_count + ?, snapshot_path = ?,
                    completed_at = ?, error = ?, not_before = NULL
                WHERE job_id = ? AND run_id = ? AND status = ?
                  AND EXISTS (
                    SELECT 1 FROM runs AS owned_run
                    WHERE owned_run.run_id = ? AND owned_run.owner_id = ?
                      AND owned_run.lease_expires_at > ?
                  )
                """,
                (
                    status.value,
                    snapshot.request_count,
                    str(path),
                    _now(),
                    notes or None,
                    job_id,
                    run_id,
                    JobStatus.RUNNING.value,
                    run_id,
                    owner_id,
                    _now(),
                ),
            )
        self._require_owned_job_update(cursor, run_id)

    def defer(
        self,
        run_id: str,
        owner_id: str,
        job_id: int,
        outcome: StoredScanOutcome,
    ) -> None:
        if outcome.deferred_until is None:
            raise ValueError("deferred scan outcome requires a not-before timestamp")
        notes = "; ".join(f"{error.probe}: {error.message}" for error in outcome.snapshot.errors)[
            :2_048
        ]
        with self.connection:
            cursor = self.connection.execute(
                """
                UPDATE jobs
                SET status = ?, request_count = request_count + ?, snapshot_path = ?, error = ?,
                    not_before = ?, completed_at = NULL
                WHERE job_id = ? AND run_id = ? AND status = ?
                  AND EXISTS (
                    SELECT 1 FROM runs AS owned_run
                    WHERE owned_run.run_id = ? AND owned_run.owner_id = ?
                      AND owned_run.lease_expires_at > ?
                  )
                """,
                (
                    JobStatus.DEFERRED.value,
                    outcome.snapshot.request_count,
                    str(outcome.path),
                    notes or "collection deferred by persistent pacing policy",
                    outcome.deferred_until.astimezone(UTC).isoformat(),
                    job_id,
                    run_id,
                    JobStatus.RUNNING.value,
                    run_id,
                    owner_id,
                    _now(),
                ),
            )
        self._require_owned_job_update(cursor, run_id)

    def fail(self, run_id: str, owner_id: str, job_id: int, exc: Exception) -> None:
        message = f"{type(exc).__name__}: {exc}"[:2_048]
        with self.connection:
            cursor = self.connection.execute(
                """
                UPDATE jobs
                SET status = ?, error = ?, completed_at = ?, not_before = NULL
                WHERE job_id = ? AND run_id = ? AND status = ?
                  AND EXISTS (
                    SELECT 1 FROM runs AS owned_run
                    WHERE owned_run.run_id = ? AND owned_run.owner_id = ?
                      AND owned_run.lease_expires_at > ?
                  )
                """,
                (
                    JobStatus.FAILED.value,
                    message,
                    _now(),
                    job_id,
                    run_id,
                    JobStatus.RUNNING.value,
                    run_id,
                    owner_id,
                    _now(),
                ),
            )
        self._require_owned_job_update(cursor, run_id)

    def cease(self, run_id: str, owner_id: str, job_id: int, exc: CollectionCeased) -> None:
        with self.connection:
            cursor = self.connection.execute(
                """
                UPDATE jobs
                SET status = ?, error = ?, completed_at = ?, not_before = NULL
                WHERE job_id = ? AND run_id = ? AND status = ?
                  AND EXISTS (
                    SELECT 1 FROM runs AS owned_run
                    WHERE owned_run.run_id = ? AND owned_run.owner_id = ?
                      AND owned_run.lease_expires_at > ?
                  )
                """,
                (
                    JobStatus.CEASED.value,
                    str(exc)[:2_048],
                    _now(),
                    job_id,
                    run_id,
                    JobStatus.RUNNING.value,
                    run_id,
                    owner_id,
                    _now(),
                ),
            )
        self._require_owned_job_update(cursor, run_id)

    @staticmethod
    def _require_owned_job_update(cursor: sqlite3.Cursor, run_id: str) -> None:
        if cursor.rowcount != 1:
            raise RunLeaseActive(f"coordinator no longer owns a live job in run {run_id}")

    def request_stop(self, run_id: str) -> None:
        self._require_run(run_id)
        with self.connection:
            self.connection.execute(
                "UPDATE runs SET stop_requested = 1 WHERE run_id = ?",
                (run_id,),
            )

    def set_global_stop(self, requested: bool) -> None:
        with self.connection:
            self.connection.execute(
                """
                UPDATE runner_control SET global_stop_requested = ?
                WHERE singleton = 1
                """,
                (int(requested),),
            )

    def global_stop_requested(self) -> bool:
        row = self.connection.execute(
            "SELECT global_stop_requested FROM runner_control WHERE singleton = 1"
        ).fetchone()
        return bool(row[0])

    def mark_stopping(self, run_id: str, owner_id: str) -> None:
        with self.connection:
            self.connection.execute(
                "UPDATE runs SET status = ? WHERE run_id = ? AND owner_id = ?",
                (RunStatus.STOPPING.value, run_id, owner_id),
            )

    def finish(self, run_id: str, status: RunStatus, owner_id: str) -> None:
        with self.connection:
            self.connection.execute(
                """
                UPDATE runs
                SET status = ?, completed_at = ?, owner_id = NULL, lease_expires_at = NULL
                WHERE run_id = ? AND owner_id = ?
                """,
                (status.value, _now(), run_id, owner_id),
            )

    def progress(self, run_id: str) -> RunProgress:
        run = self._require_run(run_id)
        counts = {
            str(row["status"]): int(row["count"])
            for row in self.connection.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM jobs WHERE run_id = ? GROUP BY status
                """,
                (run_id,),
            )
        }
        request_count = self.connection.execute(
            "SELECT COALESCE(SUM(request_count), 0) FROM jobs WHERE run_id = ?",
            (run_id,),
        ).fetchone()[0]
        return RunProgress(
            run_id=run_id,
            status=RunStatus(str(run["status"])),
            total=sum(counts.values()),
            pending=counts.get(JobStatus.PENDING.value, 0),
            running=counts.get(JobStatus.RUNNING.value, 0),
            completed=counts.get(JobStatus.COMPLETED.value, 0),
            completed_with_notes=counts.get(JobStatus.COMPLETED_WITH_NOTES.value, 0),
            failed=counts.get(JobStatus.FAILED.value, 0),
            ceased=counts.get(JobStatus.CEASED.value, 0),
            deferred=counts.get(JobStatus.DEFERRED.value, 0),
            request_count=int(request_count),
            stop_requested=bool(run["stop_requested"]),
            global_stop_requested=self.global_stop_requested(),
        )

    def completed_targets(self, run_id: str) -> list[str]:
        return [
            str(row[0])
            for row in self.connection.execute(
                """
                SELECT target FROM jobs
                WHERE run_id = ? AND status IN (?, ?) ORDER BY ordinal
                """,
                (
                    run_id,
                    JobStatus.COMPLETED.value,
                    JobStatus.COMPLETED_WITH_NOTES.value,
                ),
            )
        ]

    def _require_run(self, run_id: str) -> sqlite3.Row:
        row = cast(
            sqlite3.Row | None,
            self.connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone(),
        )
        if row is None:
            raise ValueError(f"unknown run id: {run_id}")
        return row


async def execute_run(
    store: RunStore,
    run_id: str,
    *,
    config: ScanConfig,
    snapshot_root: Path,
    concurrency: int = 3,
    scan: ScanCallable | None = None,
    stop_event: asyncio.Event | None = None,
    on_progress: ProgressCallback | None = None,
    resume: bool = False,
    owner_id: str | None = None,
    lease_seconds: float = DEFAULT_LEASE_SECONDS,
) -> RunProgress:
    """Execute pending jobs, stopping cleanly without cancelling in-flight scans."""

    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")
    if lease_seconds <= 0:
        raise ValueError("lease_seconds must be positive")
    scanner = Scanner(config)
    if scan is None:
        scan_target: OutcomeCallable = scanner.scan_outcome
    else:

        async def scan_target(target: str) -> PipelineScanOutcome:
            return PipelineScanOutcome(snapshot=await scan(target))

    local_stop = stop_event or asyncio.Event()
    active: dict[asyncio.Task[StoredScanOutcome], ScanJob] = {}
    coordinator_id = owner_id or str(uuid4())
    if resume:
        store.prepare_resume(run_id, coordinator_id, lease_seconds=lease_seconds)
    else:
        store.acquire_lease(run_id, coordinator_id, lease_seconds=lease_seconds)
    store.start(run_id, coordinator_id)
    loop = asyncio.get_running_loop()
    last_lease_renewal = loop.time()
    _emit(store.progress(run_id), on_progress)

    try:
        while True:
            if loop.time() - last_lease_renewal >= lease_seconds / 3:
                store.renew_lease(run_id, coordinator_id, lease_seconds=lease_seconds)
                last_lease_renewal = loop.time()

            progress = store.progress(run_id)
            if local_stop.is_set() and not progress.stop_requested:
                store.request_stop(run_id)
                progress = store.progress(run_id)
            stopping = progress.stop_requested or progress.global_stop_requested
            if stopping and progress.status != RunStatus.STOPPING:
                store.mark_stopping(run_id, coordinator_id)
                progress = store.progress(run_id)
                _emit(progress, on_progress)

            if not stopping:
                available = concurrency - len(active)
                claimed_job = False
                for job in store.pending_jobs(run_id):
                    if available == 0:
                        break
                    if not store.claim(run_id, job, coordinator_id):
                        continue
                    task = asyncio.create_task(
                        _scan_and_write(
                            job.target,
                            scan_target,
                            snapshot_root,
                            config.domain_timeout_seconds,
                        )
                    )
                    active[task] = job
                    available -= 1
                    claimed_job = True
                if claimed_job:
                    _emit(store.progress(run_id), on_progress)

            if not active:
                progress = store.progress(run_id)
                stopping = progress.stop_requested or progress.global_stop_requested
                unfinished = progress.pending
                if unfinished and not stopping:
                    # Wait for a due deferral or another coordinator's domain lease.
                    await asyncio.sleep(0.25)
                    continue
                if stopping and unfinished:
                    final_status = RunStatus.STOPPED
                elif progress.failed:
                    final_status = RunStatus.COMPLETED_WITH_ERRORS
                elif progress.deferred:
                    final_status = RunStatus.COMPLETED_WITH_DEFERRED
                elif progress.completed_with_notes:
                    final_status = RunStatus.COMPLETED_WITH_NOTES
                else:
                    final_status = RunStatus.COMPLETED
                store.finish(run_id, final_status, coordinator_id)
                final_progress = store.progress(run_id)
                _emit(final_progress, on_progress)
                return final_progress

            done, _pending = await asyncio.wait(
                active,
                timeout=0.25,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                job = active.pop(task)
                try:
                    outcome = task.result()
                except CollectionCeased as exc:
                    store.cease(run_id, coordinator_id, job.job_id, exc)
                except Exception as exc:
                    store.fail(run_id, coordinator_id, job.job_id, exc)
                else:
                    if outcome.deferred_until is not None:
                        store.defer(run_id, coordinator_id, job.job_id, outcome)
                    else:
                        store.complete(
                            run_id,
                            coordinator_id,
                            job.job_id,
                            outcome.snapshot,
                            outcome.path,
                        )
                _emit(store.progress(run_id), on_progress)
    finally:
        if active:
            for task in active:
                task.cancel()
            await asyncio.gather(*active, return_exceptions=True)
        store.release_lease(run_id, coordinator_id)


async def _scan_and_write(
    target: str,
    scan: OutcomeCallable,
    snapshot_root: Path,
    domain_timeout_seconds: float,
) -> StoredScanOutcome:
    async with asyncio.timeout(domain_timeout_seconds):
        outcome = await scan(target)
    path = write_snapshot(outcome.snapshot, snapshot_root)
    return StoredScanOutcome(
        snapshot=outcome.snapshot,
        path=path,
        deferred_until=outcome.deferred_until,
    )


def _emit(progress: RunProgress, callback: ProgressCallback | None) -> None:
    if callback is not None:
        callback(progress)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _after(seconds: float) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()
