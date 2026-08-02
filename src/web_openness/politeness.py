"""Persistent, registrable-domain keyed pacing for collector workers."""

import asyncio
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

import httpx

from web_openness.domains import registrable_domain


@dataclass(frozen=True, slots=True)
class Reservation:
    wait_seconds: float = 0
    deferred_until: float | None = None
    circuit_until: float | None = None


@dataclass(frozen=True, slots=True)
class TransientState:
    consecutive_failures: int
    blocked_until: float
    circuit_until: float | None


class SQLitePolitenessStore:
    """Small SQLite coordinator shared safely by tasks, workers, and runs."""

    def __init__(
        self,
        path: Path | str,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(
            str(path),
            timeout=5,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS domain_politeness (
                domain TEXT PRIMARY KEY,
                next_allowed_at REAL NOT NULL DEFAULT 0,
                interval_seconds REAL NOT NULL DEFAULT 0,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                circuit_until REAL NOT NULL DEFAULT 0,
                updated_at REAL NOT NULL
            )
            """
        )

    async def reserve(
        self,
        domain: str,
        *,
        interval_seconds: float,
        max_wait_seconds: float,
    ) -> Reservation:
        return await asyncio.to_thread(
            self._reserve,
            domain,
            interval_seconds,
            max_wait_seconds,
        )

    def _reserve(
        self,
        domain: str,
        interval_seconds: float,
        max_wait_seconds: float,
    ) -> Reservation:
        now = self._clock()
        with self._transaction():
            self._ensure_domain(domain, now)
            row = self._connection.execute(
                """
                SELECT next_allowed_at, circuit_until, interval_seconds
                FROM domain_politeness
                WHERE domain = ?
                """,
                (domain,),
            ).fetchone()
            if row is None:  # Defensive; _ensure_domain created it in this transaction.
                raise RuntimeError("politeness state disappeared during reservation")
            next_allowed_at, circuit_until = float(row[0]), float(row[1])
            effective_interval = max(interval_seconds, float(row[2]))
            if circuit_until > now:
                return Reservation(circuit_until=circuit_until)

            wait_seconds = max(0.0, next_allowed_at - now)
            if wait_seconds > max_wait_seconds:
                return Reservation(deferred_until=next_allowed_at)

            slot = max(now, next_allowed_at)
            self._connection.execute(
                """
                UPDATE domain_politeness
                SET next_allowed_at = ?
                WHERE domain = ?
                """,
                (slot + effective_interval, domain),
            )
            return Reservation(wait_seconds=wait_seconds)

    async def set_interval(self, domain: str, interval_seconds: float) -> None:
        if interval_seconds < 0:
            raise ValueError("interval_seconds must not be negative")
        await asyncio.to_thread(self._set_interval, domain, interval_seconds)

    def _set_interval(self, domain: str, interval_seconds: float) -> None:
        # The coordinator permits only one active scan per registrable domain, so
        # replacing the prior robots interval cannot invalidate another live slot.
        # This exact replacement is what lets a later 404/no-directive response
        # clear a stale Crawl-delay instead of conservatively retaining it forever.
        now = self._clock()
        with self._transaction():
            self._ensure_domain(domain, now)
            self._connection.execute(
                """
                UPDATE domain_politeness
                SET interval_seconds = ?, next_allowed_at = ?, updated_at = ?
                WHERE domain = ?
                """,
                (interval_seconds, now + interval_seconds, now, domain),
            )

    async def record_success(self, domain: str) -> None:
        await asyncio.to_thread(self._record_success, domain)

    def _record_success(self, domain: str) -> None:
        now = self._clock()
        with self._transaction():
            self._ensure_domain(domain, now)
            self._connection.execute(
                """
                UPDATE domain_politeness
                SET consecutive_failures = 0, circuit_until = 0, updated_at = ?
                WHERE domain = ?
                """,
                (now, domain),
            )

    async def record_transient(
        self,
        domain: str,
        *,
        retry_after_seconds: float,
        circuit_threshold: int,
        circuit_cooldown_seconds: float,
    ) -> TransientState:
        return await asyncio.to_thread(
            self._record_transient,
            domain,
            retry_after_seconds,
            circuit_threshold,
            circuit_cooldown_seconds,
        )

    def _record_transient(
        self,
        domain: str,
        retry_after_seconds: float,
        circuit_threshold: int,
        circuit_cooldown_seconds: float,
    ) -> TransientState:
        now = self._clock()
        with self._transaction():
            self._ensure_domain(domain, now)
            row = self._connection.execute(
                """
                SELECT next_allowed_at, consecutive_failures, circuit_until, updated_at
                FROM domain_politeness
                WHERE domain = ?
                """,
                (domain,),
            ).fetchone()
            if row is None:
                raise RuntimeError("politeness state disappeared while recording failure")

            previous_failures = int(row[1])
            failure_is_recent = now - float(row[3]) <= circuit_cooldown_seconds
            failures = previous_failures + 1 if failure_is_recent else 1
            blocked_until = max(float(row[0]), now + max(0.0, retry_after_seconds))
            circuit_until = float(row[2])
            if failures >= circuit_threshold:
                circuit_until = max(
                    circuit_until,
                    blocked_until,
                    now + circuit_cooldown_seconds,
                )
            self._connection.execute(
                """
                UPDATE domain_politeness
                SET next_allowed_at = ?, consecutive_failures = ?,
                    circuit_until = ?, updated_at = ?
                WHERE domain = ?
                """,
                (blocked_until, failures, circuit_until, now, domain),
            )
            return TransientState(
                consecutive_failures=failures,
                blocked_until=blocked_until,
                circuit_until=circuit_until if circuit_until > now else None,
            )

    async def close(self) -> None:
        await asyncio.to_thread(self._close)

    def _close(self) -> None:
        with self._lock:
            self._connection.close()

    def _ensure_domain(self, domain: str, now: float) -> None:
        self._connection.execute(
            """
            INSERT OR IGNORE INTO domain_politeness (domain, updated_at)
            VALUES (?, ?)
            """,
            (domain, now),
        )

    def _transaction(self) -> "_Transaction":
        return _Transaction(self._connection, self._lock)


class _Transaction:
    def __init__(self, connection: sqlite3.Connection, lock: threading.Lock) -> None:
        self._connection = connection
        self._lock = lock

    def __enter__(self) -> None:
        self._lock.acquire()
        try:
            self._connection.execute("BEGIN IMMEDIATE")
        except BaseException:
            self._lock.release()
            raise

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            self._connection.execute("ROLLBACK" if exc_type is not None else "COMMIT")
        finally:
            self._lock.release()


def politeness_key(url: str | httpx.URL) -> str:
    parsed = httpx.URL(url)
    hostname = parsed.host.rstrip(".").lower()
    try:
        return registrable_domain(hostname)
    except ValueError:
        # Public IP literals pass URL safety but do not have a registrable domain.
        return hostname


def parse_retry_after(value: str | None, *, now: datetime | None = None) -> float | None:
    """Parse Retry-After seconds or an HTTP date into a non-negative delay."""

    if value is None:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        seconds = int(candidate)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(candidate)
        except (TypeError, ValueError, OverflowError):
            return None
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)
        current = now or datetime.now(UTC)
        return max(0.0, (retry_at - current).total_seconds())
    return float(seconds) if seconds >= 0 else None
