from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from web_openness.client import SiteClient
from web_openness.config import ScanConfig
from web_openness.pipeline import Scanner
from web_openness.politeness import (
    SQLitePolitenessStore,
    parse_retry_after,
    politeness_key,
)
from web_openness.probes import HomepageProbe, RobotsProbe
from web_openness.probes.base import ProbeContext


class FakeClock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.mark.asyncio
async def test_sqlite_reservations_persist_and_coordinate_workers(tmp_path: Path) -> None:
    clock = FakeClock()
    path = tmp_path / "politeness.sqlite3"
    first = SQLitePolitenessStore(path, clock=clock)
    second = SQLitePolitenessStore(path, clock=clock)
    key = politeness_key("https://news.example.co.uk/story")

    try:
        initial = await first.reserve(key, interval_seconds=2, max_wait_seconds=5)
        queued = await second.reserve(key, interval_seconds=2, max_wait_seconds=5)
        await first.close()

        reopened = SQLitePolitenessStore(path, clock=clock)
        try:
            persisted = await reopened.reserve(key, interval_seconds=2, max_wait_seconds=1)
        finally:
            await reopened.close()
    finally:
        await second.close()

    assert key == "example.co.uk"
    assert initial.wait_seconds == 0
    assert queued.wait_seconds == 2
    assert persisted.deferred_until == 1_004


@pytest.mark.asyncio
async def test_deferred_workers_do_not_extend_existing_cooldown() -> None:
    clock = FakeClock()
    store = SQLitePolitenessStore(":memory:", clock=clock)
    try:
        await store.reserve("example.org", interval_seconds=10, max_wait_seconds=10)
        first = await store.reserve("example.org", interval_seconds=10, max_wait_seconds=1)
        second = await store.reserve("example.org", interval_seconds=10, max_wait_seconds=1)
    finally:
        await store.close()

    assert first.deferred_until == 1_010
    assert second.deferred_until == 1_010


@pytest.mark.asyncio
async def test_repeated_transients_open_persistent_domain_circuit(tmp_path: Path) -> None:
    clock = FakeClock()
    path = tmp_path / "politeness.sqlite3"
    store = SQLitePolitenessStore(path, clock=clock)
    try:
        first = await store.record_transient(
            "example.org",
            retry_after_seconds=5,
            circuit_threshold=2,
            circuit_cooldown_seconds=60,
        )
        clock.advance(5)
        second = await store.record_transient(
            "example.org",
            retry_after_seconds=0,
            circuit_threshold=2,
            circuit_cooldown_seconds=60,
        )
    finally:
        await store.close()

    reopened = SQLitePolitenessStore(path, clock=clock)
    try:
        reservation = await reopened.reserve(
            "example.org",
            interval_seconds=1,
            max_wait_seconds=5,
        )
    finally:
        await reopened.close()

    assert first.circuit_until is None
    assert second.consecutive_failures == 2
    assert second.circuit_until == 1_065
    assert reservation.circuit_until == 1_065


def test_retry_after_parses_seconds_dates_and_invalid_values() -> None:
    now = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)

    assert parse_retry_after("15", now=now) == 15
    assert parse_retry_after("Sat, 01 Aug 2026 12:00:20 GMT", now=now) == 20
    assert parse_retry_after("-1", now=now) is None
    assert parse_retry_after("later", now=now) is None


@pytest.mark.asyncio
async def test_429_retries_once_and_records_both_attempts() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                429,
                headers={"retry-after": "0"},
                request=request,
            )
        return httpx.Response(200, text="ok", request=request)

    async with SiteClient(
        ScanConfig(request_delay_seconds=0),
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await client.get("https://www.example.org/")

    assert result.status_code == 200
    assert calls == 2
    assert [record.status_code for record in client.records] == [429, 200]
    assert [record.status_code for record in result.attempts] == [429, 200]


@pytest.mark.asyncio
async def test_long_retry_after_defers_without_sleeping_or_retrying() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, headers={"retry-after": "30"}, request=request)

    async with SiteClient(
        ScanConfig(request_delay_seconds=0, max_politeness_wait_seconds=1),
        transport=httpx.MockTransport(handler),
    ) as client:
        first = await client.get("https://www.example.org/")
        deferred = await client.get("https://api.example.org/data")

    assert first.status_code == 429
    assert deferred.error is not None
    assert deferred.error.startswith("DomainDeferred:")
    assert calls == 1
    assert len(client.records) == 1


@pytest.mark.asyncio
async def test_second_transient_opens_circuit_and_ceases_domain() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, request=request)

    async with SiteClient(
        ScanConfig(request_budget=5, request_delay_seconds=0),
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await client.get("https://www.example.org/")
        ceased = await client.get("https://static.example.org/file")

    assert result.status_code == 503
    assert [record.status_code for record in result.attempts] == [503, 503]
    assert ceased.error is not None
    assert ceased.error.startswith("DomainCircuitOpen:")
    assert calls == 2
    assert len(client.records) == 2


@pytest.mark.asyncio
async def test_retry_never_exceeds_request_budget() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, request=request)

    async with SiteClient(
        ScanConfig(request_budget=1, request_delay_seconds=0),
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await client.get("https://example.org/")

    assert result.status_code == 503
    assert calls == 1
    assert len(client.records) == 1


@pytest.mark.asyncio
async def test_large_robots_crawl_delay_ceases_followup_requests() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        assert request.url.path == "/robots.txt"
        return httpx.Response(
            200,
            text="User-agent: *\nAllow: /\nCrawl-delay: 30\n",
            request=request,
        )

    snapshot = await Scanner(
        ScanConfig(request_delay_seconds=0, max_politeness_wait_seconds=1),
        probes=(RobotsProbe(), HomepageProbe()),
        transport=httpx.MockTransport(handler),
    ).scan("example.org")

    assert calls == ["/robots.txt"]
    assert snapshot.request_count == 1
    assert snapshot.observations["crawler.crawl_delays"].value == {"*": "30"}
    assert snapshot.observations["human.homepage_accessible"].value is None


@pytest.mark.asyncio
async def test_missing_robots_file_resets_persisted_delay_to_base() -> None:
    clock = FakeClock()
    store = SQLitePolitenessStore(":memory:", clock=clock)
    await store.set_interval("example.org", 30)
    clock.advance(30)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        status = 404 if request.url.path == "/robots.txt" else 200
        return httpx.Response(status, text="ok", request=request)

    config = ScanConfig(request_delay_seconds=0, max_politeness_wait_seconds=1)
    try:
        async with SiteClient(
            config,
            transport=httpx.MockTransport(handler),
            politeness_store=store,
        ) as client:
            context = ProbeContext(
                domain="example.org",
                origin="https://example.org",
                config=config,
                client=client,
            )
            await RobotsProbe().collect(context)
            await HomepageProbe().collect(context)
    finally:
        await store.close()

    assert calls == ["/robots.txt", "/"]
