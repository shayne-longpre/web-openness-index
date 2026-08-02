import asyncio
from datetime import UTC, datetime

import pytest

from web_openness.browser_policy import (
    BrowserPolicy,
    BrowserPolicyError,
    BrowserRender,
    BrowserRequestGate,
    run_browser_worker,
)
from web_openness.safety import URLSafetyError


async def _public_resolver(_hostname: str, _port: int) -> tuple[str, ...]:
    return ("93.184.216.34",)


@pytest.mark.asyncio
async def test_gate_bounds_first_and_third_party_requests() -> None:
    gate = BrowserRequestGate(
        "https://www.example.org/",
        BrowserPolicy(enabled=True, max_requests=3, max_third_party_requests=1),
        resolver=_public_resolver,
    )

    first_party = await gate.authorize("https://static.example.org/site.css")
    third_party = await gate.authorize("https://cdn.example.net/library.js")

    assert first_party.third_party is False
    assert third_party.third_party is True
    with pytest.raises(BrowserPolicyError, match="third-party"):
        await gate.authorize("https://images.example.net/logo.png")


@pytest.mark.asyncio
async def test_gate_rejects_non_public_destinations_before_counting_request() -> None:
    async def private_resolver(_hostname: str, _port: int) -> tuple[str, ...]:
        return ("10.0.0.8",)

    gate = BrowserRequestGate(
        "https://example.org/",
        BrowserPolicy(enabled=True),
        resolver=private_resolver,
    )

    with pytest.raises(URLSafetyError):
        await gate.authorize("https://internal.example.org/")
    assert gate.request_count == 0


def test_gate_bounds_response_and_total_bytes() -> None:
    gate = BrowserRequestGate(
        "https://example.org/",
        BrowserPolicy(
            enabled=True,
            max_response_bytes=100,
            max_total_response_bytes=150,
        ),
    )

    gate.record_response(90)
    with pytest.raises(BrowserPolicyError, match="response byte"):
        gate.record_response(101)
    with pytest.raises(BrowserPolicyError, match="total response"):
        gate.record_response(70)


def test_gate_reconciles_streamed_chunks_with_final_response_total() -> None:
    gate = BrowserRequestGate(
        "https://example.org/",
        BrowserPolicy(enabled=True),
    )

    gate.record_response_chunk("document", 30)
    gate.record_response_total("document", 100)
    gate.record_response_total("document", 90)

    assert gate.total_response_bytes == 100


@pytest.mark.asyncio
async def test_browser_runner_is_disabled_by_default_and_times_out() -> None:
    class Worker:
        async def render(self, target_url: str, request_gate: BrowserRequestGate) -> BrowserRender:
            await asyncio.sleep(0.05)
            return BrowserRender(
                final_url=target_url,
                status_code=200,
                title=None,
                document_chars=0,
                visible_text_chars=0,
                markers={},
                observed_at=datetime.now(UTC),
            )

    with pytest.raises(BrowserPolicyError, match="disabled"):
        await run_browser_worker(Worker(), "https://example.org/", BrowserPolicy())

    with pytest.raises(BrowserPolicyError, match="wall-time"):
        await run_browser_worker(
            Worker(),
            "https://example.org/",
            BrowserPolicy(enabled=True, wall_time_seconds=0.001),
            resolver=_public_resolver,
        )


@pytest.mark.asyncio
async def test_browser_runner_reports_gate_counts() -> None:
    class Worker:
        async def render(self, target_url: str, request_gate: BrowserRequestGate) -> BrowserRender:
            await request_gate.authorize(target_url, top_level_navigation=True)
            request_gate.record_response_chunk("document", 42)
            return BrowserRender(
                final_url=target_url,
                status_code=200,
                title="Example",
                document_chars=100,
                visible_text_chars=20,
                markers={"paywall": ()},
                observed_at=datetime.now(UTC),
            )

    result = await run_browser_worker(
        Worker(),
        "https://example.org/",
        BrowserPolicy(enabled=True),
        resolver=_public_resolver,
    )

    assert result.request_count == 1
    assert result.third_party_request_count == 0
    assert result.total_response_bytes == 42


@pytest.mark.asyncio
async def test_gate_blocks_cross_site_navigation_and_policy_rejections() -> None:
    resolver_called = False

    async def resolver(_hostname: str, _port: int) -> tuple[str, ...]:
        nonlocal resolver_called
        resolver_called = True
        return ("93.184.216.34",)

    gate = BrowserRequestGate(
        "https://example.org/",
        BrowserPolicy(enabled=True),
        resolver=resolver,
        url_allowed=lambda url: "/private" not in url,
    )

    with pytest.raises(BrowserPolicyError, match="collection policy"):
        await gate.authorize("https://example.org/private")
    assert resolver_called is False
    with pytest.raises(BrowserPolicyError, match="cross-site"):
        await gate.authorize(
            "https://example.net/",
            top_level_navigation=True,
        )
    assert resolver_called is False
    assert gate.request_count == 0
