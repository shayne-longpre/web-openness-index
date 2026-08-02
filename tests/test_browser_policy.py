import asyncio

import pytest

from web_openness.browser_policy import (
    BrowserPolicy,
    BrowserPolicyError,
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


@pytest.mark.asyncio
async def test_browser_runner_is_disabled_by_default_and_times_out() -> None:
    class Worker:
        async def render(
            self, target_url: str, request_gate: BrowserRequestGate
        ) -> dict[str, object]:
            await asyncio.sleep(0.05)
            return {"target_url": target_url}

    with pytest.raises(BrowserPolicyError, match="disabled"):
        await run_browser_worker(Worker(), "https://example.org/", BrowserPolicy())

    with pytest.raises(BrowserPolicyError, match="wall-time"):
        await run_browser_worker(
            Worker(),
            "https://example.org/",
            BrowserPolicy(enabled=True, wall_time_seconds=0.001),
            resolver=_public_resolver,
        )
