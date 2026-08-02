from datetime import UTC, datetime

import httpx
import pytest

from web_openness.client import FetchResult, SiteClient
from web_openness.config import ScanConfig
from web_openness.models import Confidence, ObservationOutcome, RequestRecord
from web_openness.probes.base import ProbeContext
from web_openness.probes.response import ResponseProbe


def _context(
    status: int | None,
    headers: dict[str, str],
    *,
    error: str | None = None,
) -> ProbeContext:
    config = ScanConfig(request_delay_seconds=0)
    context = ProbeContext(
        domain="example.org",
        origin="https://example.org",
        config=config,
        client=SiteClient(config),
    )
    record = RequestRecord(
        requested_url="https://example.org/",
        final_url="https://example.org/",
        started_at=datetime.now(UTC),
        elapsed_ms=1,
        status_code=status,
        response_bytes=0,
    )
    context.shared["homepage_response"] = FetchResult(
        requested_url="https://example.org/",
        final_url="https://example.org/",
        status_code=status,
        headers=headers,
        body=b"",
        truncated=False,
        error=error,
        evidence=record,
        http_version="HTTP/2",
    )
    return context


@pytest.mark.asyncio
async def test_classifies_protocol_security_cache_and_cdn_hints() -> None:
    values = await ResponseProbe().collect(
        _context(
            200,
            {
                "cache-control": "public, max-age=60",
                "cf-ray": "test-SFO",
                "content-security-policy": "default-src 'self'",
                "server": "cloudflare",
                "strict-transport-security": "max-age=31536000",
            },
        )
    )

    assert values["network.http_version"].value == "HTTP/2"
    assert values["human.http_access_disposition"].value == "reachable"
    assert values["infrastructure.cdn_hints"].value == ["cloudflare"]
    assert values["infrastructure.cdn_hints"].confidence == Confidence.LIKELY
    assert values["infrastructure.cdn"].value == ["cloudflare"]
    assert values["preservation.cache_header_hints"].value == {
        "cache-control": "public, max-age=60"
    }
    assert "preservation.cache_behavior" not in values
    assert values["infrastructure.security_headers"].value == [
        "content-security-policy",
        "strict-transport-security",
    ]


@pytest.mark.asyncio
async def test_classifies_authentication_challenge() -> None:
    values = await ResponseProbe().collect(_context(401, {"www-authenticate": "Basic"}))

    assert values["human.http_access_disposition"].value == "authentication_required"
    assert values["human.authentication_challenge"].value is True
    assert values["human.login_required"].value is True
    assert values["human.rate_limited"].value is False
    assert values["human.rate_limited"].confidence == Confidence.CONFIRMED


@pytest.mark.asyncio
async def test_failed_fetch_does_not_emit_negative_response_findings() -> None:
    values = await ResponseProbe().collect(
        _context(None, {}, error="URLSafetyError: redirect was rejected")
    )

    assert all(value.value is None for value in values.values())
    assert all(value.confidence == Confidence.UNKNOWN for value in values.values())
    assert all(value.outcome == ObservationOutcome.ERROR for value in values.values())


@pytest.mark.asyncio
async def test_successful_retry_preserves_429_measurement_evidence() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        status = 429 if calls == 1 else 200
        headers = {"retry-after": "0"} if status == 429 else {}
        return httpx.Response(status, headers=headers, request=request)

    config = ScanConfig(request_delay_seconds=0)
    async with SiteClient(config, transport=httpx.MockTransport(handler)) as client:
        result = await client.get("https://example.org/")
        context = ProbeContext(
            domain="example.org",
            origin="https://example.org",
            config=config,
            client=client,
            shared={"homepage_response": result},
        )
        values = await ResponseProbe().collect(context)

    rate_limited = values["human.rate_limited"]
    assert result.status_code == 200
    assert [record.status_code for record in result.attempts] == [429, 200]
    assert rate_limited.value is True
    assert [item.http_status for item in rate_limited.evidence] == [429]
