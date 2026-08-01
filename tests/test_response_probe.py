from datetime import UTC, datetime

import pytest

from web_openness.client import FetchResult, SiteClient
from web_openness.config import ScanConfig
from web_openness.models import Confidence, RequestRecord
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
    assert values["infrastructure.security_headers"].value == [
        "content-security-policy",
        "strict-transport-security",
    ]


@pytest.mark.asyncio
async def test_classifies_authentication_challenge() -> None:
    values = await ResponseProbe().collect(_context(401, {"www-authenticate": "Basic"}))

    assert values["human.http_access_disposition"].value == "authentication_required"
    assert values["human.authentication_challenge"].value is True
    assert values["human.rate_limited"].value is False
    assert values["human.rate_limited"].confidence == Confidence.CONFIRMED


@pytest.mark.asyncio
async def test_failed_fetch_does_not_emit_negative_response_findings() -> None:
    values = await ResponseProbe().collect(
        _context(None, {}, error="URLSafetyError: redirect was rejected")
    )

    assert all(value.value is None for value in values.values())
    assert all(value.confidence == Confidence.UNKNOWN for value in values.values())
