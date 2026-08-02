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
    cookie_names: tuple[str, ...] = (),
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
        cookie_names=cookie_names,
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
    assert values["infrastructure.waf"].value == []
    assert values["infrastructure.waf"].confidence == Confidence.NO_EVIDENCE
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
async def test_451_is_a_conservative_geographic_restriction_hint() -> None:
    values = await ResponseProbe().collect(_context(451, {}))

    assert values["human.http_access_disposition"].value == ("unavailable_for_legal_reasons")
    assert values["human.geographic_restriction"].value == {
        "detected": True,
        "status": 451,
    }
    assert values["human.geographic_restriction"].confidence == Confidence.POSSIBLE


@pytest.mark.asyncio
async def test_reports_only_specific_waf_response_hints() -> None:
    values = await ResponseProbe().collect(
        _context(
            403,
            {
                "cf-mitigated": "challenge",
                "x-iinfo": "test",
                "x-sucuri-block": "DENY",
                "x-sucuri-id": "test",
                "x-wa-info": "test",
            },
        )
    )

    finding = values["infrastructure.waf"]
    assert finding.value == ["cloudflare", "sucuri"]
    assert finding.confidence == Confidence.LIKELY
    assert values["infrastructure.cdn_hints"].value == []
    assert values["infrastructure.edge_response_hints"].value == [
        "cloudflare",
        "f5",
        "imperva",
        "sucuri",
    ]
    assert values["infrastructure.acceleration_hints"].value == ["f5_big_ip"]
    assert values["infrastructure.challenge_response"].value == {
        "provider": "cloudflare",
        "type": "challenge",
    }


@pytest.mark.asyncio
async def test_collects_response_capabilities_without_cookie_values() -> None:
    values = await ResponseProbe().collect(
        _context(
            200,
            {
                "alt-svc": 'h3=":443"; ma=86400',
                "cf-cache-status": "hit",
                "cf-ray": "abc123-SFO",
                "content-encoding": "br",
            },
            cookie_names=("__cf_bm", "BIGipServerPool", "ordinary_session"),
        )
    )

    assert values["infrastructure.cache_status"].value == [
        {"provider": "cloudflare", "status": "HIT"}
    ]
    assert values["infrastructure.edge_location_hints"].value == {"cloudflare": "SFO"}
    assert values["infrastructure.http3_advertised"].value is True
    assert values["infrastructure.content_encoding"].value == "br"
    assert values["infrastructure.response_cookie_fingerprints"].value == [
        "cloudflare:__cf_bm",
        "f5:BIGipServer*",
    ]
    assert values["infrastructure.bot_management_hints"].value == ["cloudflare"]
    assert values["infrastructure.load_balancer_hints"].value == ["f5"]


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
