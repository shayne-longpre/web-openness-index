import asyncio
from pathlib import Path

import httpx
import pytest

from web_openness.config import ScanConfig
from web_openness.governance import CollectionCeased
from web_openness.models import Confidence, Observation, ObservationOutcome
from web_openness.pipeline import DomainScanTimedOut, Scanner, normalize_target
from web_openness.probes import (
    HomepageProbe,
    MetadataProbe,
    RobotsProbe,
    SitemapProbe,
    WellKnownProbe,
)
from web_openness.probes.base import ProbeContext
from web_openness.safety import URLSafetyError
from web_openness.storage import write_snapshot

OFFLINE_HTTP_PROBES = (
    RobotsProbe(),
    SitemapProbe(),
    HomepageProbe(),
    MetadataProbe(),
    WellKnownProbe(),
)


def test_normalize_target() -> None:
    assert normalize_target("Example.ORG/path") == ("example.org", "https://example.org")
    assert normalize_target("http://example.org:8080") == (
        "example.org",
        "http://example.org:8080",
    )


@pytest.mark.asyncio
async def test_scanner_rejects_local_target_before_running_probes() -> None:
    class ExplodingProbe:
        name = "must_not_run"

        async def collect(self, _context: ProbeContext) -> dict[str, Observation]:
            raise AssertionError("probe ran before destination validation")

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"HTTP request reached transport: {request.url}")

    scanner = Scanner(
        ScanConfig(request_delay_seconds=0),
        probes=(ExplodingProbe(),),
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(URLSafetyError):
        await scanner.scan("localhost")


@pytest.mark.asyncio
async def test_scanner_enforces_cease_list_before_network(tmp_path: Path) -> None:
    cease_list = tmp_path / "cease-list.txt"
    cease_list.write_text("example.org\n", encoding="utf-8")

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"ceased target reached transport: {request.url}")

    scanner = Scanner(
        ScanConfig(request_delay_seconds=0, cease_list_path=cease_list),
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(CollectionCeased, match=r"example\.org"):
        await scanner.scan("news.example.org")


@pytest.mark.asyncio
async def test_scanner_reloads_cease_list_before_each_target(tmp_path: Path) -> None:
    cease_list = tmp_path / "cease-list.txt"
    cease_list.write_text("", encoding="utf-8")

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"newly ceased target reached transport: {request.url}")

    scanner = Scanner(
        ScanConfig(request_delay_seconds=0, cease_list_path=cease_list),
        transport=httpx.MockTransport(handler),
    )
    cease_list.write_text("example.org\n", encoding="utf-8")

    with pytest.raises(CollectionCeased, match=r"example\.org"):
        await scanner.scan("example.org")


@pytest.mark.asyncio
async def test_scan_collects_evidence_without_live_network(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(
                200,
                text=(
                    "User-agent: *\nAllow: /\n"
                    "User-agent: GPTBot\nDisallow: /\n"
                    "Sitemap: https://example.org/sitemap.xml\n"
                ),
                request=request,
            )
        if request.url.path == "/llms.txt":
            return httpx.Response(200, text="# Example", request=request)
        if request.url.path == "/sitemap.xml":
            return httpx.Response(
                200,
                text=(
                    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                    "<url><loc>https://example.org/one</loc></url>"
                    "</urlset>"
                ),
                request=request,
            )
        if request.url.path == "/":
            return httpx.Response(
                200,
                headers={"content-type": "text/html; charset=utf-8"},
                text=(
                    '<meta property="og:title" content="Example">'
                    '<script type="application/ld+json">{}</script>'
                    '<link rel="alternate" type="application/rss+xml" href="/feed.xml">'
                ),
                request=request,
            )
        raise AssertionError(f"unexpected request: {request.url}")

    scanner = Scanner(
        ScanConfig(request_delay_seconds=0),
        probes=OFFLINE_HTTP_PROBES,
        transport=httpx.MockTransport(handler),
    )
    snapshot = await scanner.scan("example.org")

    assert snapshot.domain == "example.org"
    assert snapshot.request_count == 4
    assert snapshot.errors == []
    assert snapshot.observations["crawler.robots_exists"].value is True
    assert snapshot.observations["crawler.ai_specific_user_agents"].value == ["gptbot"]
    assert snapshot.observations["crawler.ai_homepage_policies"].value["gptbot"] is False
    assert snapshot.observations["crawler.ai_homepage_policies"].value["ccbot"] is True
    assert snapshot.observations["human.homepage_accessible"].value is True
    assert snapshot.observations["metadata.sitemap_exists"].value is True
    assert snapshot.observations["metadata.sitemap_url_count"].value == 1
    assert snapshot.observations["metadata.json_ld"].value is True
    assert snapshot.observations["metadata.open_graph"].value is True
    assert snapshot.observations["metadata.feeds"].value == ["https://example.org/feed.xml"]
    assert snapshot.observations["metadata.llms_txt_exists"].value is True

    path = write_snapshot(snapshot, tmp_path)
    assert path.exists()
    assert f'"run_id": "{snapshot.run_id}"' in path.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_robots_disallow_skips_all_followup_requests() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/robots.txt"
        return httpx.Response(200, text="User-agent: *\nDisallow: /\n", request=request)

    scanner = Scanner(
        ScanConfig(request_delay_seconds=0),
        probes=OFFLINE_HTTP_PROBES,
        transport=httpx.MockTransport(handler),
    )
    snapshot = await scanner.scan("example.org")

    assert snapshot.request_count == 1
    assert snapshot.observations["crawler.homepage_policy_allowed"].value is False
    homepage = snapshot.observations["human.homepage_accessible"]
    assert homepage.value is None
    assert homepage.confidence == Confidence.UNKNOWN
    assert homepage.outcome == ObservationOutcome.SKIPPED
    assert snapshot.observations["metadata.llms_txt_exists"].value is None


@pytest.mark.asyncio
async def test_inconclusive_robots_status_fails_closed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/robots.txt"
        return httpx.Response(403, request=request)

    scanner = Scanner(
        ScanConfig(request_delay_seconds=0),
        probes=OFFLINE_HTTP_PROBES,
        transport=httpx.MockTransport(handler),
    )
    snapshot = await scanner.scan("example.org")

    assert snapshot.request_count == 1
    assert snapshot.observations["crawler.robots_exists"].value is None
    assert snapshot.observations["human.homepage_accessible"].value is None


@pytest.mark.asyncio
async def test_missing_robots_records_unrestricted_policy() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/robots.txt"
        return httpx.Response(404, request=request)

    scanner = Scanner(
        ScanConfig(request_delay_seconds=0),
        probes=(RobotsProbe(),),
        transport=httpx.MockTransport(handler),
    )
    snapshot = await scanner.scan("example.org")

    assert snapshot.observations["crawler.homepage_policy_allowed"].value is True
    policies = snapshot.observations["crawler.ai_homepage_policies"].value
    assert policies["gptbot"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "content_type"),
    [(403, "text/html"), (200, "application/json")],
)
async def test_metadata_skips_error_pages_and_non_html(
    status: int,
    content_type: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404, request=request)
        if request.url.path == "/":
            return httpx.Response(
                status,
                headers={"content-type": content_type},
                text='<a href="/graphql">not homepage metadata</a>',
                request=request,
            )
        raise AssertionError(f"unexpected request: {request.url}")

    scanner = Scanner(
        ScanConfig(request_delay_seconds=0),
        probes=(RobotsProbe(), HomepageProbe(), MetadataProbe()),
        transport=httpx.MockTransport(handler),
    )
    snapshot = await scanner.scan("example.org")

    assert snapshot.observations["agent.interface_links"].value is None
    assert snapshot.observations["metadata.html_title"].value is None


@pytest.mark.asyncio
async def test_scan_outcome_exposes_typed_pacing_deferral() -> None:
    class ForcedDeferralProbe:
        name = "forced_deferral"

        async def collect(self, context: ProbeContext) -> dict[str, Observation]:
            await context.client.set_domain_delay(context.origin, 30)
            result = await context.client.get(context.origin)
            assert result.error is not None
            assert result.deferred_until is not None
            return {}

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"deferred request reached transport: {request.url}")

    scanner = Scanner(
        ScanConfig(request_delay_seconds=0, max_politeness_wait_seconds=1),
        probes=(ForcedDeferralProbe(),),
        transport=httpx.MockTransport(handler),
    )

    outcome = await scanner.scan_outcome("example.org")

    assert outcome.deferred_until is not None
    assert outcome.snapshot.request_count == 0


@pytest.mark.asyncio
async def test_scanner_enforces_domain_wall_clock_budget() -> None:
    class SlowProbe:
        name = "slow"

        async def collect(self, _context: ProbeContext) -> dict[str, Observation]:
            await asyncio.sleep(1)
            return {}

    scanner = Scanner(
        ScanConfig(request_delay_seconds=0, domain_timeout_seconds=0.01),
        probes=(SlowProbe(),),
        transport=httpx.MockTransport(lambda request: httpx.Response(200, request=request)),
    )

    with pytest.raises(DomainScanTimedOut, match="domain scan exceeded"):
        await scanner.scan("example.org")
