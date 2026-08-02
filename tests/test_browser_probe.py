from datetime import UTC, datetime

import httpx
import pytest

from web_openness.browser_policy import BrowserPolicy, BrowserRender, BrowserRequestGate
from web_openness.config import ScanConfig
from web_openness.models import ObservationOutcome
from web_openness.pipeline import Scanner
from web_openness.probes import BrowserProbe, HomepageProbe, RobotsProbe


class FixtureBrowserWorker:
    def __init__(self, *, fail: bool = False) -> None:
        self.called = False
        self.fail = fail

    async def render(
        self,
        target_url: str,
        request_gate: BrowserRequestGate,
    ) -> BrowserRender:
        self.called = True
        if self.fail:
            raise RuntimeError("fixture browser failed")
        await request_gate.authorize(target_url, top_level_navigation=True)
        request_gate.record_response_chunk("document", 120)
        return BrowserRender(
            final_url=target_url,
            status_code=200,
            title="Rendered title",
            document_chars=320,
            visible_text_chars=80,
            markers={
                "login": (),
                "paywall": ('[id*="paywall" i]',),
                "cookie_wall": (),
                "captcha": (),
            },
            observed_at=datetime.now(UTC),
        )


def _transport(*, robots: str = "User-agent: *\nAllow: /\n") -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text=robots, request=request)
        if request.url.path == "/":
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="<title>HTTP title</title><main>Short</main>",
                request=request,
            )
        raise AssertionError(f"unexpected request: {request.url}")

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_browser_probe_collects_render_comparison_and_visible_markers() -> None:
    worker = FixtureBrowserWorker()
    scanner = Scanner(
        ScanConfig(
            request_delay_seconds=0,
            browser_policy=BrowserPolicy(enabled=True),
        ),
        probes=(RobotsProbe(), HomepageProbe(), BrowserProbe()),
        transport=_transport(),
        browser_worker=worker,
    )

    snapshot = await scanner.scan("93.184.216.34")

    assert worker.called is True
    comparison = snapshot.observations["crawler.browser_http_difference"]
    assert comparison.value["http_status"] == 200
    assert comparison.value["browser_status"] == 200
    assert comparison.value["document_char_delta"] > 0
    assert snapshot.observations["browser.network_summary"].value == {
        "requests": 1,
        "third_party_requests": 0,
        "blocked_requests": 0,
        "transferred_response_bytes": 120,
    }
    assert snapshot.observations["human.browser_paywall_marker_visible"].value == {
        "visible": True,
        "selectors": ['[id*="paywall" i]'],
    }
    assert snapshot.observations["human.browser_login_marker_visible"].outcome == (
        ObservationOutcome.NO_EVIDENCE
    )
    assert snapshot.errors == []


@pytest.mark.asyncio
async def test_browser_probe_is_disabled_by_default() -> None:
    worker = FixtureBrowserWorker()
    scanner = Scanner(
        ScanConfig(request_delay_seconds=0),
        probes=(RobotsProbe(), HomepageProbe(), BrowserProbe()),
        transport=_transport(),
        browser_worker=worker,
    )

    snapshot = await scanner.scan("93.184.216.34")

    assert worker.called is False
    assert snapshot.observations["browser.navigation"].outcome == ObservationOutcome.SKIPPED


@pytest.mark.asyncio
async def test_browser_probe_fails_closed_when_robots_disallows_homepage() -> None:
    worker = FixtureBrowserWorker()
    scanner = Scanner(
        ScanConfig(
            request_delay_seconds=0,
            browser_policy=BrowserPolicy(enabled=True),
        ),
        probes=(RobotsProbe(), HomepageProbe(), BrowserProbe()),
        transport=_transport(robots="User-agent: *\nDisallow: /\n"),
        browser_worker=worker,
    )

    snapshot = await scanner.scan("93.184.216.34")

    assert worker.called is False
    assert snapshot.observations["browser.navigation"].outcome == ObservationOutcome.SKIPPED


@pytest.mark.asyncio
async def test_browser_probe_preserves_worker_failure_as_signal_errors() -> None:
    worker = FixtureBrowserWorker(fail=True)
    scanner = Scanner(
        ScanConfig(
            request_delay_seconds=0,
            browser_policy=BrowserPolicy(enabled=True),
        ),
        probes=(RobotsProbe(), HomepageProbe(), BrowserProbe()),
        transport=_transport(),
        browser_worker=worker,
    )

    snapshot = await scanner.scan("93.184.216.34")

    assert snapshot.observations["browser.navigation"].outcome == ObservationOutcome.ERROR
    assert snapshot.errors[0].probe == "browser"
    assert "fixture browser failed" in snapshot.errors[0].message
