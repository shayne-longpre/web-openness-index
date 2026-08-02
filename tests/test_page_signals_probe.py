from datetime import UTC, datetime

import pytest

from web_openness.client import FetchResult, SiteClient
from web_openness.config import ScanConfig
from web_openness.models import Confidence, Evidence, ObservationOutcome, RequestRecord
from web_openness.probes.base import ProbeContext
from web_openness.probes.page_signals import PageSignalsProbe


def _context(html: str | None, *, truncated: bool = False) -> ProbeContext:
    config = ScanConfig(request_delay_seconds=0)
    context = ProbeContext(
        domain="example.org",
        origin="https://example.org",
        config=config,
        client=SiteClient(config),
    )
    if html is None:
        context.shared["robots_allows_followup"] = False
        return context

    record = RequestRecord(
        requested_url="https://example.org/",
        final_url="https://www.example.org/article",
        started_at=datetime.now(UTC),
        elapsed_ms=1,
        status_code=200,
        response_bytes=len(html),
    )
    context.shared.update(
        {
            "robots_allows_followup": True,
            "homepage_html": html,
            "homepage_evidence": Evidence(
                source_url="https://www.example.org/article",
                observed_at=datetime.now(UTC),
                http_status=200,
            ),
            "homepage_response": FetchResult(
                requested_url="https://example.org/",
                final_url="https://www.example.org/article",
                status_code=200,
                headers={"content-type": "text/html"},
                body=html.encode(),
                truncated=truncated,
                error=None,
                evidence=record,
                http_version="HTTP/2",
            ),
        }
    )
    return context


@pytest.mark.asyncio
async def test_collects_explicit_page_access_signals_without_more_requests() -> None:
    html = """
    <html><head>
      <link rel="license" href="/license">
      <script src="https://cdn.cookielaw.org/consent.js"></script>
      <script src="https://www.google.com/recaptcha/api.js"></script>
      <script src="https://cdn.tinypass.com/paywall.js"></script>
      <script type="application/ld+json">
        {
          "@type": "NewsArticle",
          "license": "https://creativecommons.org/licenses/by/4.0/",
          "isAccessibleForFree": false,
          "requiresSubscription": true
        }
      </script>
    </head><body>
      <div id="subscription-wall"></div>
      <noscript>Please enable JavaScript to continue.</noscript>
    </body></html>
    """

    values = await PageSignalsProbe().collect(_context(html))

    assert values["human.paywall_detected"].value["detected"] is True
    assert values["human.paywall_detected"].confidence == Confidence.LIKELY
    assert values["human.cookie_wall_detected"].value == {
        "detected": True,
        "markers": ["resource:cookielaw.org"],
    }
    assert values["human.captcha_detected"].value == {
        "detected": True,
        "markers": ["resource:google.com/recaptcha"],
    }
    assert values["human.javascript_required"].value["detected"] is True
    assert values["legal.license"].value == [
        "https://creativecommons.org/licenses/by/4.0/",
        "https://www.example.org/license",
    ]
    assert values["economic.subscription_required"].value is True


@pytest.mark.asyncio
async def test_absence_is_no_evidence_not_a_negative_finding() -> None:
    values = await PageSignalsProbe().collect(
        _context(
            """
            <html><body>
              <a href="/cookie-policy">Cookie policy</a>
              <a href="/paywall-research">Paywall research</a>
              <p>Our article discusses captcha accessibility.</p>
            </body></html>
            """
        )
    )

    for key in (
        "human.paywall_detected",
        "human.cookie_wall_detected",
        "human.captcha_detected",
        "human.javascript_required",
        "legal.license",
        "economic.subscription_required",
    ):
        assert values[key].value in (None, [])
        assert values[key].confidence == Confidence.NO_EVIDENCE
        assert values[key].outcome == ObservationOutcome.NO_EVIDENCE


@pytest.mark.asyncio
async def test_explicit_subscription_false_is_a_collected_negative() -> None:
    values = await PageSignalsProbe().collect(
        _context(
            """
            <script type="application/ld+json">
              {"@type": "WebSite", "requiresSubscription": "false"}
            </script>
            """
        )
    )

    finding = values["economic.subscription_required"]
    assert finding.value is False
    assert finding.confidence == Confidence.CONFIRMED
    assert finding.outcome == ObservationOutcome.OBSERVED


@pytest.mark.asyncio
async def test_truncated_html_keeps_markers_but_invalidates_absence() -> None:
    values = await PageSignalsProbe().collect(_context('<div id="paywall"></div>', truncated=True))

    assert values["human.paywall_detected"].value["detected"] is True
    assert values["human.paywall_detected"].outcome == ObservationOutcome.OBSERVED
    assert values["human.captcha_detected"].value is None
    assert values["human.captcha_detected"].outcome == ObservationOutcome.ERROR


@pytest.mark.asyncio
async def test_unavailable_homepage_marks_page_signals_skipped() -> None:
    values = await PageSignalsProbe().collect(_context(None))

    assert all(value.value is None for value in values.values())
    assert all(value.confidence == Confidence.UNKNOWN for value in values.values())
    assert all(value.outcome == ObservationOutcome.SKIPPED for value in values.values())
