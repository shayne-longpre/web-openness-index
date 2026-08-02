from datetime import UTC, datetime

import pytest

from web_openness.client import FetchResult, SiteClient
from web_openness.config import ScanConfig
from web_openness.models import Confidence, Evidence, ObservationOutcome, RequestRecord
from web_openness.probes.base import ProbeContext
from web_openness.probes.metadata import MetadataProbe


def _context(html: str, *, truncated: bool = False) -> ProbeContext:
    config = ScanConfig(request_delay_seconds=0)
    context = ProbeContext(
        domain="example.org",
        origin="https://example.org",
        config=config,
        client=SiteClient(config),
    )
    record = RequestRecord(
        requested_url="https://example.org/",
        final_url="https://www.example.org/landing",
        started_at=datetime.now(UTC),
        elapsed_ms=1,
        status_code=200,
        response_bytes=len(html),
    )
    context.shared.update(
        {
            "homepage_html": html,
            "homepage_evidence": Evidence(
                source_url="https://www.example.org/landing",
                observed_at=datetime.now(UTC),
                http_status=200,
            ),
            "homepage_response": FetchResult(
                requested_url="https://example.org/",
                final_url="https://www.example.org/landing",
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
async def test_extracts_bounded_metadata_and_interface_candidates() -> None:
    html = """
    <html lang="en-US"><head>
      <title> Example Observatory </title>
      <link rel="canonical" href="/about">
      <link rel="alternate" type="application/rss+xml" href="/feed.xml">
      <link rel="manifest" href="/site.webmanifest">
      <link rel="search" type="application/opensearchdescription+xml" href="/search.xml">
      <link rel="service-desc" type="application/vnd.oai.openapi+json" href="/openapi.json">
      <meta name="generator" content="Lean CMS">
      <meta property="og:title" content="Example">
      <script type="application/ld+json">{"@type": ["WebSite", "Organization"]}</script>
    </head><body>
      <a href="/graphql">GraphQL</a>
      <a href="/legal/terms">Terms of use</a>
      <a href="/pricing">Plans</a>
      <svg><title>Icon</title></svg>
    </body></html>
    """

    values = await MetadataProbe().collect(_context(html))

    assert values["metadata.html_title"].value == "Example Observatory"
    assert values["metadata.html_language"].value == "en-US"
    assert values["metadata.canonical_url"].value == "https://www.example.org/about"
    assert values["metadata.feeds"].value == ["https://www.example.org/feed.xml"]
    assert values["metadata.web_manifest_url"].value.endswith("/site.webmanifest")
    assert values["metadata.opensearch_url"].value.endswith("/search.xml")
    assert values["metadata.generator"].value == "Lean CMS"
    assert values["metadata.json_ld_types"].value == ["Organization", "WebSite"]
    assert [item["url"] for item in values["agent.interface_links"].value] == [
        "https://www.example.org/openapi.json",
        "https://www.example.org/graphql",
    ]
    assert values["agent.interface_links"].confidence == Confidence.POSSIBLE
    assert values["agent.openapi"].value == ["https://www.example.org/openapi.json"]
    assert values["agent.graphql"].value == ["https://www.example.org/graphql"]
    assert values["agent.mcp"].confidence == Confidence.NO_EVIDENCE
    assert values["legal.policy_links"].value == [
        {"url": "https://www.example.org/legal/terms", "text": "Terms of use"}
    ]
    assert values["economic.pricing_links"].value == [
        {"url": "https://www.example.org/pricing", "text": "Plans"}
    ]


@pytest.mark.asyncio
async def test_malformed_json_ld_is_unknown_without_breaking_other_metadata() -> None:
    values = await MetadataProbe().collect(
        _context('<html><script type="application/ld+json">{broken</script></html>')
    )

    assert values["metadata.json_ld"].value is True
    assert values["metadata.json_ld_types"].value == []
    assert values["metadata.json_ld_types"].confidence == Confidence.UNKNOWN
    assert values["metadata.json_ld_types"].outcome == ObservationOutcome.ERROR
    assert values["metadata.feeds"].confidence == Confidence.NO_EVIDENCE


@pytest.mark.asyncio
async def test_truncated_html_keeps_findings_but_invalidates_absence() -> None:
    values = await MetadataProbe().collect(
        _context('<meta property="og:title" content="Example">', truncated=True)
    )

    assert values["metadata.open_graph"].value is True
    assert values["metadata.open_graph"].outcome == ObservationOutcome.OBSERVED
    assert values["metadata.feeds"].value is None
    assert values["metadata.feeds"].outcome == ObservationOutcome.ERROR


@pytest.mark.asyncio
async def test_discovery_markers_match_tokens_not_substrings() -> None:
    values = await MetadataProbe().collect(
        _context('<html><body><a href="/photos">Photos</a></body></html>')
    )

    assert values["legal.policy_links"].value == []


@pytest.mark.asyncio
async def test_interface_markers_match_path_components_not_substrings() -> None:
    values = await MetadataProbe().collect(
        _context(
            '<a href="/mcpherson">Biography</a>'
            '<a href="/a2about">About</a>'
            '<a href="/.well-known/agentless">Agentless</a>'
            '<a href="/openapi.json">OpenAPI</a>'
        )
    )

    assert [item["url"] for item in values["agent.interface_links"].value] == [
        "https://www.example.org/openapi.json"
    ]


@pytest.mark.asyncio
async def test_discovery_cap_applies_after_candidate_filtering() -> None:
    filler = "".join(f'<a href="/article/{index}">Article {index}</a>' for index in range(60))
    html = f'<html><body>{filler}<a href="/terms">Terms of use</a></body></html>'

    values = await MetadataProbe().collect(_context(html))

    assert values["legal.policy_links"].value == [
        {"url": "https://www.example.org/terms", "text": "Terms of use"}
    ]
