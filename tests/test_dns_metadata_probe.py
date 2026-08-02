import pytest

from web_openness.client import SiteClient
from web_openness.config import ScanConfig
from web_openness.models import Confidence, ObservationOutcome
from web_openness.probes.base import ProbeContext
from web_openness.probes.dns_metadata import (
    DNS_PROVIDER_SUFFIXES,
    HOSTING_PROVIDER_SUFFIXES,
    DNSMetadataInspection,
    DNSMetadataProbe,
    _DNSLookup,
    _provider_hints,
    _tollbit_record_types,
)


class FakeDNSMetadataResolver:
    def __init__(
        self,
        result: DNSMetadataInspection | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result or DNSMetadataInspection()
        self.error = error
        self.calls: list[tuple[str, str, float]] = []

    async def inspect(
        self,
        hostname: str,
        root_domain: str,
        timeout_seconds: float,
    ) -> DNSMetadataInspection:
        self.calls.append((hostname, root_domain, timeout_seconds))
        if self.error is not None:
            raise self.error
        return self.result


def _context(domain: str = "news.example.org") -> ProbeContext:
    config = ScanConfig(timeout_seconds=3.5)
    return ProbeContext(
        domain=domain,
        origin=f"https://{domain}",
        config=config,
        client=SiteClient(config),
    )


@pytest.mark.asyncio
async def test_collects_dns_metadata_and_separates_provider_roles() -> None:
    resolver = FakeDNSMetadataResolver(
        DNSMetadataInspection(
            canonical_name="site.example.edgekey.net",
            nameservers=("ns-100.awsdns-01.com", "ns-200.awsdns-02.net"),
            soa_primary="ns-100.awsdns-01.com",
            tollbit_hostname="tollbit.example.org",
            tollbit_canonical_name="publisher.tollbit.com",
            tollbit_record_types=("A", "CNAME"),
        )
    )
    context = _context()

    values = await DNSMetadataProbe(resolver=resolver).collect(context)

    assert resolver.calls == [("news.example.org", "example.org", 3.5)]
    assert context.client.records == []
    assert context.errors == []
    assert values["network.dns_canonical_name"].value == "site.example.edgekey.net"
    assert values["network.dns_nameservers"].value == [
        "ns-100.awsdns-01.com",
        "ns-200.awsdns-02.net",
    ]
    assert values["network.dns_soa_primary"].value == "ns-100.awsdns-01.com"
    assert values["infrastructure.edge_provider"].value == ["akamai"]
    assert values["infrastructure.edge_service_hints"].value == [
        "akamai_enhanced_tls_edge_hostname"
    ]
    assert values["infrastructure.dns_provider"].value == ["amazon_route_53"]
    assert values["infrastructure.hosting_provider"].value is None
    assert values["agent.tollbit_gateway"].value == {
        "hostname": "tollbit.example.org",
        "record_types": ["A", "CNAME"],
        "canonical_name": "publisher.tollbit.com",
    }


@pytest.mark.asyncio
async def test_absent_dns_hints_are_no_evidence() -> None:
    context = _context("example.org")
    values = await DNSMetadataProbe(
        resolver=FakeDNSMetadataResolver(
            DNSMetadataInspection(tollbit_hostname="tollbit.example.org")
        )
    ).collect(context)

    assert context.errors == []
    assert all(value.value is None for value in values.values())
    assert all(value.confidence == Confidence.NO_EVIDENCE for value in values.values())
    assert all(value.outcome == ObservationOutcome.NO_EVIDENCE for value in values.values())


@pytest.mark.asyncio
async def test_partial_dns_failure_does_not_discard_other_results() -> None:
    context = _context()
    values = await DNSMetadataProbe(
        resolver=FakeDNSMetadataResolver(
            DNSMetadataInspection(
                nameservers=("ada.ns.cloudflare.com",),
                soa_primary="ada.ns.cloudflare.com",
                tollbit_hostname="tollbit.example.org",
                errors={"canonical_name": "LifetimeTimeout: timed out"},
            )
        )
    ).collect(context)

    assert len(context.errors) == 1
    assert context.errors[0].probe == "dns_metadata"
    assert values["network.dns_canonical_name"].outcome == ObservationOutcome.ERROR
    assert values["infrastructure.edge_provider"].outcome == ObservationOutcome.ERROR
    assert values["infrastructure.hosting_provider"].outcome == ObservationOutcome.ERROR
    assert values["infrastructure.dns_provider"].value == ["cloudflare"]
    assert values["network.dns_soa_primary"].value == "ada.ns.cloudflare.com"


@pytest.mark.asyncio
async def test_total_dns_metadata_failure_is_reported_without_http_requests() -> None:
    context = _context()
    values = await DNSMetadataProbe(
        resolver=FakeDNSMetadataResolver(error=OSError("resolver unavailable"))
    ).collect(context)

    assert context.client.records == []
    assert len(context.errors) == 1
    assert all(value.value is None for value in values.values())
    assert all(value.confidence == Confidence.UNKNOWN for value in values.values())
    assert all(value.outcome == ObservationOutcome.ERROR for value in values.values())


def test_tollbit_a_only_record_is_not_reported_as_a_gateway() -> None:
    assert (
        _tollbit_record_types(
            cname=_DNSLookup(),
            nameservers=_DNSLookup(),
            addresses=_DNSLookup(values=("192.0.2.1",)),
        )
        == ()
    )
    assert _tollbit_record_types(
        cname=_DNSLookup(),
        nameservers=_DNSLookup(values=("ns1.tollbit.com",)),
        addresses=_DNSLookup(values=("192.0.2.1",)),
    ) == ("A", "NS")


def test_provider_suffixes_keep_dns_and_hosting_roles_separate() -> None:
    assert _provider_hints(
        ("ns01.netlifydns.com", "ns1.vercel-dns.com"),
        DNS_PROVIDER_SUFFIXES,
    ) == ["netlify_dns", "vercel_dns"]
    assert _provider_hints("site.go-vip.net", HOSTING_PROVIDER_SUFFIXES) == ["wordpress_vip"]
