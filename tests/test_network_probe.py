from collections.abc import Sequence

import pytest

from web_openness.client import SiteClient
from web_openness.config import ScanConfig
from web_openness.models import Confidence, ObservationOutcome
from web_openness.probes.base import ProbeContext
from web_openness.probes.network import (
    MAX_CERTIFICATE_FIELD_CHARS,
    MAX_STORED_ADDRESSES,
    DNSAddress,
    NetworkProbe,
    TLSInspection,
)


class FakeDNSResolver:
    def __init__(
        self,
        addresses: Sequence[DNSAddress] = (),
        error: Exception | None = None,
    ) -> None:
        self.addresses = addresses
        self.error = error
        self.calls: list[tuple[str, int, float]] = []

    async def resolve(
        self,
        hostname: str,
        port: int,
        timeout_seconds: float,
    ) -> Sequence[DNSAddress]:
        self.calls.append((hostname, port, timeout_seconds))
        if self.error is not None:
            raise self.error
        return self.addresses


class FakeTLSInspector:
    def __init__(
        self,
        result: TLSInspection | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result or TLSInspection()
        self.error = error
        self.calls: list[tuple[str, int, float]] = []

    async def inspect(
        self,
        hostname: str,
        port: int,
        timeout_seconds: float,
    ) -> TLSInspection:
        self.calls.append((hostname, port, timeout_seconds))
        if self.error is not None:
            raise self.error
        return self.result


def make_context(origin: str = "https://example.org") -> ProbeContext:
    config = ScanConfig(timeout_seconds=3.5)
    return ProbeContext(
        domain="example.org",
        origin=origin,
        config=config,
        client=SiteClient(config),
    )


@pytest.mark.asyncio
async def test_collects_bounded_dns_and_tls_evidence_without_network() -> None:
    addresses = [
        DNSAddress("IPv4", "93.184.216.34"),
        DNSAddress("IPv6", "2606:2800:220:1:248:1893:25c8:1946"),
        DNSAddress("IPv4", "93.184.216.34"),
    ]
    addresses.extend(
        DNSAddress("IPv4", f"8.8.4.{number}") for number in range(20, 20 + MAX_STORED_ADDRESSES)
    )
    dns = FakeDNSResolver(addresses)
    tls = FakeTLSInspector(
        TLSInspection(
            version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_protocol="TLSv1.3",
            cipher_bits=256,
            certificate_not_before="Jul  1 00:00:00 2026 GMT",
            certificate_not_after="Sep 29 23:59:59 2026 GMT",
            certificate_issuer="countryName=US, organizationName=Example CA",
            certificate_verified=True,
        )
    )

    context = make_context()
    observations = await NetworkProbe(dns_resolver=dns, tls_inspector=tls).collect(context)

    assert dns.calls == [("example.org", 443, 3.5)]
    assert tls.calls == [("example.org", 443, 3.5)]
    assert context.client.records == []
    assert context.errors == []
    assert observations["network.dns_resolved"].value is True
    assert observations["network.dns_address_count"].value == MAX_STORED_ADDRESSES + 2
    assert len(observations["network.dns_addresses"].value) == MAX_STORED_ADDRESSES
    assert observations["network.dns_ip_families"].value == ["IPv4", "IPv6"]
    assert observations["network.dns_addresses_truncated"].value is True
    assert observations["network.tls_handshake"].value is True
    assert observations["network.tls_version"].value == "TLSv1.3"
    assert observations["network.tls_cipher"].value == {
        "name": "TLS_AES_256_GCM_SHA384",
        "protocol": "TLSv1.3",
        "bits": 256,
    }
    assert observations["network.tls_certificate_verified"].value is True
    assert all(item.evidence for item in observations.values())


@pytest.mark.asyncio
async def test_failures_are_unknown_and_record_both_errors() -> None:
    context = make_context()
    observations = await NetworkProbe(
        dns_resolver=FakeDNSResolver(error=OSError("DNS unavailable")),
        tls_inspector=FakeTLSInspector(error=TimeoutError()),
    ).collect(context)

    assert len(context.errors) == 1
    assert context.errors[0].probe == "network"
    assert context.errors[0].message == "DNS lookup failed: OSError: DNS unavailable"
    assert observations["network.dns_resolved"].value is None
    assert observations["network.dns_resolved"].confidence == Confidence.UNKNOWN
    assert observations["network.tls_handshake"].value is None
    assert observations["network.tls_handshake"].confidence == Confidence.UNKNOWN
    assert observations["network.tls_handshake"].outcome == ObservationOutcome.SKIPPED
    assert observations["network.tls_handshake"].method == (
        "not inspected because DNS was not confirmed globally routable"
    )


@pytest.mark.asyncio
async def test_http_origin_skips_tls_without_reporting_failure() -> None:
    dns = FakeDNSResolver([DNSAddress("IPv4", "93.184.216.34")])
    tls = FakeTLSInspector(error=AssertionError("TLS inspector must not be called"))
    context = make_context("http://example.org:8080")

    observations = await NetworkProbe(dns_resolver=dns, tls_inspector=tls).collect(context)

    assert dns.calls == [("example.org", 8080, 3.5)]
    assert tls.calls == []
    assert context.errors == []
    assert observations["network.tls_handshake"].value is None
    assert observations["network.tls_handshake"].confidence == Confidence.UNKNOWN
    assert observations["network.tls_handshake"].outcome == ObservationOutcome.SKIPPED
    assert observations["network.tls_handshake"].method == (
        "not inspected because the origin is not HTTPS"
    )


@pytest.mark.asyncio
async def test_missing_tls_fields_remain_unknown_and_strings_are_bounded() -> None:
    tls = FakeTLSInspector(
        TLSInspection(
            version="TLSv1.3",
            certificate_issuer="x" * (MAX_CERTIFICATE_FIELD_CHARS + 50),
            certificate_verified=True,
        )
    )
    context = make_context()

    observations = await NetworkProbe(
        dns_resolver=FakeDNSResolver([DNSAddress("IPv4", "93.184.216.34")]),
        tls_inspector=tls,
    ).collect(context)

    assert observations["network.dns_resolved"].value is True
    assert observations["network.dns_resolved"].confidence == Confidence.CONFIRMED
    assert observations["network.tls_cipher"].value is None
    assert observations["network.tls_cipher"].confidence == Confidence.NO_EVIDENCE
    assert observations["network.tls_cipher"].outcome == ObservationOutcome.NO_EVIDENCE
    assert len(observations["network.tls_certificate_issuer"].value) == (
        MAX_CERTIFICATE_FIELD_CHARS
    )


@pytest.mark.asyncio
async def test_private_dns_answer_skips_tls_connection() -> None:
    context = make_context()
    tls = FakeTLSInspector(error=AssertionError("TLS inspector must not be called"))

    observations = await NetworkProbe(
        dns_resolver=FakeDNSResolver([DNSAddress("IPv4", "127.0.0.1")]),
        tls_inspector=tls,
    ).collect(context)

    assert tls.calls == []
    assert context.shared["network_destination_safe"] is False
    assert context.errors[0].message.startswith("DNS safety check failed")
    assert observations["network.tls_handshake"].value is None
