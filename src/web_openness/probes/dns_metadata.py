import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

import dns.asyncresolver
import dns.exception
import dns.resolver

from web_openness.domains import registrable_domain
from web_openness.models import Confidence, Evidence, Observation, ObservationOutcome, ProbeError
from web_openness.probes.base import ProbeContext, observation

MAX_DNS_NAMES = 32
MAX_DNS_ERROR_CHARS = 256


@dataclass(frozen=True, slots=True)
class DNSMetadataInspection:
    canonical_name: str | None = None
    nameservers: tuple[str, ...] = ()
    soa_primary: str | None = None
    tollbit_hostname: str | None = None
    tollbit_canonical_name: str | None = None
    tollbit_record_types: tuple[str, ...] = ()
    errors: dict[str, str] = field(default_factory=dict)


class DNSMetadataResolver(Protocol):
    async def inspect(
        self,
        hostname: str,
        root_domain: str,
        timeout_seconds: float,
    ) -> DNSMetadataInspection: ...


@dataclass(frozen=True, slots=True)
class _DNSLookup:
    values: tuple[str, ...] = ()
    canonical_name: str | None = None
    error: str | None = None


class SystemDNSMetadataResolver:
    async def inspect(
        self,
        hostname: str,
        root_domain: str,
        timeout_seconds: float,
    ) -> DNSMetadataInspection:
        resolver = dns.asyncresolver.Resolver()
        tollbit_hostname = f"tollbit.{root_domain}"
        (
            canonical,
            nameservers,
            soa,
            tollbit_cname,
            tollbit_ns,
            tollbit_a,
        ) = await asyncio.gather(
            _query(resolver, hostname, "CNAME", timeout_seconds),
            _query(resolver, root_domain, "NS", timeout_seconds),
            _query(resolver, root_domain, "SOA", timeout_seconds),
            _query(resolver, tollbit_hostname, "CNAME", timeout_seconds),
            _query(resolver, tollbit_hostname, "NS", timeout_seconds),
            _query(resolver, tollbit_hostname, "A", timeout_seconds),
        )
        errors: dict[str, str] = {}
        _store_error(errors, "canonical_name", canonical.error)
        _store_error(errors, "nameservers", nameservers.error)
        _store_error(errors, "soa_primary", soa.error)
        tollbit_errors = tuple(
            error
            for error in (tollbit_cname.error, tollbit_ns.error, tollbit_a.error)
            if error is not None
        )
        record_types = _tollbit_record_types(
            cname=tollbit_cname,
            nameservers=tollbit_ns,
            addresses=tollbit_a,
        )
        if not record_types and tollbit_errors:
            errors["tollbit"] = "; ".join(tollbit_errors)[:MAX_DNS_ERROR_CHARS]

        return DNSMetadataInspection(
            canonical_name=_first(canonical.values),
            nameservers=nameservers.values,
            soa_primary=_first(soa.values),
            tollbit_hostname=tollbit_hostname,
            tollbit_canonical_name=(
                _first(tollbit_cname.values)
                or tollbit_cname.canonical_name
                or tollbit_a.canonical_name
            ),
            tollbit_record_types=record_types,
            errors=errors,
        )


class DNSMetadataProbe:
    """Collect bounded public DNS metadata and conservative provider hints."""

    name = "dns_metadata"

    def __init__(self, *, resolver: DNSMetadataResolver | None = None) -> None:
        self.resolver = resolver or SystemDNSMetadataResolver()

    async def collect(self, context: ProbeContext) -> dict[str, Observation]:
        try:
            root_domain = registrable_domain(context.domain)
        except ValueError as exc:
            return _unknown_dns_metadata(f"registrable domain unavailable: {exc}")

        try:
            result = await self.resolver.inspect(
                context.domain,
                root_domain,
                context.config.timeout_seconds,
            )
        except Exception as exc:
            message = f"DNS metadata lookup failed: {type(exc).__name__}: {exc}"
            context.errors.append(ProbeError(probe=self.name, message=message))
            return _unknown_dns_metadata(message, _evidence(context.origin))

        for field_name, message in sorted(result.errors.items()):
            context.errors.append(
                ProbeError(
                    probe=self.name,
                    message=f"{field_name} lookup failed: {message}",
                )
            )

        evidence = _evidence(context.origin)
        edge_providers = _provider_hints(result.canonical_name, EDGE_PROVIDER_SUFFIXES)
        dns_providers = _provider_hints(result.nameservers, DNS_PROVIDER_SUFFIXES)
        hosting_providers = _provider_hints(result.canonical_name, HOSTING_PROVIDER_SUFFIXES)
        edge_services = _edge_service_hints(result.canonical_name)
        tollbit_gateway = None
        if result.tollbit_record_types:
            tollbit_gateway = {
                "hostname": result.tollbit_hostname,
                "record_types": list(result.tollbit_record_types),
                "canonical_name": result.tollbit_canonical_name,
            }

        return {
            "network.dns_canonical_name": _direct_observation(
                result.canonical_name,
                field="canonical_name",
                result=result,
                method="public CNAME lookup for the scanned hostname",
                evidence=evidence,
            ),
            "network.dns_nameservers": _direct_observation(
                list(result.nameservers),
                field="nameservers",
                result=result,
                method=f"public NS lookup for {root_domain}; capped at {MAX_DNS_NAMES}",
                evidence=evidence,
            ),
            "network.dns_soa_primary": _direct_observation(
                result.soa_primary,
                field="soa_primary",
                result=result,
                method=f"public SOA lookup for {root_domain}",
                evidence=evidence,
            ),
            "infrastructure.edge_provider": _derived_observation(
                edge_providers,
                errored="canonical_name" in result.errors,
                method="provider-specific suffix in the public CNAME chain",
                evidence=evidence,
            ),
            "infrastructure.edge_service_hints": _derived_observation(
                edge_services,
                errored="canonical_name" in result.errors,
                method="service-specific public edge hostname suffix",
                evidence=evidence,
            ),
            "infrastructure.dns_provider": _derived_observation(
                dns_providers,
                errored="nameservers" in result.errors,
                method="provider-specific suffix in authoritative nameserver hostnames",
                evidence=evidence,
            ),
            "infrastructure.hosting_provider": _derived_observation(
                hosting_providers,
                errored="canonical_name" in result.errors,
                method="provider-specific suffix in the public CNAME chain",
                evidence=evidence,
            ),
            "agent.tollbit_gateway": _direct_observation(
                tollbit_gateway,
                field="tollbit",
                result=result,
                method=(
                    f"public A, CNAME, and NS discovery for tollbit.{root_domain}; "
                    "requires CNAME or delegated NS evidence and does not establish "
                    "active enforcement"
                ),
                evidence=evidence,
            ),
        }


EDGE_PROVIDER_SUFFIXES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("akamai", ("edgekey.net", "edgesuite.net", "akamaiedge.net", "akamaized.net")),
    ("amazon_cloudfront", ("cloudfront.net",)),
    ("cloudflare", ("cdn.cloudflare.net", "cloudflare.net")),
    ("fastly", ("fastly.net", "fastlylb.net")),
    ("imperva", ("incapdns.net",)),
    ("sucuri", ("cloudproxy.net", "sucuri.net")),
)

DNS_PROVIDER_SUFFIXES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("akamai", ("akam.net",)),
    ("amazon_route_53", ("awsdns-",)),
    ("azure_dns", ("azure-dns.com", "azure-dns.net", "azure-dns.org", "azure-dns.info")),
    ("cloudflare", ("cloudflare.com",)),
    ("google_cloud_dns", ("googledomains.com",)),
    ("netlify_dns", ("netlifydns.com",)),
    ("ns1", ("nsone.net",)),
    ("vercel_dns", ("vercel-dns.com",)),
)

HOSTING_PROVIDER_SUFFIXES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("github_pages", ("github.io",)),
    ("netlify", ("netlify.app", "netlifyglobalcdn.com")),
    ("shopify", ("myshopify.com",)),
    ("squarespace", ("squarespace.com",)),
    ("vercel", ("vercel-dns.com",)),
    ("wix", ("wixdns.net",)),
    ("wordpress_com", ("wordpress.com",)),
    ("wordpress_vip", ("go-vip.net", "go-vip.co")),
)


async def _query(
    resolver: dns.asyncresolver.Resolver,
    hostname: str,
    record_type: str,
    timeout_seconds: float,
) -> _DNSLookup:
    try:
        answer = await resolver.resolve(
            hostname,
            record_type,
            lifetime=timeout_seconds,
            raise_on_no_answer=False,
            search=False,
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return _DNSLookup()
    except (dns.exception.DNSException, OSError) as exc:
        return _DNSLookup(error=_error_message(exc))

    values = tuple(
        sorted(
            {
                value
                for record in answer
                if (value := _record_value(str(record), record_type)) is not None
            }
        )[:MAX_DNS_NAMES]
    )
    canonical_name = _dns_name(str(answer.canonical_name))
    if canonical_name == _dns_name(hostname):
        canonical_name = None
    return _DNSLookup(values=values, canonical_name=canonical_name)


def _record_value(value: str, record_type: str) -> str | None:
    candidate = value.split()[0] if record_type == "SOA" else value
    if record_type in {"CNAME", "NS", "SOA"}:
        return _dns_name(candidate)
    return candidate[:253] or None


def _dns_name(value: str) -> str | None:
    candidate = value.strip().rstrip(".").lower()
    return candidate[:253] or None


def _provider_hints(
    names: str | tuple[str, ...] | None,
    providers: tuple[tuple[str, tuple[str, ...]], ...],
) -> list[str]:
    candidates = (names,) if isinstance(names, str) else names or ()
    return sorted(
        provider
        for provider, suffixes in providers
        if any(_matches_provider(candidate, suffixes) for candidate in candidates)
    )


def _matches_provider(name: str, suffixes: tuple[str, ...]) -> bool:
    normalized = name.lower().rstrip(".")
    return any(
        suffix in normalized
        if suffix.endswith("-")
        else (normalized == suffix or normalized.endswith(f".{suffix}"))
        for suffix in suffixes
    )


def _edge_service_hints(canonical_name: str | None) -> list[str]:
    if canonical_name is None:
        return []
    if _matches_provider(canonical_name, ("edgekey.net", "akamaiedge.net")):
        return ["akamai_enhanced_tls_edge_hostname"]
    if _matches_provider(canonical_name, ("edgesuite.net",)):
        return ["akamai_standard_tls_edge_hostname"]
    return []


def _tollbit_record_types(
    *,
    cname: _DNSLookup,
    nameservers: _DNSLookup,
    addresses: _DNSLookup,
) -> tuple[str, ...]:
    strong_record = bool(cname.values or nameservers.values)
    return tuple(
        record_type
        for record_type, present in (
            ("A", strong_record and bool(addresses.values)),
            ("CNAME", bool(cname.values)),
            ("NS", bool(nameservers.values)),
        )
        if present
    )


def _direct_observation(
    value: object,
    *,
    field: str,
    result: DNSMetadataInspection,
    method: str,
    evidence: list[Evidence],
) -> Observation:
    if field in result.errors:
        return observation(
            None,
            confidence=Confidence.UNKNOWN,
            score=0.0,
            method=f"{method}; lookup failed",
            evidence=evidence,
            outcome=ObservationOutcome.ERROR,
        )
    present = value is not None and value != []
    return observation(
        value if present else None,
        confidence=Confidence.CONFIRMED if present else Confidence.NO_EVIDENCE,
        score=1.0,
        method=method,
        evidence=evidence,
    )


def _derived_observation(
    value: list[str],
    *,
    errored: bool,
    method: str,
    evidence: list[Evidence],
) -> Observation:
    if errored:
        return observation(
            None,
            confidence=Confidence.UNKNOWN,
            score=0.0,
            method=f"{method}; source lookup failed",
            evidence=evidence,
            outcome=ObservationOutcome.ERROR,
        )
    return observation(
        value if value else None,
        confidence=Confidence.LIKELY if value else Confidence.NO_EVIDENCE,
        score=0.8 if value else 1.0,
        method=f"{method}; attribution is probabilistic",
        evidence=evidence,
    )


def _unknown_dns_metadata(
    method: str,
    evidence: list[Evidence] | None = None,
) -> dict[str, Observation]:
    return {
        key: observation(
            None,
            confidence=Confidence.UNKNOWN,
            score=0.0,
            method=method,
            evidence=evidence,
            outcome=ObservationOutcome.ERROR,
        )
        for key in (
            "network.dns_canonical_name",
            "network.dns_nameservers",
            "network.dns_soa_primary",
            "infrastructure.edge_provider",
            "infrastructure.edge_service_hints",
            "infrastructure.dns_provider",
            "infrastructure.hosting_provider",
            "agent.tollbit_gateway",
        )
    }


def _evidence(origin: str) -> list[Evidence]:
    return [
        Evidence(
            source_url=origin,
            observed_at=datetime.now(UTC),
            note="bounded public DNS metadata lookup",
        )
    ]


def _first(values: tuple[str, ...]) -> str | None:
    return values[0] if values else None


def _store_error(errors: dict[str, str], key: str, message: str | None) -> None:
    if message is not None:
        errors[key] = message


def _error_message(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"[:MAX_DNS_ERROR_CHARS]
