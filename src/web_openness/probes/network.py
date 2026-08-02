import asyncio
import ipaddress
import socket
import ssl
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlsplit

from web_openness.models import Confidence, Evidence, Observation, ObservationOutcome, ProbeError
from web_openness.probes.base import ProbeContext, observation
from web_openness.safety import URLSafetyError, require_public_address

MAX_STORED_ADDRESSES = 16
MAX_CERTIFICATE_FIELD_CHARS = 1_024


@dataclass(frozen=True, slots=True)
class DNSAddress:
    family: str
    address: str


@dataclass(frozen=True, slots=True)
class TLSInspection:
    version: str | None = None
    cipher_name: str | None = None
    cipher_protocol: str | None = None
    cipher_bits: int | None = None
    certificate_not_before: str | None = None
    certificate_not_after: str | None = None
    certificate_issuer: str | None = None
    certificate_verified: bool | None = None


class DNSResolver(Protocol):
    async def resolve(
        self,
        hostname: str,
        port: int,
        timeout_seconds: float,
    ) -> Sequence[DNSAddress]: ...


class TLSInspector(Protocol):
    async def inspect(
        self,
        hostname: str,
        port: int,
        timeout_seconds: float,
    ) -> TLSInspection: ...


class SystemDNSResolver:
    async def resolve(
        self,
        hostname: str,
        port: int,
        timeout_seconds: float,
    ) -> Sequence[DNSAddress]:
        loop = asyncio.get_running_loop()
        results = await asyncio.wait_for(
            loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM),
            timeout=timeout_seconds,
        )
        addresses: list[DNSAddress] = []
        for family, _socket_type, _protocol, _canonical_name, socket_address in results:
            if family == socket.AF_INET:
                family_name = "IPv4"
            elif family == socket.AF_INET6:
                family_name = "IPv6"
            else:
                family_name = f"other:{int(family)}"
            if not socket_address:
                continue
            addresses.append(DNSAddress(family=family_name, address=str(socket_address[0])))
        return addresses


class SystemTLSInspector:
    async def inspect(
        self,
        hostname: str,
        port: int,
        timeout_seconds: float,
    ) -> TLSInspection:
        inspection = asyncio.to_thread(
            self._inspect_sync,
            hostname,
            port,
            timeout_seconds,
        )
        return await asyncio.wait_for(inspection, timeout=timeout_seconds)

    @staticmethod
    def _inspect_sync(hostname: str, port: int, timeout_seconds: float) -> TLSInspection:
        tls_context = ssl.create_default_context()
        with (
            socket.create_connection((hostname, port), timeout=timeout_seconds) as connection,
            tls_context.wrap_socket(connection, server_hostname=hostname) as tls_socket,
        ):
            cipher = tls_socket.cipher()
            certificate = tls_socket.getpeercert() or {}
            return TLSInspection(
                version=_bounded_string(tls_socket.version()),
                cipher_name=_bounded_string(cipher[0] if cipher else None),
                cipher_protocol=_bounded_string(cipher[1] if cipher else None),
                cipher_bits=cipher[2] if cipher else None,
                certificate_not_before=_certificate_string(certificate, "notBefore"),
                certificate_not_after=_certificate_string(certificate, "notAfter"),
                certificate_issuer=_format_distinguished_name(certificate.get("issuer")),
                certificate_verified=True,
            )


class NetworkProbe:
    name = "network"

    def __init__(
        self,
        *,
        dns_resolver: DNSResolver | None = None,
        tls_inspector: TLSInspector | None = None,
    ) -> None:
        self.dns_resolver = dns_resolver or SystemDNSResolver()
        self.tls_inspector = tls_inspector or SystemTLSInspector()

    async def collect(self, context: ProbeContext) -> dict[str, Observation]:
        parsed = urlsplit(context.origin)
        hostname = parsed.hostname
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            return self._invalid_origin(context, f"invalid origin port: {exc}")
        if hostname is None:
            return self._invalid_origin(context, "origin has no hostname")

        observations = await self._collect_dns(context, hostname, port)
        if parsed.scheme == "https" and context.shared.get("network_destination_safe") is not True:
            observations.update(
                _unknown_tls(
                    "not inspected because DNS was not confirmed globally routable",
                    outcome=ObservationOutcome.SKIPPED,
                )
            )
        else:
            observations.update(await self._collect_tls(context, hostname, port, parsed.scheme))
        return observations

    async def _collect_dns(
        self,
        context: ProbeContext,
        hostname: str,
        port: int,
    ) -> dict[str, Observation]:
        evidence = [_evidence(context.origin, "system DNS lookup")]
        try:
            resolved = await self.dns_resolver.resolve(
                hostname,
                port,
                context.config.timeout_seconds,
            )
        except Exception as exc:
            context.shared["network_destination_safe"] = False
            context.errors.append(
                ProbeError(probe=self.name, message=_error_message("DNS lookup failed", exc))
            )
            return _unknown_dns("DNS lookup failed", evidence)

        unique = sorted({(address.family, address.address) for address in resolved})
        context.shared["network_destination_safe"] = bool(unique)
        try:
            for _family, address in unique:
                require_public_address(ipaddress.ip_address(address))
        except (ValueError, URLSafetyError) as exc:
            context.shared["network_destination_safe"] = False
            context.errors.append(
                ProbeError(
                    probe=self.name,
                    message=f"DNS safety check failed: {type(exc).__name__}: {exc}",
                )
            )
        stored = unique[:MAX_STORED_ADDRESSES]
        values = [{"family": family, "address": address} for family, address in stored]
        families = sorted({family for family, _address in unique})
        method = "system address resolution"
        return {
            "network.dns_resolved": observation(
                bool(unique),
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method=method,
                evidence=evidence,
            ),
            "network.dns_addresses": observation(
                values,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method=f"{method}; capped at {MAX_STORED_ADDRESSES} unique addresses",
                evidence=evidence,
            ),
            "network.dns_address_count": observation(
                len(unique),
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="count of unique resolved addresses before storage cap",
                evidence=evidence,
            ),
            "network.dns_ip_families": observation(
                families,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method=method,
                evidence=evidence,
            ),
            "network.dns_addresses_truncated": observation(
                len(unique) > MAX_STORED_ADDRESSES,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="address evidence storage bound",
                evidence=evidence,
            ),
        }

    async def _collect_tls(
        self,
        context: ProbeContext,
        hostname: str,
        port: int,
        scheme: str,
    ) -> dict[str, Observation]:
        if scheme != "https":
            return _unknown_tls(
                "not inspected because the origin is not HTTPS",
                outcome=ObservationOutcome.SKIPPED,
            )

        evidence = [_evidence(context.origin, "direct TLS handshake")]
        try:
            result = await self.tls_inspector.inspect(
                hostname,
                port,
                context.config.timeout_seconds,
            )
        except Exception as exc:
            context.errors.append(
                ProbeError(probe=self.name, message=_error_message("TLS inspection failed", exc))
            )
            return _unknown_tls("TLS inspection failed", evidence)

        cipher: dict[str, str | int | None] | None = None
        if result.cipher_name is not None:
            cipher = {
                "name": _bounded_string(result.cipher_name),
                "protocol": _bounded_string(result.cipher_protocol),
                "bits": result.cipher_bits,
            }
        return {
            "network.tls_handshake": observation(
                True,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="TLS handshake",
                evidence=evidence,
            ),
            "network.tls_version": _tls_value_observation(
                _bounded_string(result.version), "negotiated TLS protocol", evidence
            ),
            "network.tls_cipher": _tls_value_observation(cipher, "negotiated TLS cipher", evidence),
            "network.tls_certificate_not_before": _tls_value_observation(
                _bounded_string(result.certificate_not_before),
                "peer certificate validity start",
                evidence,
            ),
            "network.tls_certificate_not_after": _tls_value_observation(
                _bounded_string(result.certificate_not_after),
                "peer certificate validity end",
                evidence,
            ),
            "network.tls_certificate_issuer": _tls_value_observation(
                _bounded_string(result.certificate_issuer),
                "peer certificate issuer",
                evidence,
            ),
            "network.tls_certificate_verified": _tls_value_observation(
                result.certificate_verified,
                "certificate verification result",
                evidence,
            ),
        }

    def _invalid_origin(
        self,
        context: ProbeContext,
        message: str,
    ) -> dict[str, Observation]:
        context.errors.append(ProbeError(probe=self.name, message=message))
        observations = _unknown_dns(message)
        observations.update(_unknown_tls(message))
        return observations


def _unknown_dns(
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
        )
        for key in (
            "network.dns_resolved",
            "network.dns_addresses",
            "network.dns_address_count",
            "network.dns_ip_families",
            "network.dns_addresses_truncated",
        )
    }


def _unknown_tls(
    method: str,
    evidence: list[Evidence] | None = None,
    *,
    outcome: ObservationOutcome = ObservationOutcome.ERROR,
) -> dict[str, Observation]:
    return {
        key: observation(
            None,
            confidence=Confidence.UNKNOWN,
            score=0.0,
            method=method,
            evidence=evidence,
            outcome=outcome,
        )
        for key in (
            "network.tls_handshake",
            "network.tls_version",
            "network.tls_cipher",
            "network.tls_certificate_not_before",
            "network.tls_certificate_not_after",
            "network.tls_certificate_issuer",
            "network.tls_certificate_verified",
        )
    }


def _tls_value_observation(
    value: object,
    method: str,
    evidence: list[Evidence],
) -> Observation:
    confidence = Confidence.CONFIRMED if value is not None else Confidence.NO_EVIDENCE
    return observation(
        value,
        confidence=confidence,
        score=1.0 if value is not None else 0.0,
        method=method if value is not None else f"{method} was not exposed by the inspector",
        evidence=evidence,
    )


def _evidence(source_url: str, note: str) -> Evidence:
    return Evidence(source_url=source_url, observed_at=datetime.now(UTC), note=note)


def _certificate_string(certificate: Mapping[str, object], key: str) -> str | None:
    value = certificate.get(key)
    return _bounded_string(value if isinstance(value, str) else None)


def _format_distinguished_name(value: object) -> str | None:
    parts: list[str] = []

    def visit(item: object) -> None:
        if isinstance(item, (tuple, list)):
            if len(item) == 2 and all(isinstance(part, str) for part in item):
                parts.append(f"{item[0]}={item[1]}")
                return
            for child in item:
                visit(child)

    visit(value)
    return _bounded_string(", ".join(parts) or None)


def _bounded_string(value: str | None) -> str | None:
    if value is None:
        return None
    return value[:MAX_CERTIFICATE_FIELD_CHARS]


def _error_message(prefix: str, error: Exception) -> str:
    detail = str(error).strip()
    if detail:
        return f"{prefix}: {type(error).__name__}: {detail}"
    return f"{prefix}: {type(error).__name__}"
