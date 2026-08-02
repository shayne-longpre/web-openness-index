import asyncio
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import SplitResult, urlsplit, urlunsplit
from uuid import uuid4

import httpx

from web_openness import __version__
from web_openness.client import RequestBudgetExceeded, SiteClient
from web_openness.config import ScanConfig
from web_openness.domains import canonical_hostname
from web_openness.governance import CeaseList
from web_openness.models import DomainSnapshot, Observation, ProbeError
from web_openness.probes import (
    HomepageProbe,
    MetadataProbe,
    NetworkProbe,
    ResponseProbe,
    RobotsProbe,
    SitemapProbe,
    WellKnownProbe,
)
from web_openness.probes.base import Probe, ProbeContext
from web_openness.safety import validate_public_url

DEFAULT_PROBES: tuple[Probe, ...] = (
    NetworkProbe(),
    RobotsProbe(),
    SitemapProbe(),
    HomepageProbe(),
    ResponseProbe(),
    MetadataProbe(),
    WellKnownProbe(),
)


class DomainScanTimedOut(TimeoutError):
    """Raised when a domain exceeds its total collection wall-clock budget."""


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    snapshot: DomainSnapshot
    deferred_until: datetime | None = None


def normalize_target(target: str) -> tuple[str, str]:
    candidate = target.strip()
    if not candidate:
        raise ValueError("target must not be empty")
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("target scheme must be http or https")
    if parsed.hostname is None:
        raise ValueError(f"target has no valid hostname: {target!r}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("target must not include credentials")

    hostname = canonical_hostname(parsed.hostname)
    host = f"[{hostname}]" if ":" in hostname else hostname
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    origin_parts = SplitResult(parsed.scheme, host, "", "", "")
    return hostname, urlunsplit(origin_parts).rstrip("/")


class Scanner:
    def __init__(
        self,
        config: ScanConfig | None = None,
        *,
        probes: Iterable[Probe] = DEFAULT_PROBES,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config or ScanConfig()
        self.probes = tuple(probes)
        self.transport = transport
        self.cease_list = (
            CeaseList.load(self.config.cease_list_path)
            if self.config.cease_list_path is not None
            else CeaseList.empty()
        )

    def require_target_allowed(self, target: str) -> None:
        domain, _origin = normalize_target(target)
        cease_list = (
            CeaseList.load(self.config.cease_list_path)
            if self.config.cease_list_path is not None
            else self.cease_list
        )
        cease_list.require_allowed(domain)

    async def scan(self, target: str) -> DomainSnapshot:
        return (await self.scan_outcome(target)).snapshot

    async def scan_outcome(self, target: str) -> ScanOutcome:
        try:
            async with asyncio.timeout(self.config.domain_timeout_seconds):
                return await self._scan_outcome(target)
        except TimeoutError as exc:
            raise DomainScanTimedOut(
                f"domain scan exceeded {self.config.domain_timeout_seconds:g} seconds"
            ) from exc

    async def _scan_outcome(self, target: str) -> ScanOutcome:
        domain, origin = normalize_target(target)
        self.require_target_allowed(target)
        await validate_public_url(
            origin,
            resolve_dns=not isinstance(self.transport, httpx.MockTransport),
        )
        started_at = datetime.now(UTC)
        observations: dict[str, Observation] = {}

        async with SiteClient(self.config, transport=self.transport) as client:
            context = ProbeContext(
                domain=domain,
                origin=origin,
                config=self.config,
                client=client,
            )
            for probe in self.probes:
                try:
                    probe_observations = await probe.collect(context)
                    overlap = observations.keys() & probe_observations.keys()
                    if overlap:
                        duplicate = ", ".join(sorted(overlap))
                        raise ValueError(f"probe emitted duplicate observations: {duplicate}")
                    observations.update(probe_observations)
                except RequestBudgetExceeded as exc:
                    context.errors.append(ProbeError(probe=probe.name, message=str(exc)))
                    break
                except Exception as exc:  # Keep one detector from invalidating a scan.
                    context.errors.append(
                        ProbeError(probe=probe.name, message=f"{type(exc).__name__}: {exc}")
                    )

            completed_at = datetime.now(UTC)
            snapshot = DomainSnapshot(
                run_id=str(uuid4()),
                domain=domain,
                origin=origin,
                started_at=started_at,
                completed_at=completed_at,
                collector_version=__version__,
                request_count=len(client.records),
                observations=observations,
                requests=client.records,
                errors=context.errors,
            )
            return ScanOutcome(snapshot=snapshot, deferred_until=client.deferred_until)
