import asyncio
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit

from web_openness.domains import canonical_hostname, registrable_domain
from web_openness.safety import AddressResolver, resolve_host_addresses, validate_public_url


class BrowserPolicyError(RuntimeError):
    """Raised before an optional browser worker exceeds its collection policy."""


@dataclass(frozen=True, slots=True)
class BrowserPolicy:
    """Hard limits for one isolated browser navigation; disabled by default."""

    enabled: bool = False
    wall_time_seconds: float = 20.0
    max_requests: int = 30
    max_third_party_requests: int = 10
    max_response_bytes: int = 2_000_000
    max_total_response_bytes: int = 10_000_000

    def __post_init__(self) -> None:
        if self.wall_time_seconds <= 0:
            raise ValueError("wall_time_seconds must be positive")
        if self.max_requests < 1:
            raise ValueError("max_requests must be at least 1")
        if not 0 <= self.max_third_party_requests <= self.max_requests:
            raise ValueError("max_third_party_requests must be between 0 and max_requests")
        if self.max_response_bytes < 1:
            raise ValueError("max_response_bytes must be at least 1")
        if self.max_total_response_bytes < self.max_response_bytes:
            raise ValueError("max_total_response_bytes must cover at least one response")


@dataclass(frozen=True, slots=True)
class AuthorizedBrowserRequest:
    url: str
    addresses: tuple[str, ...]
    third_party: bool


@dataclass(slots=True)
class BrowserRequestGate:
    """Stateful gate that a browser adapter must call before every request."""

    top_level_url: str
    policy: BrowserPolicy
    resolver: AddressResolver = resolve_host_addresses
    request_count: int = 0
    third_party_request_count: int = 0
    total_response_bytes: int = 0
    _started_at: float = field(default_factory=time.monotonic)

    async def authorize(self, url: str) -> AuthorizedBrowserRequest:
        if not self.policy.enabled:
            raise BrowserPolicyError("browser collection is disabled")
        self._require_time_remaining()
        if self.request_count >= self.policy.max_requests:
            raise BrowserPolicyError("browser request limit exhausted")

        addresses = await validate_public_url(url, resolver=self.resolver)
        third_party = not _same_site(self.top_level_url, url)
        if third_party and self.third_party_request_count >= self.policy.max_third_party_requests:
            raise BrowserPolicyError("browser third-party request limit exhausted")

        self.request_count += 1
        if third_party:
            self.third_party_request_count += 1
        return AuthorizedBrowserRequest(str(url), addresses, third_party)

    def record_response(self, response_bytes: int) -> None:
        """Record transferred bytes after the adapter enforces the per-response cap."""

        self._require_time_remaining()
        if response_bytes < 0:
            raise ValueError("response_bytes must not be negative")
        if response_bytes > self.policy.max_response_bytes:
            raise BrowserPolicyError("browser response byte limit exceeded")
        if self.total_response_bytes + response_bytes > self.policy.max_total_response_bytes:
            raise BrowserPolicyError("browser total response byte limit exceeded")
        self.total_response_bytes += response_bytes

    def _require_time_remaining(self) -> None:
        if time.monotonic() - self._started_at >= self.policy.wall_time_seconds:
            raise BrowserPolicyError("browser wall-time limit exhausted")


class BrowserWorker(Protocol):
    """Adapter boundary for a separately deployed, sandboxed browser runtime."""

    async def render(
        self,
        target_url: str,
        request_gate: BrowserRequestGate,
    ) -> Mapping[str, object]: ...


async def run_browser_worker(
    worker: BrowserWorker,
    target_url: str,
    policy: BrowserPolicy,
    *,
    resolver: AddressResolver = resolve_host_addresses,
) -> Mapping[str, object]:
    """Run an adapter under a wall-clock timeout; the adapter must use the gate."""

    if not policy.enabled:
        raise BrowserPolicyError("browser collection is disabled")
    gate = BrowserRequestGate(target_url, policy, resolver=resolver)
    try:
        async with asyncio.timeout(policy.wall_time_seconds):
            return await worker.render(target_url, gate)
    except TimeoutError as exc:
        raise BrowserPolicyError("browser wall-time limit exhausted") from exc


def _same_site(first_url: str, second_url: str) -> bool:
    first_host = _hostname(first_url)
    second_host = _hostname(second_url)
    try:
        return registrable_domain(first_host) == registrable_domain(second_host)
    except ValueError:
        return first_host == second_host


def _hostname(url: str) -> str:
    hostname = urlsplit(url).hostname
    if hostname is None:
        raise BrowserPolicyError("browser URL must include a hostname")
    try:
        return canonical_hostname(hostname)
    except ValueError as exc:
        raise BrowserPolicyError(f"invalid browser hostname: {hostname!r}") from exc
