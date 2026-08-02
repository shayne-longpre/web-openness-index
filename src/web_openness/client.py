import asyncio
import hashlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime

import httpx

from web_openness.config import ScanConfig
from web_openness.models import RequestRecord
from web_openness.politeness import SQLitePolitenessStore, parse_retry_after, politeness_key
from web_openness.safety import URLSafetyError, validate_public_url

STORED_HEADERS = {
    "age",
    "cache-control",
    "cf-ray",
    "cf-cache-status",
    "content-language",
    "content-length",
    "content-security-policy",
    "content-type",
    "date",
    "link",
    "permissions-policy",
    "referrer-policy",
    "retry-after",
    "server",
    "server-timing",
    "strict-transport-security",
    "via",
    "www-authenticate",
    "x-akamai-transformed",
    "x-amz-cf-id",
    "x-cache",
    "x-content-type-options",
    "x-frame-options",
    "x-served-by",
}
MAX_STORED_HEADER_CHARS = 4_096


class RequestBudgetExceeded(RuntimeError):
    """Raised before a request would exceed the configured domain budget."""


@dataclass(frozen=True, slots=True)
class FetchResult:
    requested_url: str
    final_url: str | None
    status_code: int | None
    http_version: str | None
    headers: dict[str, str]
    body: bytes
    truncated: bool
    error: str | None
    evidence: RequestRecord
    attempts: tuple[RequestRecord, ...] = ()
    deferred_until: datetime | None = None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


@dataclass(frozen=True, slots=True)
class _AttemptOutcome:
    result: FetchResult
    next_url: str | None
    transient: bool
    retry_after_seconds: float | None


@dataclass(frozen=True, slots=True)
class _PacingRejection:
    error: str
    deferred_until: datetime


class SiteClient:
    """An async HTTP client that applies scan policy to every request.

    Public destinations are DNS-checked before real requests and every redirect.
    HTTPX does not expose connection-level DNS pinning, so deployments should also
    restrict outbound traffic at the network boundary. Mock transports skip DNS
    lookup to keep tests offline, but still receive URL and literal-IP checks.
    """

    def __init__(
        self,
        config: ScanConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        politeness_store: SQLitePolitenessStore | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.config = config
        self.transport = transport
        self.records: list[RequestRecord] = []
        self._client: httpx.AsyncClient | None = None
        self._politeness_store = politeness_store
        self._owns_politeness_store = False
        self._sleep = sleep
        self.deferred_until: datetime | None = None

    async def __aenter__(self) -> "SiteClient":
        if self._politeness_store is None:
            state_path = self.config.politeness_db_path or ":memory:"
            if isinstance(self.transport, httpx.MockTransport):
                state_path = ":memory:"
            self._politeness_store = SQLitePolitenessStore(state_path)
            self._owns_politeness_store = True
        self._client = httpx.AsyncClient(
            headers={
                "User-Agent": self.config.user_agent,
                "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5",
            },
            http2=True,
            follow_redirects=False,
            max_redirects=self.config.max_redirects,
            timeout=self.config.timeout_seconds,
            transport=self.transport,
            trust_env=False,
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> None:
        try:
            if self._client is not None:
                await self._client.aclose()
                self._client = None
        finally:
            if self._owns_politeness_store and self._politeness_store is not None:
                await self._politeness_store.close()
                self._politeness_store = None
                self._owns_politeness_store = False

    async def get(self, url: str) -> FetchResult:
        if self._client is None:
            raise RuntimeError("SiteClient must be used as an async context manager")
        current_url = url
        redirects_followed = 0
        transient_retries = 0
        attempts: list[RequestRecord] = []

        while True:
            if len(self.records) >= self.config.request_budget:
                raise RequestBudgetExceeded(
                    f"request budget of {self.config.request_budget} exhausted"
                )

            safety_error = await self._safety_error(current_url)
            if safety_error is not None:
                result = self._rejected_result(url, current_url, safety_error)
                return replace(result, attempts=tuple(attempts))

            domain_key = politeness_key(current_url)
            pacing_rejection = await self._apply_persistent_pacing(domain_key)
            if pacing_rejection is not None:
                self.deferred_until = _latest_datetime(
                    self.deferred_until, pacing_rejection.deferred_until
                )
                result = self._rejected_result(
                    url,
                    current_url,
                    pacing_rejection.error,
                    deferred_until=pacing_rejection.deferred_until,
                )
                return replace(result, attempts=tuple(attempts))

            outcome = await self._fetch_once(url, current_url)
            attempts.append(outcome.result.evidence)
            if outcome.transient:
                retry_delay = outcome.retry_after_seconds
                if retry_delay is None:
                    retry_delay = self.config.request_delay_seconds
                transient_state = await self._require_politeness_store().record_transient(
                    domain_key,
                    retry_after_seconds=retry_delay,
                    circuit_threshold=self.config.circuit_failure_threshold,
                    circuit_cooldown_seconds=self.config.circuit_cooldown_seconds,
                )
                if (
                    transient_state.circuit_until is not None
                    or transient_retries >= self.config.transient_retry_limit
                    or len(self.records) >= self.config.request_budget
                    or retry_delay > self.config.max_politeness_wait_seconds
                ):
                    return replace(outcome.result, attempts=tuple(attempts))
                transient_retries += 1
                continue

            if outcome.result.error is None:
                await self._require_politeness_store().record_success(domain_key)
            if outcome.result.error is not None or outcome.next_url is None:
                return replace(outcome.result, attempts=tuple(attempts))
            if redirects_followed >= self.config.max_redirects:
                return replace(
                    outcome.result,
                    error=f"TooManyRedirects: exceeded {self.config.max_redirects} redirects",
                    attempts=tuple(attempts),
                )

            redirects_followed += 1
            current_url = outcome.next_url

    async def _fetch_once(
        self,
        original_url: str,
        attempt_url: str,
    ) -> _AttemptOutcome:
        if self._client is None:
            raise RuntimeError("SiteClient must be used as an async context manager")

        started_at = datetime.now(UTC)
        started_clock = time.monotonic()
        status_code: int | None = None
        final_url: str | None = None
        http_version: str | None = None
        response_headers: dict[str, str] = {}
        body = bytearray()
        truncated = False
        error: str | None = None
        next_url: str | None = None
        transient = False
        retry_after_seconds: float | None = None

        try:
            async with self._client.stream("GET", attempt_url) as response:
                status_code = response.status_code
                final_url = str(response.url)
                http_version = response.http_version
                if response.next_request is not None:
                    next_url = str(response.next_request.url)
                if status_code in {429, 503}:
                    transient = True
                    retry_after_seconds = parse_retry_after(response.headers.get("retry-after"))
                response_headers = {
                    key.lower(): value[:MAX_STORED_HEADER_CHARS]
                    for key, value in response.headers.items()
                    if key.lower() in STORED_HEADERS
                }
                async for chunk in response.aiter_bytes():
                    remaining = self.config.max_response_bytes - len(body)
                    if remaining <= 0:
                        truncated = True
                        break
                    body.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        truncated = True
                        break
        except httpx.TransportError as exc:
            transient = True
            error = f"{type(exc).__name__}: {exc}"
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            error = f"{type(exc).__name__}: {exc}"

        elapsed_ms = (time.monotonic() - started_clock) * 1000
        content_sha256 = hashlib.sha256(body).hexdigest() if body else None
        record = RequestRecord(
            requested_url=attempt_url,
            final_url=final_url,
            started_at=started_at,
            elapsed_ms=elapsed_ms,
            status_code=status_code,
            response_bytes=len(body),
            response_truncated=truncated,
            content_sha256=content_sha256,
            error=error,
        )
        self.records.append(record)
        return _AttemptOutcome(
            result=FetchResult(
                requested_url=original_url,
                final_url=final_url,
                status_code=status_code,
                http_version=http_version,
                headers=response_headers,
                body=bytes(body),
                truncated=truncated,
                error=error,
                evidence=record,
                attempts=(record,),
            ),
            next_url=next_url,
            transient=transient,
            retry_after_seconds=retry_after_seconds,
        )

    async def _apply_persistent_pacing(self, domain: str) -> _PacingRejection | None:
        reservation = await self._require_politeness_store().reserve(
            domain,
            interval_seconds=self.config.request_delay_seconds,
            max_wait_seconds=self.config.max_politeness_wait_seconds,
        )
        if reservation.circuit_until is not None:
            until = datetime.fromtimestamp(reservation.circuit_until, UTC)
            return _PacingRejection(
                error=f"DomainCircuitOpen: requests ceased until {until.isoformat()}",
                deferred_until=until,
            )
        if reservation.deferred_until is not None:
            until = datetime.fromtimestamp(reservation.deferred_until, UTC)
            return _PacingRejection(
                error=f"DomainDeferred: retry after {until.isoformat()}",
                deferred_until=until,
            )
        if reservation.wait_seconds > 0:
            await self._sleep(reservation.wait_seconds)
        return None

    def _require_politeness_store(self) -> SQLitePolitenessStore:
        if self._politeness_store is None:
            raise RuntimeError("SiteClient must be used as an async context manager")
        return self._politeness_store

    async def set_domain_delay(self, url: str, interval_seconds: float) -> None:
        """Persist the robots-selected interval for this registrable domain."""

        await self._require_politeness_store().set_interval(
            politeness_key(url),
            interval_seconds,
        )

    async def _safety_error(self, url: str) -> str | None:
        try:
            async with asyncio.timeout(self.config.timeout_seconds):
                await validate_public_url(
                    url,
                    resolve_dns=not isinstance(self.transport, httpx.MockTransport),
                )
        except URLSafetyError as exc:
            return f"URLSafetyError: {exc}"
        except TimeoutError as exc:
            return f"URLSafetyError: DNS safety check timed out ({type(exc).__name__})"
        return None

    @staticmethod
    def _rejected_result(
        original_url: str,
        rejected_url: str,
        error: str,
        *,
        deferred_until: datetime | None = None,
    ) -> FetchResult:
        """Represent a rejected destination without counting it as an HTTP attempt."""

        record = RequestRecord(
            requested_url=rejected_url,
            started_at=datetime.now(UTC),
            elapsed_ms=0,
            response_bytes=0,
            error=error,
        )
        return FetchResult(
            requested_url=original_url,
            final_url=None,
            status_code=None,
            http_version=None,
            headers={},
            body=b"",
            truncated=False,
            error=error,
            evidence=record,
            deferred_until=deferred_until,
        )


def _latest_datetime(first: datetime | None, second: datetime) -> datetime:
    return second if first is None else max(first, second)
