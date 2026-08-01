import asyncio
import hashlib
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime

import httpx

from web_openness.config import ScanConfig
from web_openness.models import RequestRecord
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

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


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
    ) -> None:
        self.config = config
        self.transport = transport
        self.records: list[RequestRecord] = []
        self._client: httpx.AsyncClient | None = None
        self._last_request_started: float | None = None

    async def __aenter__(self) -> "SiteClient":
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
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get(self, url: str) -> FetchResult:
        if self._client is None:
            raise RuntimeError("SiteClient must be used as an async context manager")
        current_url = url
        redirects_followed = 0

        while True:
            if len(self.records) >= self.config.request_budget:
                raise RequestBudgetExceeded(
                    f"request budget of {self.config.request_budget} exhausted"
                )

            safety_error = await self._safety_error(current_url)
            if safety_error is not None:
                return self._rejected_result(url, current_url, safety_error)

            result, next_url = await self._fetch_once(url, current_url)
            if result.error is not None or next_url is None:
                return result
            if redirects_followed >= self.config.max_redirects:
                return replace(
                    result,
                    error=f"TooManyRedirects: exceeded {self.config.max_redirects} redirects",
                )

            redirects_followed += 1
            current_url = next_url

    async def _fetch_once(
        self,
        original_url: str,
        attempt_url: str,
    ) -> tuple[FetchResult, str | None]:
        if self._client is None:
            raise RuntimeError("SiteClient must be used as an async context manager")

        await self._apply_delay()
        started_at = datetime.now(UTC)
        started_clock = time.monotonic()
        self._last_request_started = started_clock
        status_code: int | None = None
        final_url: str | None = None
        http_version: str | None = None
        response_headers: dict[str, str] = {}
        body = bytearray()
        truncated = False
        error: str | None = None
        next_url: str | None = None

        try:
            async with self._client.stream("GET", attempt_url) as response:
                status_code = response.status_code
                final_url = str(response.url)
                http_version = response.http_version
                if response.next_request is not None:
                    next_url = str(response.next_request.url)
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
        return (
            FetchResult(
                requested_url=original_url,
                final_url=final_url,
                status_code=status_code,
                http_version=http_version,
                headers=response_headers,
                body=bytes(body),
                truncated=truncated,
                error=error,
                evidence=record,
            ),
            next_url,
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
    def _rejected_result(original_url: str, rejected_url: str, error: str) -> FetchResult:
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
        )

    async def _apply_delay(self) -> None:
        if self._last_request_started is None:
            return
        elapsed = time.monotonic() - self._last_request_started
        remaining = self.config.request_delay_seconds - elapsed
        if remaining > 0:
            await asyncio.sleep(remaining)
