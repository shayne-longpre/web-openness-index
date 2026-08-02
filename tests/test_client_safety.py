import httpx
import pytest

from web_openness.client import (
    MAX_COOKIE_NAMES,
    MAX_STORED_HEADER_CHARS,
    RequestBudgetExceeded,
    SiteClient,
)
from web_openness.config import ScanConfig
from web_openness.safety import URLSafetyError, validate_public_url


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.org/file",
        "https://user:secret@example.org/",
        "https://localhost/",
        "https://service.localhost/",
        "https://intranet/",
        "http://example.org:8080/",
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://169.254.1.1/",
        "http://224.0.0.1/",
        "http://240.0.0.1/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://[fd00::1]/",
        "http://[fe80::1]/",
        "http://[ff02::1]/",
    ],
)
@pytest.mark.asyncio
async def test_unsafe_urls_never_reach_transport(url: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unsafe request reached transport: {request.url}")

    async with SiteClient(
        ScanConfig(request_delay_seconds=0),
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await client.get(url)

    assert result.status_code is None
    assert result.error is not None
    assert "URLSafetyError" in result.error
    assert client.records == []


@pytest.mark.asyncio
async def test_dns_answer_set_must_be_entirely_public() -> None:
    calls: list[tuple[str, int]] = []

    async def resolver(hostname: str, port: int) -> tuple[str, ...]:
        calls.append((hostname, port))
        return ("93.184.216.34", "10.0.0.4")

    with pytest.raises(URLSafetyError, match="not globally routable"):
        await validate_public_url("https://example.org/path", resolver=resolver)

    assert calls == [("example.org", 443)]


@pytest.mark.asyncio
async def test_redirect_target_is_validated_before_request() -> None:
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(
            302,
            headers={"location": "http://127.0.0.1/admin"},
            request=request,
        )

    async with SiteClient(
        ScanConfig(request_delay_seconds=0),
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await client.get("https://example.org/start")

    assert requests == ["https://example.org/start"]
    assert result.error is not None
    assert "127.0.0.1" in result.error
    assert len(client.records) == 1
    assert client.records[0].status_code == 302


@pytest.mark.asyncio
async def test_public_redirect_preserves_bounded_evidence() -> None:
    long_header = "a" * (MAX_STORED_HEADER_CHARS + 100)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(
                302,
                headers=[
                    ("location", "/final"),
                    ("set-cookie", "__cf_bm=redirect-secret; Secure; HttpOnly"),
                ],
                request=request,
            )
        return httpx.Response(
            200,
            headers=[
                ("content-language", "en"),
                ("server-timing", long_header),
                ("x-ignored", "not stored"),
                ("cf-mitigated", "challenge"),
                ("x-iinfo", "example"),
                ("set-cookie", "BIGipServerPool=final-secret; Secure"),
                ("set-cookie", "ordinary_session=also-secret; Secure"),
            ],
            text="ok",
            extensions={"http_version": b"HTTP/2"},
            request=request,
        )

    async with SiteClient(
        ScanConfig(request_delay_seconds=0),
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await client.get("https://example.org/start")

    assert result.error is None
    assert result.final_url == "https://example.org/final"
    assert result.http_version == "HTTP/2"
    assert result.headers["content-language"] == "en"
    assert len(result.headers["server-timing"]) == MAX_STORED_HEADER_CHARS
    assert result.headers["cf-mitigated"] == "challenge"
    assert result.headers["x-iinfo"] == "example"
    assert "x-ignored" not in result.headers
    assert "set-cookie" not in result.headers
    assert result.cookie_names == ("__cf_bm", "BIGipServerPool", "ordinary_session")
    assert "redirect-secret" not in repr(result)
    assert "final-secret" not in repr(result)
    assert [record.requested_url for record in client.records] == [
        "https://example.org/start",
        "https://example.org/final",
    ]
    assert [record.status_code for record in client.records] == [302, 200]
    assert result.evidence is client.records[-1]


@pytest.mark.asyncio
async def test_cookie_name_limit_applies_across_redirects() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            headers = [("location", "/final")]
            headers.extend(("set-cookie", f"c{index:03}=secret") for index in range(40))
            return httpx.Response(302, headers=headers, request=request)
        headers = [("set-cookie", f"c{index:03}=secret") for index in range(40, 80)]
        return httpx.Response(200, headers=headers, request=request)

    async with SiteClient(
        ScanConfig(request_delay_seconds=0),
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await client.get("https://example.org/start")

    assert len(result.cookie_names) == MAX_COOKIE_NAMES
    assert result.cookie_names == tuple(f"c{index:03}" for index in range(MAX_COOKIE_NAMES))


@pytest.mark.asyncio
async def test_redirects_consume_request_budget_per_http_attempt() -> None:
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        step = int(request.url.path.removeprefix("/step/"))
        return httpx.Response(
            302,
            headers={"location": f"/step/{step + 1}"},
            request=request,
        )

    async with SiteClient(
        ScanConfig(request_budget=2, request_delay_seconds=0, max_redirects=5),
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(RequestBudgetExceeded, match="request budget of 2 exhausted"):
            await client.get("https://example.org/step/0")

    assert requests == ["/step/0", "/step/1"]
    assert len(client.records) == 2
    assert [record.status_code for record in client.records] == [302, 302]


@pytest.mark.asyncio
async def test_max_redirects_records_each_attempt_but_stops_before_next() -> None:
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        return httpx.Response(302, headers={"location": "/again"}, request=request)

    async with SiteClient(
        ScanConfig(request_budget=5, request_delay_seconds=0, max_redirects=1),
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await client.get("https://example.org/start")

    assert requests == ["/start", "/again"]
    assert len(client.records) == 2
    assert result.status_code == 302
    assert result.error == "TooManyRedirects: exceeded 1 redirects"
