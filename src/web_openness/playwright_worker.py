import asyncio
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any, cast

from web_openness.browser_policy import (
    BrowserPolicyError,
    BrowserRender,
    BrowserRequestGate,
)
from web_openness.safety import URLSafetyError

MARKER_SELECTORS: dict[str, tuple[str, ...]] = {
    "login": (
        'form[action*="login" i]',
        'form[action*="signin" i]',
        'form[action*="sign-in" i]',
    ),
    "paywall": (
        '[id*="paywall" i]',
        '[class~="paywall" i]',
        '[data-testid*="paywall" i]',
        "#tp-modal",
        ".piano-offer",
    ),
    "cookie_wall": (
        "#onetrust-banner-sdk",
        "#CybotCookiebotDialog",
        "#didomi-host",
        '[data-testid*="cookie-consent" i]',
    ),
    "captcha": (
        ".g-recaptcha",
        ".h-captcha",
        ".cf-turnstile",
        'iframe[src*="recaptcha" i]',
        'iframe[src*="hcaptcha" i]',
        'iframe[src*="challenges.cloudflare.com" i]',
    ),
}

_VISIBLE_MARKERS_SCRIPT = """
selectors => {
  const visible = element => {
    const style = window.getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return style.display !== "none" && style.visibility !== "hidden" &&
      style.opacity !== "0" && rect.width > 0 && rect.height > 0;
  };
  const result = {};
  for (const [category, categorySelectors] of Object.entries(selectors)) {
    result[category] = categorySelectors.filter(selector =>
      Array.from(document.querySelectorAll(selector)).some(visible)
    );
  }
  return result;
}
"""

_DOCUMENT_COUNTS_SCRIPT = """
() => ({
  documentChars: document.documentElement?.outerHTML.length ?? 0,
  visibleTextChars: document.body?.innerText.length ?? 0,
})
"""


class PlaywrightBrowserWorker:
    """Render one public page without clicking, typing, or retaining a profile."""

    def __init__(self, *, user_agent: str, settle_milliseconds: int = 500) -> None:
        if settle_milliseconds < 0:
            raise ValueError("settle_milliseconds must not be negative")
        self.user_agent = user_agent
        self.settle_milliseconds = settle_milliseconds

    async def render(
        self,
        target_url: str,
        request_gate: BrowserRequestGate,
    ) -> BrowserRender:
        try:
            from playwright.async_api import Error as PlaywrightError
            from playwright.async_api import Route, async_playwright
        except ImportError as exc:  # pragma: no cover - depends on optional installation.
            raise BrowserPolicyError(
                "browser collection requires the 'browser' optional dependency"
            ) from exc

        blocked_requests = 0
        transfer_error: BrowserPolicyError | None = None
        close_task: asyncio.Task[None] | None = None

        async with async_playwright() as playwright:
            try:
                browser = await playwright.chromium.launch(headless=True)
            except PlaywrightError as exc:
                raise BrowserPolicyError(
                    "Chromium is unavailable; install it with 'playwright install chromium'"
                ) from exc

            context = await browser.new_context(
                accept_downloads=False,
                java_script_enabled=True,
                service_workers="block",
                user_agent=self.user_agent,
                viewport={"width": 1280, "height": 720},
            )
            page = await context.new_page()

            def stop_for_transfer_limit(error: BrowserPolicyError) -> None:
                nonlocal transfer_error, close_task
                if transfer_error is None:
                    transfer_error = error
                    close_task = asyncio.create_task(page.close())

            session = await context.new_cdp_session(page)
            await session.send("Network.enable")
            await session.send("Network.setCacheDisabled", {"cacheDisabled": True})

            def record_transfer(params: dict[str, Any]) -> None:
                response_id = params.get("requestId")
                encoded_length = params.get("encodedDataLength") or params.get("dataLength")
                if not isinstance(response_id, str) or not isinstance(encoded_length, (int, float)):
                    return
                try:
                    request_gate.record_response_chunk(response_id, int(encoded_length))
                except BrowserPolicyError as exc:
                    stop_for_transfer_limit(exc)

            session.on("Network.dataReceived", record_transfer)

            def reconcile_transfer(params: dict[str, Any]) -> None:
                response_id = params.get("requestId")
                encoded_length = params.get("encodedDataLength")
                if not isinstance(response_id, str) or not isinstance(encoded_length, (int, float)):
                    return
                try:
                    request_gate.record_response_total(response_id, int(encoded_length))
                except BrowserPolicyError as exc:
                    stop_for_transfer_limit(exc)

            session.on("Network.loadingFinished", reconcile_transfer)

            async def route_request(route: Route) -> None:
                nonlocal blocked_requests
                request = route.request
                top_level_navigation = False
                if request.is_navigation_request():
                    with suppress(PlaywrightError):
                        top_level_navigation = request.frame == page.main_frame
                try:
                    await request_gate.authorize(
                        request.url,
                        top_level_navigation=top_level_navigation,
                    )
                except (BrowserPolicyError, URLSafetyError):
                    blocked_requests += 1
                    await route.abort("blockedbyclient")
                    return
                await route.continue_()

            await context.route("**/*", route_request)
            response = None
            try:
                response = await page.goto(target_url, wait_until="domcontentloaded")
                if self.settle_milliseconds:
                    await page.wait_for_timeout(self.settle_milliseconds)
                if transfer_error is not None:
                    raise transfer_error

                raw_markers = await page.evaluate(_VISIBLE_MARKERS_SCRIPT, MARKER_SELECTORS)
                markers = _normalize_markers(raw_markers)
                raw_counts = await page.evaluate(_DOCUMENT_COUNTS_SCRIPT)
                document_chars, visible_text_chars = _normalize_counts(raw_counts)
                title = (await page.title()).strip()[:500] or None
                return BrowserRender(
                    final_url=page.url,
                    status_code=response.status if response is not None else None,
                    title=title,
                    document_chars=document_chars,
                    visible_text_chars=visible_text_chars,
                    markers=markers,
                    observed_at=datetime.now(UTC),
                    blocked_request_count=blocked_requests,
                )
            except PlaywrightError as exc:
                if transfer_error is not None:
                    raise transfer_error from exc
                message = " ".join(str(exc).split())[:300]
                raise BrowserPolicyError(f"browser navigation failed: {message}") from exc
            finally:
                if close_task is not None:
                    await asyncio.gather(close_task, return_exceptions=True)
                await context.close()
                await browser.close()


def _normalize_markers(value: object) -> dict[str, tuple[str, ...]]:
    if not isinstance(value, dict):
        raise BrowserPolicyError("browser marker result had an invalid shape")
    raw = cast(dict[object, object], value)
    markers: dict[str, tuple[str, ...]] = {}
    for category in MARKER_SELECTORS:
        selected = raw.get(category, [])
        if not isinstance(selected, list) or not all(isinstance(item, str) for item in selected):
            raise BrowserPolicyError("browser marker result had an invalid shape")
        markers[category] = tuple(sorted(cast(list[str], selected)))
    return markers


def _normalize_counts(value: object) -> tuple[int, int]:
    if not isinstance(value, dict):
        raise BrowserPolicyError("browser document result had an invalid shape")
    raw = cast(dict[object, object], value)
    document_chars = raw.get("documentChars")
    visible_text_chars = raw.get("visibleTextChars")
    if not isinstance(document_chars, int) or not isinstance(visible_text_chars, int):
        raise BrowserPolicyError("browser document result had an invalid shape")
    return max(0, document_chars), max(0, visible_text_chars)
