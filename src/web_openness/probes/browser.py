from typing import cast
from urllib.parse import urljoin, urlsplit

from web_openness.browser_policy import (
    BrowserRender,
    BrowserWorker,
    run_browser_worker,
    same_site,
)
from web_openness.client import FetchResult
from web_openness.domains import canonical_hostname
from web_openness.governance import CeaseList
from web_openness.models import (
    Confidence,
    Evidence,
    Observation,
    ObservationOutcome,
    ProbeError,
)
from web_openness.probes.base import ProbeContext, evidence_from_fetch, observation
from web_openness.probes.robots import policy_allows

BROWSER_KEYS = (
    "crawler.browser_http_difference",
    "browser.navigation",
    "browser.rendered_document",
    "browser.network_summary",
    "human.browser_login_marker_visible",
    "human.browser_paywall_marker_visible",
    "human.browser_cookie_wall_marker_visible",
    "human.browser_captcha_marker_visible",
)

_MARKER_KEYS = {
    "login": "human.browser_login_marker_visible",
    "paywall": "human.browser_paywall_marker_visible",
    "cookie_wall": "human.browser_cookie_wall_marker_visible",
    "captcha": "human.browser_captcha_marker_visible",
}


class BrowserProbe:
    name = "browser"

    async def collect(self, context: ProbeContext) -> dict[str, Observation]:
        policy = context.config.browser_policy
        if not policy.enabled:
            return _unavailable_browser(
                "browser collection is disabled",
                outcome=ObservationOutcome.SKIPPED,
            )
        if context.shared.get("robots_allows_followup") is not True:
            return _unavailable_browser(
                "skipped because crawler policy was not affirmatively allowed",
                outcome=ObservationOutcome.SKIPPED,
            )

        target_url = urljoin(f"{context.origin}/", "/")
        worker = context.shared.get("browser_worker")
        if worker is None:
            from web_openness.playwright_worker import PlaywrightBrowserWorker

            worker = PlaywrightBrowserWorker(user_agent=context.config.user_agent)

        try:
            rendered = await run_browser_worker(
                cast(BrowserWorker, worker),
                target_url,
                policy,
                url_allowed=lambda url: _url_allowed(context, url),
            )
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            context.errors.append(ProbeError(probe=self.name, message=message))
            return _unavailable_browser("browser navigation failed")

        return _browser_observations(context, rendered)


def _url_allowed(context: ProbeContext, url: str) -> bool:
    hostname = urlsplit(url).hostname
    if hostname is None:
        return False
    try:
        normalized_host = canonical_hostname(hostname)
    except ValueError:
        return False

    cease_list = context.shared.get("cease_list")
    if isinstance(cease_list, CeaseList) and cease_list.blocks(normalized_host):
        return False
    return not same_site(context.origin, url) or policy_allows(context, url)


def _browser_observations(
    context: ProbeContext,
    rendered: BrowserRender,
) -> dict[str, Observation]:
    browser_evidence = Evidence(
        source_url=rendered.final_url,
        observed_at=rendered.observed_at,
        http_status=rendered.status_code,
        note="fresh browser context; no page interactions",
    )
    evidence = [browser_evidence]
    homepage = context.shared.get("homepage_response")
    if isinstance(homepage, FetchResult):
        evidence.insert(0, evidence_from_fetch(homepage, note="direct HTTP homepage response"))

    accessible = rendered.status_code is not None and 200 <= rendered.status_code < 400
    observations = {
        "crawler.browser_http_difference": observation(
            _http_comparison(homepage, rendered),
            confidence=Confidence.CONFIRMED,
            score=1.0,
            method="direct HTTP response compared with a fresh rendered browser document",
            evidence=evidence,
        ),
        "browser.navigation": observation(
            {
                "final_url": rendered.final_url,
                "status": rendered.status_code,
                "accessible": accessible,
            },
            confidence=Confidence.CONFIRMED,
            score=1.0,
            method="fresh browser navigation without page interaction",
            evidence=[browser_evidence],
        ),
        "browser.rendered_document": observation(
            {
                "title": rendered.title,
                "document_chars": rendered.document_chars,
                "visible_text_chars": rendered.visible_text_chars,
            },
            confidence=Confidence.CONFIRMED,
            score=1.0,
            method="bounded rendered-DOM metadata; document text was not retained",
            evidence=[browser_evidence],
        ),
        "browser.network_summary": observation(
            {
                "requests": rendered.request_count,
                "third_party_requests": rendered.third_party_request_count,
                "blocked_requests": rendered.blocked_request_count,
                "transferred_response_bytes": rendered.total_response_bytes,
            },
            confidence=Confidence.CONFIRMED,
            score=1.0,
            method="isolated browser request gate and Chromium transfer counters",
            evidence=[browser_evidence],
        ),
    }
    for category, key in _MARKER_KEYS.items():
        observations[key] = _marker_observation(
            category,
            rendered.markers.get(category, ()),
            browser_evidence,
        )
    return observations


def _http_comparison(homepage: object, rendered: BrowserRender) -> dict[str, object]:
    if not isinstance(homepage, FetchResult):
        return {
            "http_available": False,
            "browser_status": rendered.status_code,
            "browser_final_url": rendered.final_url,
            "rendered_document_chars": rendered.document_chars,
        }

    http_final_url = homepage.final_url or homepage.requested_url
    http_accessible = homepage.status_code is not None and 200 <= homepage.status_code < 400
    browser_accessible = rendered.status_code is not None and 200 <= rendered.status_code < 400
    return {
        "http_available": homepage.error is None,
        "http_status": homepage.status_code,
        "browser_status": rendered.status_code,
        "status_changed": homepage.status_code != rendered.status_code,
        "access_disposition_changed": http_accessible != browser_accessible,
        "http_final_url": http_final_url,
        "browser_final_url": rendered.final_url,
        "final_url_changed": http_final_url != rendered.final_url,
        "http_document_chars": len(homepage.text),
        "rendered_document_chars": rendered.document_chars,
        "document_char_delta": rendered.document_chars - len(homepage.text),
    }


def _marker_observation(
    category: str,
    markers: tuple[str, ...],
    evidence: Evidence,
) -> Observation:
    if not markers:
        return observation(
            None,
            confidence=Confidence.NO_EVIDENCE,
            score=1.0,
            method=f"no visible high-precision {category.replace('_', ' ')} marker observed",
            evidence=[evidence],
        )
    return observation(
        {"visible": True, "selectors": list(markers)},
        confidence=Confidence.LIKELY,
        score=0.9,
        method=f"visible high-precision {category.replace('_', ' ')} DOM selector",
        evidence=[evidence],
    )


def _unavailable_browser(
    method: str,
    *,
    outcome: ObservationOutcome = ObservationOutcome.ERROR,
) -> dict[str, Observation]:
    return {
        key: observation(
            None,
            confidence=Confidence.UNKNOWN,
            score=0.0,
            method=method,
            outcome=outcome,
        )
        for key in BROWSER_KEYS
    }
