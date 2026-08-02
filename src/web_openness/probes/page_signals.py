import json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from web_openness.client import FetchResult
from web_openness.models import Confidence, Evidence, Observation, ObservationOutcome
from web_openness.probes.base import ProbeContext, mark_absences_inconclusive, observation

MAX_JSON_LD_CHARS = 100_000
MAX_NOSCRIPT_CHARS = 4_096
MAX_LICENSE_VALUES = 50
MAX_VALUE_CHARS = 4_096

ATTRIBUTE_MARKERS: dict[str, tuple[str, ...]] = {
    "paywall": (
        "metered-content",
        "paywall",
        "piano-offer",
        "subscription-wall",
        "tp-modal",
        "zephr-paywall",
    ),
    "cookie_wall": (
        "cookie-banner",
        "cookie-consent",
        "cookie-notice",
        "cybotcookiebotdialog",
        "didomi-host",
        "onetrust-banner-sdk",
        "onetrust-consent-sdk",
        "qc-cmp2-container",
        "usercentrics-root",
    ),
    "captcha": (
        "cf-turnstile",
        "g-recaptcha",
        "h-captcha",
    ),
}

URL_MARKERS: dict[str, tuple[str, ...]] = {
    "paywall": (
        "cdn.tinypass.com",
        "experience.tinypass.com",
        "piano.io",
        "pelcro.com",
        "poool.fr",
        "zephr.com",
    ),
    "cookie_wall": (
        "consentmanager.net",
        "cookiebot.com",
        "cookielaw.org",
        "didomi.io",
        "privacy-mgmt.com",
        "usercentrics.eu",
    ),
    "captcha": (
        "challenges.cloudflare.com/turnstile",
        "google.com/recaptcha",
        "gstatic.com/recaptcha",
        "hcaptcha.com",
    ),
}

JAVASCRIPT_REQUIRED = re.compile(
    r"\b(?:enable|turn on) javascript\b|\bjavascript (?:is )?required\b|"
    r"\brequires javascript\b",
    re.IGNORECASE,
)


@dataclass(slots=True)
class StructuredFindings:
    licenses: set[str] = field(default_factory=set)
    accessible_for_free: list[bool] = field(default_factory=list)
    requires_subscription: list[bool] = field(default_factory=list)


class PageSignalsHTMLParser(HTMLParser):
    """Extract bounded, high-precision declarations and barrier hints."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.markers: dict[str, set[str]] = {key: set() for key in ATTRIBUTE_MARKERS}
        self.license_hrefs: list[str] = []
        self.json_ld_documents: list[str] = []
        self._json_ld_parts: list[str] = []
        self._json_ld_chars = 0
        self._in_json_ld = False
        self._noscript_depth = 0
        self._noscript_parts: list[str] = []
        self._noscript_chars = 0

    @property
    def noscript_text(self) -> str:
        return " ".join("".join(self._noscript_parts).split())[:MAX_NOSCRIPT_CHARS]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        values = {key.lower(): value or "" for key, value in attrs}
        self._record_attribute_markers(values)
        self._record_url_markers(values.get("src", ""))

        rels = {part.lower() for part in values.get("rel", "").split()}
        href = values.get("href", "").strip()
        if "license" in rels and href and len(self.license_hrefs) < MAX_LICENSE_VALUES:
            self.license_hrefs.append(href[:MAX_VALUE_CHARS])

        if tag == "script" and values.get("type", "").lower() == "application/ld+json":
            self._in_json_ld = True
            self._json_ld_parts = []
            self._json_ld_chars = 0
        if tag == "noscript":
            self._noscript_depth += 1

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "script" and self._in_json_ld:
            document = "".join(self._json_ld_parts).strip()
            if document:
                self.json_ld_documents.append(document[:MAX_JSON_LD_CHARS])
            self._in_json_ld = False
            self._json_ld_parts = []
        if tag == "noscript" and self._noscript_depth:
            self._noscript_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._in_json_ld:
            chunk = data[: MAX_JSON_LD_CHARS - self._json_ld_chars]
            if chunk:
                self._json_ld_parts.append(chunk)
                self._json_ld_chars += len(chunk)
        if self._noscript_depth:
            chunk = data[: MAX_NOSCRIPT_CHARS - self._noscript_chars]
            if chunk:
                self._noscript_parts.append(chunk)
                self._noscript_chars += len(chunk)

    def _record_attribute_markers(self, values: dict[str, str]) -> None:
        haystack = " ".join((values.get("id", ""), values.get("class", ""))).lower()
        normalized = "-".join(re.findall(r"[a-z0-9]+", haystack))
        for category, markers in ATTRIBUTE_MARKERS.items():
            for marker in markers:
                if _bounded_marker_match(normalized, marker):
                    self.markers[category].add(f"dom:{marker}")

    def _record_url_markers(self, value: str) -> None:
        lowered = value.lower()
        for category, markers in URL_MARKERS.items():
            for marker in markers:
                if marker in lowered:
                    self.markers[category].add(f"resource:{marker}")


class PageSignalsProbe:
    name = "page_signals"

    async def collect(self, context: ProbeContext) -> dict[str, Observation]:
        html = context.shared.get("homepage_html")
        evidence_value = context.shared.get("homepage_evidence")
        evidence = [evidence_value] if isinstance(evidence_value, Evidence) else []
        if not isinstance(html, str):
            return _unknown_page_signals(
                "homepage HTML was unavailable",
                evidence,
                outcome=_unavailable_outcome(context),
            )

        parser = PageSignalsHTMLParser()
        parser.feed(html)
        structured = _structured_findings(parser.json_ld_documents)
        response = context.shared.get("homepage_response")
        base_url = (
            response.final_url
            if isinstance(response, FetchResult) and response.final_url
            else context.origin
        )
        licenses = _license_values(base_url, parser.license_hrefs, structured.licenses)

        paywall_markers = set(parser.markers["paywall"])
        if False in structured.accessible_for_free:
            paywall_markers.add("jsonld:isAccessibleForFree=false")

        javascript_markers = (
            ["noscript:javascript-required"]
            if JAVASCRIPT_REQUIRED.search(parser.noscript_text)
            else []
        )

        observations = {
            "human.paywall_detected": _possible_detection(
                paywall_markers,
                "homepage structured-data declaration or known paywall markup/resource marker",
                evidence,
                score=0.8 if "jsonld:isAccessibleForFree=false" in paywall_markers else 0.6,
            ),
            "human.cookie_wall_detected": _possible_detection(
                parser.markers["cookie_wall"],
                "known homepage consent-management markup or resource marker; "
                "visual state not evaluated",
                evidence,
            ),
            "human.captcha_detected": _possible_detection(
                parser.markers["captcha"],
                "known homepage CAPTCHA markup or resource marker; challenge state not evaluated",
                evidence,
            ),
            "human.javascript_required": _possible_detection(
                javascript_markers,
                "explicit bounded homepage noscript instruction; browser behavior not evaluated",
                evidence,
                score=0.8,
            ),
            "legal.license": observation(
                licenses,
                confidence=Confidence.CONFIRMED if licenses else Confidence.NO_EVIDENCE,
                score=1.0,
                method="explicit homepage rel=license link or JSON-LD license declaration",
                evidence=evidence,
            ),
            "economic.subscription_required": _subscription_observation(
                structured.requires_subscription,
                evidence,
            ),
        }
        if isinstance(response, FetchResult) and response.truncated:
            return mark_absences_inconclusive(
                observations,
                method="homepage HTML was truncated; absence could not be established",
                evidence=evidence,
            )
        return observations


def _possible_detection(
    markers: set[str] | list[str],
    method: str,
    evidence: list[Evidence],
    *,
    score: float = 0.6,
) -> Observation:
    ordered = sorted(markers)
    if not ordered:
        return observation(
            None,
            confidence=Confidence.NO_EVIDENCE,
            score=1.0,
            method=f"no {method}",
            evidence=evidence,
        )
    return observation(
        {"detected": True, "markers": ordered},
        confidence=Confidence.LIKELY if score >= 0.8 else Confidence.POSSIBLE,
        score=score,
        method=method,
        evidence=evidence,
    )


def _subscription_observation(values: list[bool], evidence: list[Evidence]) -> Observation:
    if not values:
        return observation(
            None,
            confidence=Confidence.NO_EVIDENCE,
            score=1.0,
            method="no explicit homepage JSON-LD requiresSubscription declaration",
            evidence=evidence,
        )
    return observation(
        any(values),
        confidence=Confidence.CONFIRMED,
        score=1.0,
        method="explicit homepage JSON-LD requiresSubscription declaration",
        evidence=evidence,
    )


def _structured_findings(documents: list[str]) -> StructuredFindings:
    findings = StructuredFindings()
    for document in documents:
        try:
            payload = json.loads(document)
        except (json.JSONDecodeError, RecursionError):
            continue
        stack = [payload]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                _record_licenses(findings, value.get("license"))
                if (parsed := _schema_bool(value.get("isAccessibleForFree"))) is not None:
                    findings.accessible_for_free.append(parsed)
                subscription = value.get("requiresSubscription")
                if isinstance(subscription, dict):
                    findings.requires_subscription.append(True)
                elif (parsed := _schema_bool(subscription)) is not None:
                    findings.requires_subscription.append(parsed)
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
    return findings


def _record_licenses(findings: StructuredFindings, value: object) -> None:
    if len(findings.licenses) >= MAX_LICENSE_VALUES:
        return
    if isinstance(value, str):
        bounded = " ".join(value.split())[:MAX_VALUE_CHARS]
        if bounded:
            findings.licenses.add(bounded)
    elif isinstance(value, list):
        for item in value:
            _record_licenses(findings, item)
    elif isinstance(value, dict):
        for key in ("@id", "url", "name"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                _record_licenses(findings, candidate)
                break


def _schema_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
    return None


def _license_values(base_url: str, hrefs: list[str], declared: set[str]) -> list[str]:
    values = set(declared)
    for href in hrefs:
        resolved = urljoin(base_url, href)
        parsed = urlsplit(resolved)
        if (
            parsed.scheme in {"http", "https"}
            and parsed.hostname is not None
            and parsed.username is None
            and parsed.password is None
        ):
            values.add(resolved[:MAX_VALUE_CHARS])
    return sorted(values)[:MAX_LICENSE_VALUES]


def _bounded_marker_match(haystack: str, marker: str) -> bool:
    return bool(re.search(rf"(?:^|-){re.escape(marker)}(?:-|$)", haystack))


def _unavailable_outcome(context: ProbeContext) -> ObservationOutcome:
    if context.shared.get("robots_allows_followup") is not True:
        return ObservationOutcome.SKIPPED
    response = context.shared.get("homepage_response")
    if (
        isinstance(response, FetchResult)
        and response.error is None
        and response.status_code is not None
    ):
        return ObservationOutcome.SKIPPED
    return ObservationOutcome.ERROR


def _unknown_page_signals(
    method: str,
    evidence: list[Evidence],
    *,
    outcome: ObservationOutcome,
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
            "human.paywall_detected",
            "human.cookie_wall_detected",
            "human.captcha_detected",
            "human.javascript_required",
            "legal.license",
            "economic.subscription_required",
        )
    }
