from web_openness.client import FetchResult
from web_openness.models import (
    Confidence,
    Evidence,
    Observation,
    ObservationOutcome,
    RequestRecord,
)
from web_openness.probes.base import ProbeContext, observation

SECURITY_HEADERS = (
    "content-security-policy",
    "permissions-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
)
CACHE_HEADERS = ("age", "cache-control", "cf-cache-status", "x-cache")
MAX_HEADER_VALUE_CHARS = 2_048


class ResponseProbe:
    """Classify evidence already returned with the homepage response."""

    name = "homepage_response"

    async def collect(self, context: ProbeContext) -> dict[str, Observation]:
        value = context.shared.get("homepage_response")
        if not isinstance(value, FetchResult):
            outcome = (
                ObservationOutcome.SKIPPED
                if context.shared.get("robots_allows_followup") is not True
                else ObservationOutcome.ERROR
            )
            return _unknown_response("homepage response was unavailable", outcome=outcome)

        attempts = value.attempts or (value.evidence,)
        evidence = [_evidence_from_attempt(record) for record in attempts]
        if value.error is not None or value.status_code is None:
            return _unknown_response(
                "homepage request did not return a response",
                evidence,
                outcome=ObservationOutcome.ERROR,
            )
        headers = {
            key: header_value[:MAX_HEADER_VALUE_CHARS]
            for key, header_value in sorted(value.headers.items())
        }
        security = sorted(key for key in SECURITY_HEADERS if key in headers)
        cache = {key: headers[key] for key in CACHE_HEADERS if key in headers}
        cdn_hints = _cdn_hints(headers)
        status = value.status_code
        disposition = _access_disposition(status)
        http_version = getattr(value, "http_version", None)
        authentication_challenge = bool(status == 401 or "www-authenticate" in headers)
        rate_limited_attempts = tuple(record for record in attempts if record.status_code == 429)
        rate_limited = bool(rate_limited_attempts)
        rate_limit_evidence = (
            [_evidence_from_attempt(record) for record in rate_limited_attempts]
            if rate_limited
            else evidence
        )

        return {
            "network.http_version": _known_or_unknown(
                http_version,
                "HTTP protocol reported by the HTTP client",
                evidence,
            ),
            "infrastructure.response_headers": observation(
                headers,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="allowlisted homepage response headers",
                evidence=evidence,
            ),
            "infrastructure.server_header": _known_or_no_evidence(
                headers.get("server"),
                "homepage Server response header",
                evidence,
            ),
            "infrastructure.security_headers": observation(
                security,
                confidence=Confidence.CONFIRMED if security else Confidence.NO_EVIDENCE,
                score=1.0,
                method="presence of common browser security response headers",
                evidence=evidence,
            ),
            "infrastructure.cache_headers": observation(
                cache,
                confidence=Confidence.CONFIRMED if cache else Confidence.NO_EVIDENCE,
                score=1.0,
                method="allowlisted cache response headers",
                evidence=evidence,
            ),
            "infrastructure.cdn_hints": observation(
                cdn_hints,
                confidence=Confidence.LIKELY if cdn_hints else Confidence.NO_EVIDENCE,
                score=0.8 if cdn_hints else 1.0,
                method="provider-specific response-header hints; not definitive attribution",
                evidence=evidence,
            ),
            "infrastructure.cdn": observation(
                cdn_hints,
                confidence=Confidence.LIKELY if cdn_hints else Confidence.NO_EVIDENCE,
                score=0.8 if cdn_hints else 1.0,
                method="provider-specific homepage headers; provider attribution is probabilistic",
                evidence=evidence,
            ),
            "human.http_access_disposition": observation(
                disposition,
                confidence=(Confidence.CONFIRMED if status is not None else Confidence.UNKNOWN),
                score=1.0 if status is not None else 0.0,
                method="homepage HTTP status class",
                evidence=evidence,
            ),
            "human.authentication_challenge": observation(
                authentication_challenge,
                confidence=(
                    Confidence.CONFIRMED if authentication_challenge else Confidence.NO_EVIDENCE
                ),
                score=1.0,
                method="HTTP 401 or WWW-Authenticate response header",
                evidence=evidence,
            ),
            "human.login_required": observation(
                True if authentication_challenge else None,
                confidence=(
                    Confidence.CONFIRMED if authentication_challenge else Confidence.NO_EVIDENCE
                ),
                score=1.0,
                method=(
                    "HTTP authentication challenge"
                    if authentication_challenge
                    else "no HTTP authentication challenge; form-based login not yet evaluated"
                ),
                evidence=evidence,
            ),
            "human.rate_limited": observation(
                rate_limited,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="HTTP 429 observed in homepage request attempts",
                evidence=rate_limit_evidence,
            ),
            "preservation.cache_header_hints": observation(
                cache,
                confidence=Confidence.CONFIRMED if cache else Confidence.NO_EVIDENCE,
                score=1.0,
                method=(
                    "cache-related homepage response headers; does not establish cache behavior"
                ),
                evidence=evidence,
            ),
        }


def _cdn_hints(headers: dict[str, str]) -> list[str]:
    hints: set[str] = set()
    if "cf-ray" in headers or "cf-cache-status" in headers:
        hints.add("cloudflare")
    if "x-amz-cf-id" in headers:
        hints.add("amazon_cloudfront")
    if "x-akamai-transformed" in headers:
        hints.add("akamai")
    if "x-served-by" in headers and "fastly" in headers.get("via", "").lower():
        hints.add("fastly")
    return sorted(hints)


def _access_disposition(status: int | None) -> str | None:
    if status is None:
        return None
    if status == 401:
        return "authentication_required"
    if status == 403:
        return "forbidden"
    if status == 429:
        return "rate_limited"
    if 200 <= status < 400:
        return "reachable"
    if 400 <= status < 500:
        return "other_client_error"
    if status >= 500:
        return "server_error"
    return "other_status"


def _known_or_unknown(
    value: object,
    method: str,
    evidence: list[Evidence],
) -> Observation:
    return observation(
        value,
        confidence=Confidence.CONFIRMED if value is not None else Confidence.NO_EVIDENCE,
        score=1.0 if value is not None else 0.0,
        method=method,
        evidence=evidence,
    )


def _evidence_from_attempt(record: RequestRecord) -> Evidence:
    return Evidence(
        source_url=record.final_url or record.requested_url,
        observed_at=record.started_at,
        http_status=record.status_code,
        content_sha256=record.content_sha256,
        note="HTTP attempt in the homepage redirect/retry chain",
    )


def _known_or_no_evidence(
    value: object,
    method: str,
    evidence: list[Evidence],
) -> Observation:
    return observation(
        value,
        confidence=Confidence.CONFIRMED if value is not None else Confidence.NO_EVIDENCE,
        score=1.0,
        method=method,
        evidence=evidence,
    )


def _unknown_response(
    method: str,
    evidence: list[Evidence] | None = None,
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
            "network.http_version",
            "infrastructure.response_headers",
            "infrastructure.server_header",
            "infrastructure.security_headers",
            "infrastructure.cache_headers",
            "infrastructure.cdn_hints",
            "infrastructure.cdn",
            "human.http_access_disposition",
            "human.authentication_challenge",
            "human.login_required",
            "human.rate_limited",
            "preservation.cache_header_hints",
        )
    }
