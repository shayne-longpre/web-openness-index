from web_openness.client import FetchResult
from web_openness.models import Confidence, Evidence, Observation
from web_openness.probes.base import ProbeContext, evidence_from_fetch, observation

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
            return _unknown_response("homepage response was unavailable")

        evidence = [evidence_from_fetch(value)]
        if value.error is not None or value.status_code is None:
            return _unknown_response("homepage request did not return a response", evidence)
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
            "human.http_access_disposition": observation(
                disposition,
                confidence=(Confidence.CONFIRMED if status is not None else Confidence.UNKNOWN),
                score=1.0 if status is not None else 0.0,
                method="homepage HTTP status class",
                evidence=evidence,
            ),
            "human.authentication_challenge": observation(
                bool(status == 401 or "www-authenticate" in headers),
                confidence=(
                    Confidence.CONFIRMED
                    if status == 401 or "www-authenticate" in headers
                    else Confidence.NO_EVIDENCE
                ),
                score=1.0,
                method="HTTP 401 or WWW-Authenticate response header",
                evidence=evidence,
            ),
            "human.rate_limited": observation(
                status == 429,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="homepage HTTP 429 response status",
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
        confidence=Confidence.CONFIRMED if value is not None else Confidence.UNKNOWN,
        score=1.0 if value is not None else 0.0,
        method=method,
        evidence=evidence,
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
            "network.http_version",
            "infrastructure.response_headers",
            "infrastructure.server_header",
            "infrastructure.security_headers",
            "infrastructure.cache_headers",
            "infrastructure.cdn_hints",
            "human.http_access_disposition",
            "human.authentication_challenge",
            "human.rate_limited",
        )
    }
