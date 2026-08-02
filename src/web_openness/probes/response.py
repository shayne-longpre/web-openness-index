import re

from web_openness.client import FetchResult
from web_openness.models import (
    Confidence,
    Evidence,
    Observation,
    ObservationOutcome,
)
from web_openness.probes.base import ProbeContext, evidence_from_request, observation

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
HTTP3_ALTERNATIVE = re.compile(r"(?:^|,)\s*h3(?:-[0-9]+)?\s*=", re.IGNORECASE)


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
        evidence = [
            evidence_from_request(
                record,
                note="HTTP attempt in the homepage redirect/retry chain",
            )
            for record in attempts
        ]
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
        edge_response_hints = _edge_response_hints(headers, cdn_hints)
        waf_hints = _waf_hints(headers)
        cookie_fingerprints = _cookie_fingerprints(value.cookie_names)
        bot_management_hints = _bot_management_hints(cookie_fingerprints)
        load_balancer_hints = _load_balancer_hints(cookie_fingerprints)
        acceleration_hints = ["f5_big_ip"] if "x-wa-info" in headers else []
        challenge = _challenge_response(headers)
        cache_status = _cache_status(headers, cdn_hints)
        edge_locations = _edge_location_hints(headers)
        http3_advertised = bool(HTTP3_ALTERNATIVE.search(headers.get("alt-svc", "")))
        status = value.status_code
        disposition = _access_disposition(status)
        http_version = getattr(value, "http_version", None)
        authentication_challenge = bool(status == 401 or "www-authenticate" in headers)
        rate_limited_attempts = tuple(record for record in attempts if record.status_code == 429)
        rate_limited = bool(rate_limited_attempts)
        rate_limit_evidence = (
            [
                evidence_from_request(
                    record,
                    note="HTTP 429 in the homepage redirect/retry chain",
                )
                for record in rate_limited_attempts
            ]
            if rate_limited
            else evidence
        )
        legal_restriction_attempts = tuple(
            record for record in attempts if record.status_code == 451
        )
        legal_restriction_evidence = [
            evidence_from_request(
                record,
                note="HTTP 451 in the homepage redirect/retry chain",
            )
            for record in legal_restriction_attempts
        ]

        return {
            "network.http_version": _known_or_no_evidence(
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
            "infrastructure.edge_response_hints": observation(
                edge_response_hints,
                confidence=(Confidence.LIKELY if edge_response_hints else Confidence.NO_EVIDENCE),
                score=0.8 if edge_response_hints else 1.0,
                method="provider-specific homepage edge headers; role is not inferred",
                evidence=evidence,
            ),
            "infrastructure.waf": observation(
                waf_hints,
                confidence=Confidence.LIKELY if waf_hints else Confidence.NO_EVIDENCE,
                score=0.8 if waf_hints else 1.0,
                method=(
                    "provider-specific WAF or challenge response headers; "
                    "not definitive attribution"
                ),
                evidence=evidence,
            ),
            "infrastructure.challenge_response": _known_or_no_evidence(
                challenge,
                "explicit edge challenge or block response header",
                evidence,
            ),
            "infrastructure.cache_status": observation(
                cache_status,
                confidence=Confidence.CONFIRMED if cache_status else Confidence.NO_EVIDENCE,
                score=1.0,
                method="provider-specific cache outcome for this homepage response",
                evidence=evidence,
            ),
            "infrastructure.edge_location_hints": observation(
                edge_locations,
                confidence=Confidence.LIKELY if edge_locations else Confidence.NO_EVIDENCE,
                score=0.8 if edge_locations else 1.0,
                method="provider-specific edge request identifier suffix",
                evidence=evidence,
            ),
            "infrastructure.http3_advertised": observation(
                True if http3_advertised else None,
                confidence=Confidence.CONFIRMED if http3_advertised else Confidence.NO_EVIDENCE,
                score=1.0,
                method="h3 protocol token in the homepage Alt-Svc response header",
                evidence=evidence,
            ),
            "infrastructure.content_encoding": _known_or_no_evidence(
                headers.get("content-encoding"),
                "homepage Content-Encoding response header",
                evidence,
            ),
            "infrastructure.response_cookie_fingerprints": observation(
                cookie_fingerprints,
                confidence=(Confidence.POSSIBLE if cookie_fingerprints else Confidence.NO_EVIDENCE),
                score=0.6 if cookie_fingerprints else 1.0,
                method="recognized Set-Cookie names only; cookie values were discarded",
                evidence=evidence,
            ),
            "infrastructure.bot_management_hints": observation(
                bot_management_hints,
                confidence=(
                    Confidence.POSSIBLE if bot_management_hints else Confidence.NO_EVIDENCE
                ),
                score=0.6 if bot_management_hints else 1.0,
                method="recognized infrastructure cookie names; product use is probabilistic",
                evidence=evidence,
            ),
            "infrastructure.load_balancer_hints": observation(
                load_balancer_hints,
                confidence=(Confidence.POSSIBLE if load_balancer_hints else Confidence.NO_EVIDENCE),
                score=0.6 if load_balancer_hints else 1.0,
                method="recognized load-balancer cookie names; product use is probabilistic",
                evidence=evidence,
            ),
            "infrastructure.acceleration_hints": observation(
                acceleration_hints,
                confidence=(Confidence.LIKELY if acceleration_hints else Confidence.NO_EVIDENCE),
                score=0.8 if acceleration_hints else 1.0,
                method="provider-specific response acceleration header",
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
            "human.geographic_restriction": observation(
                ({"detected": True, "status": 451} if legal_restriction_attempts else None),
                confidence=(
                    Confidence.POSSIBLE if legal_restriction_attempts else Confidence.NO_EVIDENCE
                ),
                score=0.6 if legal_restriction_attempts else 1.0,
                method=(
                    "HTTP 451 observed; the legal restriction may be geographic or jurisdictional"
                    if legal_restriction_attempts
                    else "no HTTP 451 in the homepage request attempts"
                ),
                evidence=legal_restriction_evidence or evidence,
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
    if "x-akamai-transformed" in headers or "akamai-grn" in headers:
        hints.add("akamai")
    if "x-served-by" in headers and "fastly" in headers.get("via", "").lower():
        hints.add("fastly")
    return sorted(hints)


def _edge_response_hints(headers: dict[str, str], cdn_hints: list[str]) -> list[str]:
    hints = set(cdn_hints)
    if headers.get("cf-mitigated", "").lower() == "challenge":
        hints.add("cloudflare")
    if "x-sucuri-id" in headers or "x-sucuri-block" in headers:
        hints.add("sucuri")
    if "x-iinfo" in headers or "imperva" in headers.get("x-cdn", "").lower():
        hints.add("imperva")
    if "x-wa-info" in headers:
        hints.add("f5")
    return sorted(hints)


def _waf_hints(headers: dict[str, str]) -> list[str]:
    hints: set[str] = set()
    if headers.get("cf-mitigated", "").lower() == "challenge":
        hints.add("cloudflare")
    if "x-sucuri-block" in headers:
        hints.add("sucuri")
    return sorted(hints)


def _challenge_response(headers: dict[str, str]) -> dict[str, str] | None:
    if headers.get("cf-mitigated", "").lower() == "challenge":
        return {"provider": "cloudflare", "type": "challenge"}
    if "x-sucuri-block" in headers:
        return {"provider": "sucuri", "type": "block"}
    return None


def _cache_status(headers: dict[str, str], cdn_hints: list[str]) -> list[dict[str, str]]:
    statuses: list[dict[str, str]] = []
    if value := headers.get("cf-cache-status"):
        statuses.append({"provider": "cloudflare", "status": value.upper()})
    if value := headers.get("x-cache"):
        provider = cdn_hints[0] if len(cdn_hints) == 1 else "unspecified"
        statuses.append({"provider": provider, "status": value})
    return statuses


def _edge_location_hints(headers: dict[str, str]) -> dict[str, str]:
    locations: dict[str, str] = {}
    if value := headers.get("cf-ray"):
        _identifier, separator, suffix = value.rpartition("-")
        if separator and re.fullmatch(r"[A-Za-z0-9]{3}", suffix):
            locations["cloudflare"] = suffix.upper()
    return locations


def _cookie_fingerprints(names: tuple[str, ...]) -> list[str]:
    fingerprints: set[str] = set()
    for name in names:
        lowered = name.lower()
        if lowered == "__cf_bm":
            fingerprints.add("cloudflare:__cf_bm")
        elif lowered == "cf_clearance":
            fingerprints.add("cloudflare:cf_clearance")
        elif lowered == "__cflb":
            fingerprints.add("cloudflare:__cflb")
        elif lowered in {"_abck", "ak_bmsc", "bm_sz"}:
            fingerprints.add(f"akamai:{lowered}")
        elif lowered == "datadome":
            fingerprints.add("datadome:datadome")
        elif lowered.startswith(("incap_ses_", "visid_incap_")):
            fingerprints.add("imperva:session_cookie")
        elif lowered.startswith("bigipserver"):
            fingerprints.add("f5:BIGipServer*")
        elif re.fullmatch(r"ts[0-9a-f]+", lowered):
            fingerprints.add("f5:TS*")
    return sorted(fingerprints)


def _bot_management_hints(fingerprints: list[str]) -> list[str]:
    providers: set[str] = set()
    for value in fingerprints:
        if value.startswith("cloudflare:__cf_bm"):
            providers.add("cloudflare")
        elif value.startswith("akamai:"):
            providers.add("akamai")
        elif value.startswith("datadome:"):
            providers.add("datadome")
        elif value.startswith("imperva:"):
            providers.add("imperva")
        elif value.startswith("f5:TS"):
            providers.add("f5")
    return sorted(providers)


def _load_balancer_hints(fingerprints: list[str]) -> list[str]:
    providers: set[str] = set()
    for value in fingerprints:
        if value == "cloudflare:__cflb":
            providers.add("cloudflare")
        elif value.startswith("f5:BIGipServer"):
            providers.add("f5")
    return sorted(providers)


def _access_disposition(status: int | None) -> str | None:
    if status is None:
        return None
    if status == 401:
        return "authentication_required"
    if status == 403:
        return "forbidden"
    if status == 429:
        return "rate_limited"
    if status == 451:
        return "unavailable_for_legal_reasons"
    if 200 <= status < 400:
        return "reachable"
    if 400 <= status < 500:
        return "other_client_error"
    if status >= 500:
        return "server_error"
    return "other_status"


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
            "infrastructure.edge_response_hints",
            "infrastructure.waf",
            "infrastructure.challenge_response",
            "infrastructure.cache_status",
            "infrastructure.edge_location_hints",
            "infrastructure.http3_advertised",
            "infrastructure.content_encoding",
            "infrastructure.response_cookie_fingerprints",
            "infrastructure.bot_management_hints",
            "infrastructure.load_balancer_hints",
            "infrastructure.acceleration_hints",
            "human.http_access_disposition",
            "human.authentication_challenge",
            "human.login_required",
            "human.rate_limited",
            "human.geographic_restriction",
            "preservation.cache_header_hints",
        )
    }
