import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from web_openness.models import Confidence, Evidence, Observation, ObservationOutcome, ProbeError
from web_openness.probes.base import ProbeContext, evidence_from_fetch, observation
from web_openness.probes.robots import policy_allows

MAX_SITEMAP_XML_BYTES = 1_000_000

EXISTS_KEY = "metadata.sitemap_exists"
STATUS_KEY = "metadata.sitemap_status"
DOCUMENT_TYPE_KEY = "metadata.sitemap_document_type"
URL_COUNT_KEY = "metadata.sitemap_url_count"
CHILD_SITEMAP_COUNT_KEY = "metadata.sitemap_child_sitemap_count"


@dataclass(frozen=True, slots=True)
class ParsedSitemap:
    document_type: str
    url_count: int
    child_sitemap_count: int


class SitemapParseError(ValueError):
    """Raised when a response cannot be safely classified as a sitemap."""


def parse_sitemap(body: bytes) -> ParsedSitemap:
    """Parse one bounded sitemap document without following any referenced URLs."""

    if not body.strip():
        raise SitemapParseError("sitemap response was empty")
    if len(body) > MAX_SITEMAP_XML_BYTES:
        raise SitemapParseError(
            f"sitemap response exceeded the {MAX_SITEMAP_XML_BYTES}-byte parser limit"
        )

    normalized = body.lower()
    if b"<!doctype" in normalized or b"<!entity" in normalized:
        raise SitemapParseError("sitemap XML declarations are not permitted")

    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise SitemapParseError("sitemap response was malformed XML") from exc

    document_type = _local_name(root.tag)
    if document_type not in {"urlset", "sitemapindex"}:
        raise SitemapParseError(f"unsupported sitemap root element: {document_type or '<empty>'}")

    url_count = 0
    child_sitemap_count = 0
    for child in root:
        child_name = _local_name(child.tag)
        if document_type == "urlset" and child_name == "url":
            url_count += 1
        elif document_type == "sitemapindex" and child_name == "sitemap":
            child_sitemap_count += 1

    return ParsedSitemap(
        document_type=document_type,
        url_count=url_count,
        child_sitemap_count=child_sitemap_count,
    )


def _local_name(tag: object) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", maxsplit=1)[-1].lower()


def _candidate_url(context: ProbeContext) -> str:
    declared = context.shared.get("robots_sitemaps")
    if isinstance(declared, (list, tuple)):
        for item in declared:
            if isinstance(item, str) and item.strip():
                return urljoin(f"{context.origin}/", item.strip())
    return urljoin(f"{context.origin}/", "sitemap.xml")


def _is_safe_http_url(url: str) -> bool:
    parsed = urlsplit(url)
    return (
        parsed.scheme in {"http", "https"}
        and parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None
    )


def _unknown_fields(
    *,
    method: str,
    evidence: list[Evidence] | None = None,
    status: int | None = None,
    outcome: ObservationOutcome = ObservationOutcome.ERROR,
) -> dict[str, Observation]:
    status_confidence = Confidence.CONFIRMED if status is not None else Confidence.UNKNOWN
    status_score = 1.0 if status is not None else 0.0
    unknown_confidence = (
        Confidence.NO_EVIDENCE if outcome == ObservationOutcome.NO_EVIDENCE else Confidence.UNKNOWN
    )
    return {
        EXISTS_KEY: observation(
            None,
            confidence=unknown_confidence,
            score=0.0,
            method=method,
            evidence=evidence,
            outcome=outcome,
        ),
        STATUS_KEY: observation(
            status,
            confidence=status_confidence,
            score=status_score,
            method="HTTP status" if status is not None else method,
            evidence=evidence,
            outcome=ObservationOutcome.OBSERVED if status is not None else outcome,
        ),
        DOCUMENT_TYPE_KEY: observation(
            None,
            confidence=unknown_confidence,
            score=0.0,
            method=method,
            evidence=evidence,
            outcome=outcome,
        ),
        URL_COUNT_KEY: observation(
            None,
            confidence=unknown_confidence,
            score=0.0,
            method=method,
            evidence=evidence,
            outcome=outcome,
        ),
        CHILD_SITEMAP_COUNT_KEY: observation(
            None,
            confidence=unknown_confidence,
            score=0.0,
            method=method,
            evidence=evidence,
            outcome=outcome,
        ),
    }


class SitemapProbe:
    name = "sitemap"

    async def collect(self, context: ProbeContext) -> dict[str, Observation]:
        url = _candidate_url(context)
        if not _is_safe_http_url(url):
            message = "robots.txt declared an invalid sitemap URL"
            context.errors.append(ProbeError(probe=self.name, message=message))
            return _unknown_fields(method=message)

        if not policy_allows(context, url):
            return _unknown_fields(
                method="skipped because crawler policy was not affirmatively allowed",
                outcome=ObservationOutcome.SKIPPED,
            )

        result = await context.client.get(url)
        evidence = [evidence_from_fetch(result)]
        if result.error is not None:
            context.errors.append(ProbeError(probe=self.name, message=result.error))
            return _unknown_fields(method="sitemap fetch failed", evidence=evidence)

        status = result.status_code
        if status in {404, 410}:
            fields = _unknown_fields(
                method="sitemap returned a not-found status",
                evidence=evidence,
                status=status,
                outcome=ObservationOutcome.NO_EVIDENCE,
            )
            fields[EXISTS_KEY] = observation(
                False,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="sitemap returned a not-found status",
                evidence=evidence,
            )
            return fields

        if status != 200:
            return _unknown_fields(
                method="sitemap returned an inconclusive status",
                evidence=evidence,
                status=status,
                outcome=ObservationOutcome.NO_EVIDENCE,
            )

        if result.truncated:
            message = "sitemap response was truncated at the configured response limit"
            context.errors.append(ProbeError(probe=self.name, message=message))
            return _unknown_fields(method=message, evidence=evidence, status=status)

        try:
            parsed = parse_sitemap(result.body)
        except SitemapParseError as exc:
            context.errors.append(ProbeError(probe=self.name, message=str(exc)))
            return _unknown_fields(
                method="sitemap XML could not be safely classified",
                evidence=evidence,
                status=status,
            )

        return {
            EXISTS_KEY: observation(
                True,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="valid sitemap XML document",
                evidence=evidence,
            ),
            STATUS_KEY: observation(
                status,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="HTTP status",
                evidence=evidence,
            ),
            DOCUMENT_TYPE_KEY: observation(
                parsed.document_type,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="sitemap XML root element",
                evidence=evidence,
            ),
            URL_COUNT_KEY: observation(
                parsed.url_count,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="count of direct URL entries; linked documents were not fetched",
                evidence=evidence,
            ),
            CHILD_SITEMAP_COUNT_KEY: observation(
                parsed.child_sitemap_count,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="count of direct sitemap entries; child sitemaps were not fetched",
                evidence=evidence,
            ),
        }
