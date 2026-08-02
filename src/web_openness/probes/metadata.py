import json
import re
from collections.abc import Iterable
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from web_openness.client import FetchResult
from web_openness.models import Confidence, Evidence, Observation, ObservationOutcome
from web_openness.probes.base import ProbeContext, observation

FEED_TYPES = {
    "application/atom+xml",
    "application/feed+json",
    "application/json",
    "application/rss+xml",
}
INTERFACE_MEDIA_TYPES = {
    "application/openapi+json",
    "application/schema+json",
    "application/vnd.oai.openapi+json",
}
INTERFACE_RELS = {"service-desc", "service-doc"}
MAX_DISCOVERED_LINKS = 50
MAX_TEXT_CHARS = 4_096
MAX_LINK_TEXT_CHARS = 256
MAX_JSON_LD_CHARS = 100_000

DISCOVERY_MARKERS: dict[str, tuple[str, ...]] = {
    "legal.policy_links": (
        "acceptable-use",
        "legal",
        "privacy",
        "terms",
        "tos",
    ),
    "legal.license_links": ("copyright", "license", "licensing"),
    "economic.pricing_links": ("membership", "plans", "pricing", "subscribe", "subscription"),
    "economic.registration_links": ("create-account", "log-in", "login", "register", "sign-up"),
}


class MetadataHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.has_json_ld = False
        self.has_open_graph = False
        self.feeds: set[str] = set()
        self.canonical_urls: list[str] = []
        self.manifest_urls: list[str] = []
        self.opensearch_urls: list[str] = []
        self.interface_links: list[dict[str, object]] = []
        self.page_links: list[dict[str, str]] = []
        self.json_ld_documents: list[str] = []
        self.html_language: str | None = None
        self.generator: str | None = None
        self._title_parts: list[str] = []
        self._json_ld_parts: list[str] = []
        self._in_title = False
        self._title_complete = False
        self._in_json_ld = False
        self._current_anchor: dict[str, str] | None = None

    @property
    def title(self) -> str | None:
        value = " ".join("".join(self._title_parts).split())
        return value[:MAX_TEXT_CHARS] or None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        values = {key.lower(): value or "" for key, value in attrs}
        if tag == "html" and not self.html_language:
            self.html_language = _bounded(values.get("lang"))
        if tag == "title" and not self._title_complete:
            self._in_title = True
        if tag == "script" and values.get("type", "").lower() == "application/ld+json":
            self.has_json_ld = True
            self._in_json_ld = True
            self._json_ld_parts = []
        if tag == "meta":
            if values.get("property", "").lower().startswith("og:"):
                self.has_open_graph = True
            if values.get("name", "").lower() == "generator" and not self.generator:
                self.generator = _bounded(values.get("content"))
        if tag == "link":
            self._record_link(values, tag)
        elif tag == "a":
            self._current_anchor = {"href": values.get("href", "").strip(), "text": ""}
            self._record_interface_link(values, tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title" and self._in_title:
            self._in_title = False
            self._title_complete = True
        if tag == "script" and self._in_json_ld:
            document = "".join(self._json_ld_parts).strip()
            if document:
                self.json_ld_documents.append(document[:MAX_JSON_LD_CHARS])
            self._in_json_ld = False
            self._json_ld_parts = []
        if tag == "a" and self._current_anchor is not None:
            href = self._current_anchor["href"]
            text = _bounded(self._current_anchor["text"], limit=MAX_LINK_TEXT_CHARS) or ""
            if (
                href
                and _is_discovery_candidate(href, text)
                and len(self.page_links) < MAX_DISCOVERED_LINKS
            ):
                self.page_links.append(
                    {
                        "href": href[:MAX_TEXT_CHARS],
                        "text": text,
                    }
                )
            self._current_anchor = None

    def handle_data(self, data: str) -> None:
        if self._in_title and sum(map(len, self._title_parts)) < MAX_TEXT_CHARS:
            self._title_parts.append(data)
        if self._in_json_ld and sum(map(len, self._json_ld_parts)) < MAX_JSON_LD_CHARS:
            self._json_ld_parts.append(data)
        if (
            self._current_anchor is not None
            and len(self._current_anchor["text"]) < MAX_LINK_TEXT_CHARS
        ):
            self._current_anchor["text"] += data

    def _record_link(self, values: dict[str, str], tag: str) -> None:
        rels = {part.lower() for part in values.get("rel", "").split()}
        media_type = values.get("type", "").lower().split(";", maxsplit=1)[0]
        href = values.get("href", "").strip()
        if not href:
            return
        if "alternate" in rels and media_type in FEED_TYPES:
            self.feeds.add(href)
        if "canonical" in rels and len(self.canonical_urls) < MAX_DISCOVERED_LINKS:
            self.canonical_urls.append(href)
        if "manifest" in rels and len(self.manifest_urls) < MAX_DISCOVERED_LINKS:
            self.manifest_urls.append(href)
        if (
            "search" in rels
            and media_type == "application/opensearchdescription+xml"
            and len(self.opensearch_urls) < MAX_DISCOVERED_LINKS
        ):
            self.opensearch_urls.append(href)
        self._record_interface_link(values, tag)

    def _record_interface_link(self, values: dict[str, str], tag: str) -> None:
        if len(self.interface_links) >= MAX_DISCOVERED_LINKS:
            return
        href = values.get("href", "").strip()
        if not href:
            return
        rels = {part.lower() for part in values.get("rel", "").split()}
        media_type = values.get("type", "").lower().split(";", maxsplit=1)[0]
        if not _is_interface_candidate(href, rels, media_type):
            return
        self.interface_links.append(
            {
                "href": href[:MAX_TEXT_CHARS],
                "rel": sorted(rels),
                "type": media_type or None,
                "tag": tag,
            }
        )


class MetadataProbe:
    name = "homepage_metadata"

    async def collect(self, context: ProbeContext) -> dict[str, Observation]:
        html = context.shared.get("homepage_html")
        evidence_value = context.shared.get("homepage_evidence")
        evidence = [evidence_value] if isinstance(evidence_value, Evidence) else []
        if not isinstance(html, str):
            return _unknown_metadata(
                "homepage HTML was unavailable",
                evidence,
                outcome=_metadata_unavailable_outcome(context),
            )

        parser = MetadataHTMLParser()
        parser.feed(html)
        response = context.shared.get("homepage_response")
        base_url = (
            response.final_url
            if isinstance(response, FetchResult) and response.final_url
            else context.origin
        )
        feeds = _absolute_urls(base_url, parser.feeds)
        canonical = _first_absolute_url(base_url, parser.canonical_urls)
        manifest = _first_absolute_url(base_url, parser.manifest_urls)
        opensearch = _first_absolute_url(base_url, parser.opensearch_urls)
        interface_links = _absolute_interface_links(base_url, parser.interface_links)
        discovery_links = _classify_discovery_links(base_url, parser.page_links)
        interface_kinds = _classify_interface_links(interface_links)
        json_ld_types, parsed_json_ld = _json_ld_types(parser.json_ld_documents)

        return {
            "metadata.json_ld": _presence(
                parser.has_json_ld, "homepage JSON-LD script tag detection", evidence
            ),
            "metadata.json_ld_types": observation(
                json_ld_types,
                confidence=(
                    Confidence.CONFIRMED
                    if parsed_json_ld
                    else Confidence.UNKNOWN
                    if parser.has_json_ld
                    else Confidence.NO_EVIDENCE
                ),
                score=1.0 if parsed_json_ld or not parser.has_json_ld else 0.0,
                method=(
                    "bounded JSON-LD parsing"
                    if parsed_json_ld
                    else "JSON-LD was present but could not be parsed"
                    if parser.has_json_ld
                    else "no JSON-LD script tag was observed"
                ),
                evidence=evidence,
                outcome=(
                    ObservationOutcome.ERROR if parser.has_json_ld and not parsed_json_ld else None
                ),
            ),
            "metadata.open_graph": _presence(
                parser.has_open_graph, "homepage Open Graph tag detection", evidence
            ),
            "metadata.feeds": observation(
                feeds,
                confidence=Confidence.CONFIRMED if feeds else Confidence.NO_EVIDENCE,
                score=1.0,
                method="homepage alternate-link feed discovery",
                evidence=evidence,
            ),
            "metadata.html_title": _value_or_no_evidence(
                parser.title, "homepage title element", evidence
            ),
            "metadata.html_language": _value_or_no_evidence(
                parser.html_language, "homepage html lang attribute", evidence
            ),
            "metadata.canonical_url": _value_or_no_evidence(
                canonical, "homepage canonical link", evidence
            ),
            "metadata.generator": _value_or_no_evidence(
                parser.generator, "homepage generator meta tag", evidence
            ),
            "metadata.web_manifest_url": _value_or_no_evidence(
                manifest, "homepage web manifest link", evidence
            ),
            "metadata.opensearch_url": _value_or_no_evidence(
                opensearch, "homepage OpenSearch description link", evidence
            ),
            "agent.interface_links": observation(
                interface_links,
                confidence=Confidence.POSSIBLE if interface_links else Confidence.NO_EVIDENCE,
                score=0.6 if interface_links else 1.0,
                method="explicit service relations and strongly named homepage links; not fetched",
                evidence=evidence,
            ),
            **{
                key: observation(
                    urls,
                    confidence=Confidence.POSSIBLE if urls else Confidence.NO_EVIDENCE,
                    score=0.6 if urls else 1.0,
                    method="strongly named public homepage link; candidate was not fetched",
                    evidence=evidence,
                )
                for key, urls in interface_kinds.items()
            },
            **{
                key: observation(
                    links,
                    confidence=Confidence.POSSIBLE if links else Confidence.NO_EVIDENCE,
                    score=0.6 if links else 1.0,
                    method="strongly named homepage link; linked document was not fetched",
                    evidence=evidence,
                )
                for key, links in discovery_links.items()
            },
        }


def _unknown_metadata(
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
            "metadata.json_ld",
            "metadata.json_ld_types",
            "metadata.open_graph",
            "metadata.feeds",
            "metadata.html_title",
            "metadata.html_language",
            "metadata.canonical_url",
            "metadata.generator",
            "metadata.web_manifest_url",
            "metadata.opensearch_url",
            "agent.interface_links",
            "agent.openapi",
            "agent.graphql",
            "agent.oauth_metadata",
            "agent.mcp",
            "agent.a2a",
            "agent.agent_card",
            "agent.api_documentation",
            *DISCOVERY_MARKERS,
        )
    }


def _metadata_unavailable_outcome(context: ProbeContext) -> ObservationOutcome:
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


def _presence(value: bool, method: str, evidence: list[Evidence]) -> Observation:
    return observation(
        value,
        confidence=Confidence.CONFIRMED if value else Confidence.NO_EVIDENCE,
        score=1.0,
        method=method,
        evidence=evidence,
    )


def _value_or_no_evidence(
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


def _absolute_urls(base_url: str, values: Iterable[str]) -> list[str]:
    return sorted({resolved for value in values if (resolved := _http_url(base_url, value))})


def _first_absolute_url(base_url: str, values: list[str]) -> str | None:
    for value in values:
        if resolved := _http_url(base_url, value):
            return resolved
    return None


def _absolute_interface_links(
    base_url: str,
    values: list[dict[str, object]],
) -> list[dict[str, object]]:
    resolved: list[dict[str, object]] = []
    seen: set[str] = set()
    for value in values:
        href = value.get("href")
        if not isinstance(href, str):
            continue
        url = _http_url(base_url, href)
        if url is None:
            continue
        if url in seen:
            continue
        seen.add(url)
        resolved.append({**value, "url": url})
        resolved[-1].pop("href", None)
    return resolved


def _classify_interface_links(values: list[dict[str, object]]) -> dict[str, list[str]]:
    classified: dict[str, list[str]] = {
        "agent.openapi": [],
        "agent.graphql": [],
        "agent.oauth_metadata": [],
        "agent.mcp": [],
        "agent.a2a": [],
        "agent.agent_card": [],
        "agent.api_documentation": [],
    }
    markers = {
        "agent.openapi": ("openapi", "swagger"),
        "agent.graphql": ("graphql",),
        "agent.oauth_metadata": ("oauth", "openid-configuration"),
        "agent.mcp": ("/mcp", "model-context-protocol"),
        "agent.a2a": ("/a2a", "agent2agent"),
        "agent.agent_card": ("agent-card", "agent.json", "/.well-known/agent"),
        "agent.api_documentation": ("api-docs", "developer", "openapi", "swagger"),
    }
    for value in values:
        url = value.get("url")
        media_type = value.get("type")
        if not isinstance(url, str):
            continue
        haystack = f"{url} {media_type if isinstance(media_type, str) else ''}".lower()
        for key, candidates in markers.items():
            if any(candidate in haystack for candidate in candidates):
                classified[key].append(url)
    return {key: sorted(set(urls)) for key, urls in classified.items()}


def _classify_discovery_links(
    base_url: str,
    values: list[dict[str, str]],
) -> dict[str, list[dict[str, str]]]:
    classified: dict[str, list[dict[str, str]]] = {key: [] for key in DISCOVERY_MARKERS}
    seen: dict[str, set[str]] = {key: set() for key in DISCOVERY_MARKERS}
    for value in values:
        url = _http_url(base_url, value["href"])
        if url is None:
            continue
        text = _bounded(value.get("text"), limit=MAX_LINK_TEXT_CHARS) or ""
        haystack = f"{urlsplit(url).path} {text}".lower().replace("_", "-")
        for key, markers in DISCOVERY_MARKERS.items():
            if url in seen[key] or not any(
                _contains_marker(haystack, marker) for marker in markers
            ):
                continue
            seen[key].add(url)
            classified[key].append({"url": url, "text": text})
    return classified


def _is_discovery_candidate(href: str, text: str) -> bool:
    haystack = f"{urlsplit(href).path} {text}".lower().replace("_", "-")
    return any(
        _contains_marker(haystack, marker)
        for markers in DISCOVERY_MARKERS.values()
        for marker in markers
    )


def _contains_marker(haystack: str, marker: str) -> bool:
    tokens = set(re.findall(r"[a-z0-9]+", haystack))
    marker_tokens = re.findall(r"[a-z0-9]+", marker)
    if len(marker_tokens) == 1:
        return marker_tokens[0] in tokens
    normalized = "-".join(re.findall(r"[a-z0-9]+", haystack))
    return "-".join(marker_tokens) in normalized


def _json_ld_types(documents: list[str]) -> tuple[list[str], bool]:
    types: set[str] = set()
    parsed_any = False

    for document in documents:
        try:
            payload = json.loads(document)
        except (json.JSONDecodeError, RecursionError):
            continue
        parsed_any = True
        stack = [payload]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                item_type = value.get("@type")
                if isinstance(item_type, str):
                    types.add(item_type[:MAX_TEXT_CHARS])
                elif isinstance(item_type, list):
                    types.update(
                        item[:MAX_TEXT_CHARS] for item in item_type if isinstance(item, str)
                    )
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
    return sorted(types), parsed_any


def _is_interface_candidate(href: str, rels: set[str], media_type: str) -> bool:
    if rels & INTERFACE_RELS or media_type in INTERFACE_MEDIA_TYPES:
        return True
    path = urlsplit(href).path.lower()
    markers = (
        "/api-docs",
        "/a2a",
        "/graphql",
        "/mcp",
        "/oauth",
        "/openapi",
        "/swagger",
        "/.well-known/agent",
        "/.well-known/mcp",
        "/.well-known/oauth",
        "/.well-known/openid-configuration",
    )
    return any(marker in path for marker in markers)


def _http_url(base_url: str, value: str) -> str | None:
    resolved = urljoin(base_url, value)
    parsed = urlsplit(resolved)
    if (
        parsed.scheme in {"http", "https"}
        and parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None
    ):
        return resolved
    return None


def _bounded(value: str | None, *, limit: int = MAX_TEXT_CHARS) -> str | None:
    if value is None:
        return None
    normalized = " ".join(value.split())
    return normalized[:limit] or None
