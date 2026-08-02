import asyncio
import json
from collections import Counter
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

from web_openness.config import ScanConfig
from web_openness.models import DomainSnapshot, Observation, ObservationOutcome
from web_openness.pipeline import Scanner
from web_openness.storage import write_snapshot

SMOKE_REPORT_VERSION = "0.2.0"


class SignalStatus(StrEnum):
    COLLECTED = "collected"
    NO_EVIDENCE = "no_evidence"
    SKIPPED = "skipped"
    ERROR = "error"
    NOT_YET_SUPPORTED = "not_yet_supported"


@dataclass(frozen=True, slots=True)
class SignalSpec:
    key: str
    implemented: bool


# This short catalog is a coverage checklist, not a scoring model. Observations emitted
# by newer probes are included automatically even when they are not listed here.
SIGNAL_CATALOG: tuple[SignalSpec, ...] = tuple(
    SignalSpec(key, True)
    for key in (
        "network.dns_resolved",
        "network.dns_addresses",
        "network.dns_address_count",
        "network.dns_ip_families",
        "network.dns_addresses_truncated",
        "network.tls_handshake",
        "network.tls_version",
        "network.tls_cipher",
        "network.tls_certificate_not_before",
        "network.tls_certificate_not_after",
        "network.tls_certificate_issuer",
        "network.tls_certificate_verified",
        "network.http_version",
        "infrastructure.response_headers",
        "infrastructure.server_header",
        "infrastructure.security_headers",
        "infrastructure.cache_headers",
        "infrastructure.cdn_hints",
        "infrastructure.cdn",
        "crawler.robots_exists",
        "crawler.robots_status",
        "crawler.user_agents",
        "crawler.ai_specific_user_agents",
        "crawler.ai_homepage_policies",
        "crawler.crawl_delays",
        "crawler.sitemaps",
        "crawler.homepage_policy_allowed",
        "human.homepage_accessible",
        "human.homepage_status",
        "human.homepage_final_url",
        "human.homepage_content_type",
        "human.http_access_disposition",
        "human.authentication_challenge",
        "human.login_required",
        "human.rate_limited",
        "preservation.cache_header_hints",
        "metadata.sitemap_exists",
        "metadata.sitemap_status",
        "metadata.sitemap_document_type",
        "metadata.sitemap_url_count",
        "metadata.sitemap_child_sitemap_count",
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
        "legal.policy_links",
        "legal.license_links",
        "economic.pricing_links",
        "economic.registration_links",
        "metadata.llms_txt_exists",
        "metadata.llms_txt_status",
    )
) + tuple(
    SignalSpec(key, False)
    for key in (
        "infrastructure.waf",
        "infrastructure.dns_provider",
        "infrastructure.hosting_provider",
        "human.paywall_detected",
        "human.cookie_wall_detected",
        "human.captcha_detected",
        "human.javascript_required",
        "crawler.browser_http_difference",
        "legal.scraping_restrictions",
        "legal.ai_restrictions",
        "legal.license",
        "economic.registration_required",
        "economic.metering",
        "economic.subscription_required",
        "economic.api_pricing",
        "preservation.archive_coverage",
        "preservation.archive_blocked",
        "preservation.cache_behavior",
    )
)

ScanCallable = Callable[[str], Awaitable[DomainSnapshot]]


@dataclass(frozen=True, slots=True)
class SignalResult:
    status: SignalStatus
    value: object = None
    method: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "value": self.value,
            "method": self.method,
        }


@dataclass(frozen=True, slots=True)
class DomainResult:
    target: str
    domain: str | None
    snapshot_path: str | None
    request_count: int
    errors: tuple[str, ...]
    signals: Mapping[str, SignalResult]

    def as_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "domain": self.domain,
            "snapshot_path": self.snapshot_path,
            "request_count": self.request_count,
            "errors": list(self.errors),
            "signals": {key: result.as_dict() for key, result in self.signals.items()},
        }


@dataclass(frozen=True, slots=True)
class SmokeRun:
    run_id: str
    started_at: datetime
    completed_at: datetime
    concurrency: int
    domains: tuple[DomainResult, ...]

    @property
    def status_counts(self) -> Counter[SignalStatus]:
        return Counter(
            signal.status for domain in self.domains for signal in domain.signals.values()
        )

    def as_dict(self) -> dict[str, object]:
        counts = self.status_counts
        return {
            "report_version": SMOKE_REPORT_VERSION,
            "run_id": self.run_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "concurrency": self.concurrency,
            "domain_count": len(self.domains),
            "request_count": sum(domain.request_count for domain in self.domains),
            "status_counts": {status.value: counts[status] for status in SignalStatus},
            "domains": [domain.as_dict() for domain in self.domains],
        }


async def collect_smoke_run(
    targets: Iterable[str],
    *,
    config: ScanConfig,
    snapshot_root: Path,
    concurrency: int = 3,
    scan: ScanCallable | None = None,
) -> SmokeRun:
    """Scan an explicit target set with bounded cross-domain concurrency."""

    normalized_targets = tuple(target.strip() for target in targets if target.strip())
    if not normalized_targets:
        raise ValueError("smoke run requires at least one target")
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")

    scanner = Scanner(config)
    if scanner.cease_list.domains:
        for target in normalized_targets:
            scanner.require_target_allowed(target)
    scan_target = scan or scanner.scan
    semaphore = asyncio.Semaphore(concurrency)
    started_at = datetime.now(UTC)

    async def collect_one(target: str) -> DomainResult:
        async with semaphore:
            try:
                snapshot = await scan_target(target)
                snapshot_path = write_snapshot(snapshot, snapshot_root)
            except Exception as exc:  # Preserve failures in the diagnostic report.
                return _failed_domain(target, exc)
            return _domain_result(target, snapshot, snapshot_path)

    domains = tuple(await asyncio.gather(*(collect_one(target) for target in normalized_targets)))
    return SmokeRun(
        run_id=str(uuid4()),
        started_at=started_at,
        completed_at=datetime.now(UTC),
        concurrency=concurrency,
        domains=domains,
    )


def load_targets(path: Path) -> list[str]:
    """Read one target per line, ignoring blanks/comments and preserving order."""

    targets: list[str] = []
    seen: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        target = raw_line.split("#", maxsplit=1)[0].strip()
        if target and target not in seen:
            seen.add(target)
            targets.append(target)
    return targets


def write_run_reports(run: SmokeRun, root: Path) -> tuple[Path, Path]:
    """Write immutable machine-readable and compact human-readable run reports."""

    partition = root / run.completed_at.date().isoformat()
    json_path = partition / f"{run.run_id}.json"
    markdown_path = partition / f"{run.run_id}.md"
    _write_new(json_path, f"{json.dumps(run.as_dict(), indent=2, default=str)}\n")
    _write_new(markdown_path, render_markdown(run))
    return json_path, markdown_path


def render_markdown(run: SmokeRun) -> str:
    counts = run.status_counts
    failed_domains = sum(domain.domain is None for domain in run.domains)
    scan_notes = sum(len(domain.errors) for domain in run.domains)
    lines = [
        f"# Smoke run `{run.run_id}`",
        "",
        (
            f"Scanned {len(run.domains)} domains with concurrency {run.concurrency}; "
            f"made {sum(domain.request_count for domain in run.domains)} requests and "
            f"had {failed_domains} top-level failures and {scan_notes} scan notes."
        ),
        "",
        "## Domain results",
        "",
        "| Domain | Requests | Collected | No evidence | Skipped | Signal errors | "
        "Scan notes | Snapshot |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    for domain in run.domains:
        domain_counts = Counter(signal.status for signal in domain.signals.values())
        label = domain.domain or domain.target
        snapshot = domain.snapshot_path or "—"
        lines.append(
            f"| {label} | {domain.request_count} | "
            f"{domain_counts[SignalStatus.COLLECTED]} | "
            f"{domain_counts[SignalStatus.NO_EVIDENCE]} | "
            f"{domain_counts[SignalStatus.SKIPPED]} | "
            f"{domain_counts[SignalStatus.ERROR]} | {_display_errors(domain.errors)} | "
            f"{snapshot} |"
        )

    lines.extend(
        [
            "",
            "## Selected findings",
            "",
            "| Domain | Homepage | Robots | AI policies | Sitemap | Feeds | Interfaces | "
            "CDN hints | TLS | HTTP |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for domain in run.domains:
        label = domain.domain or domain.target
        lines.append(
            f"| {label} | "
            f"{_display_signal(domain, 'human.homepage_accessible')} | "
            f"{_display_signal(domain, 'crawler.robots_exists')} | "
            f"{_display_signal(domain, 'crawler.ai_homepage_policies')} | "
            f"{_display_signal(domain, 'metadata.sitemap_exists')} | "
            f"{_display_signal(domain, 'metadata.feeds')} | "
            f"{_display_signal(domain, 'agent.interface_links')} | "
            f"{_display_signal(domain, 'infrastructure.cdn_hints')} | "
            f"{_display_signal(domain, 'network.tls_version')} | "
            f"{_display_signal(domain, 'network.http_version')} |"
        )

    lines.extend(
        [
            "",
            "## Coverage",
            "",
            "| Status | Domain-signal results |",
            "| --- | ---: |",
        ]
    )
    for status in SignalStatus:
        lines.append(f"| {status.value} | {counts[status]} |")

    no_evidence = _key_status_counts(run, SignalStatus.NO_EVIDENCE)
    skipped = _key_status_counts(run, SignalStatus.SKIPPED)
    errors = _key_status_counts(run, SignalStatus.ERROR)
    unsupported = _key_status_counts(run, SignalStatus.NOT_YET_SUPPORTED)
    lines.extend(
        [
            "",
            "## Diagnostic gaps",
            "",
            f"- No evidence: {_format_key_counts(no_evidence, len(run.domains))}",
            f"- Skipped: {_format_key_counts(skipped, len(run.domains))}",
            f"- Errors: {_format_key_counts(errors, len(run.domains))}",
            f"- Not yet supported: {_format_key_counts(unsupported, len(run.domains))}",
            "",
        ]
    )
    return "\n".join(lines)


def _domain_result(target: str, snapshot: DomainSnapshot, path: Path) -> DomainResult:
    specs = {spec.key: spec for spec in SIGNAL_CATALOG}
    keys = list(specs)
    keys.extend(sorted(snapshot.observations.keys() - specs.keys()))
    signals: dict[str, SignalResult] = {}
    for key in keys:
        observation = snapshot.observations.get(key)
        if observation is not None:
            signals[key] = _classify_observation(observation)
        elif specs[key].implemented:
            signals[key] = SignalResult(SignalStatus.SKIPPED)
        else:
            signals[key] = SignalResult(SignalStatus.NOT_YET_SUPPORTED)

    return DomainResult(
        target=target,
        domain=snapshot.domain,
        snapshot_path=str(path),
        request_count=snapshot.request_count,
        errors=tuple(f"{error.probe}: {error.message}" for error in snapshot.errors),
        signals=signals,
    )


def _classify_observation(observation: Observation) -> SignalResult:
    status = {
        ObservationOutcome.OBSERVED: SignalStatus.COLLECTED,
        ObservationOutcome.NO_EVIDENCE: SignalStatus.NO_EVIDENCE,
        ObservationOutcome.SKIPPED: SignalStatus.SKIPPED,
        ObservationOutcome.ERROR: SignalStatus.ERROR,
    }[observation.outcome]
    return SignalResult(status=status, value=observation.value, method=observation.method)


def _failed_domain(target: str, exc: Exception) -> DomainResult:
    signals = {
        spec.key: SignalResult(
            SignalStatus.ERROR if spec.implemented else SignalStatus.NOT_YET_SUPPORTED
        )
        for spec in SIGNAL_CATALOG
    }
    return DomainResult(
        target=target,
        domain=None,
        snapshot_path=None,
        request_count=0,
        errors=(f"{type(exc).__name__}: {exc}",),
        signals=signals,
    )


def _key_status_counts(run: SmokeRun, status: SignalStatus) -> Counter[str]:
    return Counter(
        key
        for domain in run.domains
        for key, signal in domain.signals.items()
        if signal.status == status
    )


def _format_key_counts(counts: Counter[str], domain_count: int) -> str:
    if not counts:
        return "none"
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return ", ".join(f"`{key}` ({count}/{domain_count})" for key, count in ordered)


def _display_signal(domain: DomainResult, key: str) -> str:
    signal = domain.signals.get(key)
    if signal is None:
        return "—"
    if signal.status != SignalStatus.COLLECTED:
        return signal.status.value.replace("_", " ")
    value = json.dumps(signal.value, separators=(",", ":"), default=str)
    return value if len(value) <= 40 else f"{value[:37]}..."


def _display_errors(errors: tuple[str, ...]) -> str:
    if not errors:
        return "—"
    value = "; ".join(error.replace("|", "\\|") for error in errors)
    return value if len(value) <= 80 else f"{value[:77]}..."


def _write_new(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        handle.write(content)
