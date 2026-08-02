import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from web_openness.config import ScanConfig
from web_openness.models import (
    Confidence,
    DomainSnapshot,
    Observation,
    ObservationOutcome,
    ProbeError,
)
from web_openness.smoke import (
    SignalStatus,
    collect_smoke_run,
    load_targets,
    render_markdown,
    write_run_reports,
)


def _observation(
    value: object,
    *,
    confidence: Confidence = Confidence.CONFIRMED,
    outcome: ObservationOutcome = ObservationOutcome.OBSERVED,
    method: str = "offline fixture",
) -> Observation:
    return Observation(
        value=value,
        outcome=outcome,
        confidence=confidence,
        confidence_score=1.0 if confidence == Confidence.CONFIRMED else 0.0,
        method=method,
    )


def _snapshot(domain: str) -> DomainSnapshot:
    timestamp = datetime.now(UTC)
    return DomainSnapshot(
        run_id=str(uuid4()),
        domain=domain,
        origin=f"https://{domain}",
        started_at=timestamp,
        completed_at=timestamp,
        collector_version="test",
        request_count=2,
        observations={
            "crawler.robots_exists": _observation(False),
            "human.homepage_accessible": _observation(
                None,
                confidence=Confidence.UNKNOWN,
                outcome=ObservationOutcome.ERROR,
                method="opaque fixture state",
            ),
            "metadata.llms_txt_exists": _observation(
                None,
                confidence=Confidence.NO_EVIDENCE,
                outcome=ObservationOutcome.NO_EVIDENCE,
                method="public file was not observed",
            ),
        },
        requests=[],
        errors=[ProbeError(probe="homepage", message="offline fixture failure")],
    )


@pytest.mark.asyncio
async def test_smoke_run_is_bounded_and_writes_individual_snapshots(tmp_path: Path) -> None:
    active = 0
    maximum_active = 0

    async def scan(target: str) -> DomainSnapshot:
        nonlocal active, maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        await asyncio.sleep(0.01)
        active -= 1
        return _snapshot(target)

    run = await collect_smoke_run(
        ["one.example", "two.example", "three.example"],
        config=ScanConfig(request_delay_seconds=0),
        snapshot_root=tmp_path / "snapshots",
        concurrency=2,
        scan=scan,
    )

    assert maximum_active == 2
    assert [domain.domain for domain in run.domains] == [
        "one.example",
        "two.example",
        "three.example",
    ]
    assert all(Path(domain.snapshot_path or "").exists() for domain in run.domains)
    first = run.domains[0]
    assert first.signals["crawler.robots_exists"].status == SignalStatus.COLLECTED
    assert first.signals["human.homepage_accessible"].status == SignalStatus.ERROR
    assert first.signals["metadata.llms_txt_exists"].status == SignalStatus.NO_EVIDENCE
    assert first.signals["infrastructure.cdn"].status == SignalStatus.SKIPPED
    assert first.signals["preservation.cache_header_hints"].status == SignalStatus.SKIPPED
    assert first.signals["preservation.cache_behavior"].status == (SignalStatus.NOT_YET_SUPPORTED)


@pytest.mark.asyncio
async def test_smoke_run_preserves_top_level_failure(tmp_path: Path) -> None:
    async def scan(_target: str) -> DomainSnapshot:
        raise ValueError("bad target")

    run = await collect_smoke_run(
        ["not a target"],
        config=ScanConfig(request_delay_seconds=0),
        snapshot_root=tmp_path,
        scan=scan,
    )

    result = run.domains[0]
    assert result.domain is None
    assert result.snapshot_path is None
    assert result.errors == ("ValueError: bad target",)
    assert result.signals["crawler.robots_exists"].status == SignalStatus.ERROR
    assert result.signals["agent.mcp"].status == SignalStatus.ERROR
    assert result.signals["human.paywall_detected"].status == (SignalStatus.NOT_YET_SUPPORTED)


def test_reports_are_machine_readable_and_human_readable(tmp_path: Path) -> None:
    run = asyncio.run(
        collect_smoke_run(
            ["example.org"],
            config=ScanConfig(request_delay_seconds=0),
            snapshot_root=tmp_path / "snapshots",
            scan=lambda _target: asyncio.sleep(0, result=_snapshot("example.org")),
        )
    )

    json_path, markdown_path = write_run_reports(run, tmp_path / "runs")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = markdown_path.read_text(encoding="utf-8")

    assert run.completed_at.date().isoformat() in str(json_path)
    assert payload["report_version"] == "0.2.0"
    assert payload["run_id"] == run.run_id
    assert payload["domain_count"] == 1
    assert payload["request_count"] == 2
    assert payload["status_counts"]["not_yet_supported"] > 0
    assert "## Diagnostic gaps" in markdown
    assert "## Selected findings" in markdown
    assert "1 scan notes" in markdown
    assert "homepage: offline fixture failure" in markdown
    assert "`infrastructure.cdn`" in markdown
    assert render_markdown(run) == markdown


def test_load_targets_ignores_comments_blanks_and_duplicates(tmp_path: Path) -> None:
    path = tmp_path / "domains.txt"
    path.write_text(
        "# canaries\nexample.org\n\nexample.net # note\nexample.org\n",
        encoding="utf-8",
    )

    assert load_targets(path) == ["example.org", "example.net"]
