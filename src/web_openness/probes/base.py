from dataclasses import dataclass, field
from typing import Protocol

from web_openness.client import FetchResult, SiteClient
from web_openness.config import ScanConfig
from web_openness.models import (
    Confidence,
    Evidence,
    Observation,
    ObservationOutcome,
    ProbeError,
    RequestRecord,
)


@dataclass(slots=True)
class ProbeContext:
    domain: str
    origin: str
    config: ScanConfig
    client: SiteClient
    shared: dict[str, object] = field(default_factory=dict)
    errors: list[ProbeError] = field(default_factory=list)


class Probe(Protocol):
    name: str

    async def collect(self, context: ProbeContext) -> dict[str, Observation]: ...


def evidence_from_fetch(result: FetchResult, *, note: str | None = None) -> Evidence:
    record = result.evidence
    return Evidence(
        source_url=result.final_url or record.final_url or result.requested_url,
        observed_at=record.started_at,
        http_status=record.status_code,
        content_sha256=record.content_sha256,
        note=note,
    )


def evidence_from_request(record: RequestRecord, *, note: str | None = None) -> Evidence:
    return Evidence(
        source_url=record.final_url or record.requested_url,
        observed_at=record.started_at,
        http_status=record.status_code,
        content_sha256=record.content_sha256,
        note=note,
    )


def observation(
    value: object,
    *,
    confidence: Confidence,
    score: float,
    method: str,
    evidence: list[Evidence] | None = None,
    outcome: ObservationOutcome | None = None,
) -> Observation:
    if outcome is None:
        if confidence == Confidence.NO_EVIDENCE:
            outcome = ObservationOutcome.NO_EVIDENCE
        elif confidence == Confidence.UNKNOWN:
            outcome = ObservationOutcome.ERROR
        else:
            outcome = ObservationOutcome.OBSERVED
    return Observation(
        value=value,
        outcome=outcome,
        confidence=confidence,
        confidence_score=score,
        method=method,
        evidence=evidence or [],
    )


def mark_absences_inconclusive(
    observations: dict[str, Observation],
    *,
    method: str,
    evidence: list[Evidence],
) -> dict[str, Observation]:
    """Retain positive findings but invalidate absences from an incomplete source."""

    return {
        key: (
            observation(
                None,
                confidence=Confidence.UNKNOWN,
                score=0.0,
                method=method,
                evidence=evidence,
                outcome=ObservationOutcome.ERROR,
            )
            if value.outcome == ObservationOutcome.NO_EVIDENCE
            else value
        )
        for key, value in observations.items()
    }
