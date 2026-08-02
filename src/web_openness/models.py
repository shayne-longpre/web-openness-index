from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION: Literal["0.2.0"] = "0.2.0"


class ContractModel(BaseModel):
    """Base for persisted models: unknown fields must never disappear silently."""

    model_config = ConfigDict(extra="forbid")


class Confidence(StrEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    NO_EVIDENCE = "no_evidence"
    UNKNOWN = "unknown"


class ObservationOutcome(StrEnum):
    """Collection outcome, separate from confidence in an observed value."""

    OBSERVED = "observed"
    NO_EVIDENCE = "no_evidence"
    SKIPPED = "skipped"
    ERROR = "error"


class Evidence(ContractModel):
    source_url: str
    observed_at: datetime
    http_status: int | None = None
    content_sha256: str | None = None
    note: str | None = None


class Observation(ContractModel):
    value: Any
    outcome: ObservationOutcome
    confidence: Confidence
    confidence_score: float = Field(ge=0.0, le=1.0)
    method: str
    evidence: list[Evidence] = Field(default_factory=list)

    @model_validator(mode="after")
    def outcome_matches_confidence(self) -> "Observation":
        expected = {
            ObservationOutcome.OBSERVED: {
                Confidence.CONFIRMED,
                Confidence.LIKELY,
                Confidence.POSSIBLE,
            },
            ObservationOutcome.NO_EVIDENCE: {Confidence.NO_EVIDENCE},
            ObservationOutcome.SKIPPED: {Confidence.UNKNOWN},
            ObservationOutcome.ERROR: {Confidence.UNKNOWN},
        }
        if self.confidence not in expected[self.outcome]:
            raise ValueError(
                f"outcome {self.outcome.value!r} is inconsistent with "
                f"confidence {self.confidence.value!r}"
            )
        return self


class RequestRecord(ContractModel):
    requested_url: str
    final_url: str | None = None
    started_at: datetime
    elapsed_ms: float = Field(ge=0.0)
    status_code: int | None = None
    response_bytes: int = Field(ge=0)
    response_truncated: bool = False
    content_sha256: str | None = None
    error: str | None = None


class ProbeError(ContractModel):
    probe: str
    message: str


class DomainSnapshot(ContractModel):
    schema_version: Literal["0.2.0"] = SCHEMA_VERSION
    run_id: str
    domain: str
    origin: str
    started_at: datetime
    completed_at: datetime
    collector_version: str
    request_count: int = Field(ge=0)
    observations: dict[str, Observation]
    requests: list[RequestRecord]
    errors: list[ProbeError] = Field(default_factory=list)
