from datetime import UTC, datetime

from web_openness.models import Confidence, ObservationOutcome, RequestRecord
from web_openness.probes.http_attempts import summarize_http_attempts


def _record(status: int | None) -> RequestRecord:
    return RequestRecord(
        requested_url="https://example.org/",
        started_at=datetime.now(UTC),
        elapsed_ms=1,
        status_code=status,
        response_bytes=0,
    )


def test_summarizes_statuses_and_block_frequencies() -> None:
    values = summarize_http_attempts(
        [_record(200), _record(403), _record(429), _record(429), _record(None)]
    )

    assert values["crawler.http_status_distribution"].value == {
        "200": 1,
        "403": 1,
        "429": 2,
    }
    assert values["crawler.http_403_frequency"].value == {
        "count": 1,
        "response_count": 4,
        "rate": 0.25,
    }
    assert values["crawler.http_429_frequency"].value == {
        "count": 2,
        "response_count": 4,
        "rate": 0.5,
    }


def test_no_response_status_is_not_reported_as_a_zero_rate() -> None:
    values = summarize_http_attempts([_record(None)])

    assert all(value.value is None for value in values.values())
    assert all(value.confidence == Confidence.NO_EVIDENCE for value in values.values())
    assert all(value.outcome == ObservationOutcome.NO_EVIDENCE for value in values.values())
