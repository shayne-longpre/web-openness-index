from collections import Counter
from collections.abc import Iterable

from web_openness.models import Confidence, Evidence, Observation, RequestRecord
from web_openness.probes.base import evidence_from_request, observation


def summarize_http_attempts(records: Iterable[RequestRecord]) -> dict[str, Observation]:
    """Summarize status evidence already collected by the scan."""

    responses = tuple(record for record in records if record.status_code is not None)
    if not responses:
        return {
            key: observation(
                None,
                confidence=Confidence.NO_EVIDENCE,
                score=1.0,
                method="no HTTP response status was observed during the scan",
            )
            for key in (
                "crawler.http_status_distribution",
                "crawler.http_403_frequency",
                "crawler.http_429_frequency",
            )
        }

    counts = Counter(record.status_code for record in responses)
    evidence = [
        evidence_from_request(
            record,
            note="HTTP attempt included in the scan-level status summary",
        )
        for record in responses
    ]
    response_count = len(responses)

    return {
        "crawler.http_status_distribution": observation(
            {str(status): count for status, count in sorted(counts.items())},
            confidence=Confidence.CONFIRMED,
            score=1.0,
            method="status distribution across all HTTP responses in this scan",
            evidence=evidence,
        ),
        "crawler.http_403_frequency": _frequency_observation(
            403,
            counts[403],
            response_count,
            evidence,
        ),
        "crawler.http_429_frequency": _frequency_observation(
            429,
            counts[429],
            response_count,
            evidence,
        ),
    }


def _frequency_observation(
    status: int,
    count: int,
    response_count: int,
    evidence: list[Evidence],
) -> Observation:
    return observation(
        {
            "count": count,
            "response_count": response_count,
            "rate": count / response_count,
        },
        confidence=Confidence.CONFIRMED,
        score=1.0,
        method=f"HTTP {status} responses divided by all HTTP responses in this scan",
        evidence=evidence,
    )
