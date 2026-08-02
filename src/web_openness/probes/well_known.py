from urllib.parse import urljoin

from web_openness.models import Confidence, Evidence, Observation, ObservationOutcome, ProbeError
from web_openness.probes.base import ProbeContext, evidence_from_fetch, observation
from web_openness.probes.robots import policy_allows

LLMS_TXT_KEYS = ("metadata.llms_txt_exists", "metadata.llms_txt_status")


class WellKnownProbe:
    name = "well_known"

    async def collect(self, context: ProbeContext) -> dict[str, Observation]:
        url = urljoin(f"{context.origin}/", "llms.txt")
        if not policy_allows(context, url):
            return _unavailable_llms_txt(
                "skipped because crawler policy was not affirmatively allowed",
                outcome=ObservationOutcome.SKIPPED,
            )

        result = await context.client.get(url)
        evidence = [evidence_from_fetch(result)]
        if result.error is not None:
            context.errors.append(ProbeError(probe=self.name, message=result.error))
            return _unavailable_llms_txt("llms.txt fetch failed", evidence=evidence)

        status = result.status_code
        values = {
            "metadata.llms_txt_status": observation(
                status,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="HTTP status",
                evidence=evidence,
            ),
        }
        if status == 200:
            values["metadata.llms_txt_exists"] = observation(
                True,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="llms.txt returned HTTP 200",
                evidence=evidence,
            )
        elif status in {404, 410}:
            values["metadata.llms_txt_exists"] = observation(
                False,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="llms.txt returned a not-found status",
                evidence=evidence,
            )
        else:
            values["metadata.llms_txt_exists"] = observation(
                None,
                confidence=Confidence.NO_EVIDENCE,
                score=0.0,
                method="llms.txt returned an inconclusive status",
                evidence=evidence,
            )
        return values


def _unavailable_llms_txt(
    method: str,
    *,
    evidence: list[Evidence] | None = None,
    outcome: ObservationOutcome = ObservationOutcome.ERROR,
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
        for key in LLMS_TXT_KEYS
    }
