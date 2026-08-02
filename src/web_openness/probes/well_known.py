from urllib.parse import urljoin

from web_openness.models import Confidence, Observation, ObservationOutcome, ProbeError
from web_openness.probes.base import ProbeContext, evidence_from_fetch, observation
from web_openness.probes.robots import policy_allows


class WellKnownProbe:
    name = "well_known"

    async def collect(self, context: ProbeContext) -> dict[str, Observation]:
        url = urljoin(f"{context.origin}/", "llms.txt")
        if not policy_allows(context, url):
            return {
                "metadata.llms_txt_exists": observation(
                    None,
                    confidence=Confidence.UNKNOWN,
                    score=0.0,
                    method="skipped because crawler policy was not affirmatively allowed",
                    outcome=ObservationOutcome.SKIPPED,
                )
            }

        result = await context.client.get(url)
        evidence = [evidence_from_fetch(result)]
        if result.error is not None:
            context.errors.append(ProbeError(probe=self.name, message=result.error))
            return {
                "metadata.llms_txt_exists": observation(
                    None,
                    confidence=Confidence.UNKNOWN,
                    score=0.0,
                    method="llms.txt fetch failed",
                    evidence=evidence,
                )
            }

        exists = result.status_code == 200 and bool(result.body.strip())
        return {
            "metadata.llms_txt_exists": observation(
                exists,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="public llms.txt HTTP response",
                evidence=evidence,
            ),
            "metadata.llms_txt_status": observation(
                result.status_code,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="HTTP status",
                evidence=evidence,
            ),
        }
