from urllib.parse import urljoin

from web_openness.models import Confidence, Observation, ObservationOutcome, ProbeError
from web_openness.probes.base import ProbeContext, evidence_from_fetch, observation


class HomepageProbe:
    name = "homepage"

    async def collect(self, context: ProbeContext) -> dict[str, Observation]:
        allowed = context.shared.get("robots_allows_followup")
        if allowed is not True:
            return {
                "human.homepage_accessible": observation(
                    None,
                    confidence=Confidence.UNKNOWN,
                    score=0.0,
                    method="skipped because crawler policy was not affirmatively allowed",
                    outcome=ObservationOutcome.SKIPPED,
                )
            }

        url = urljoin(f"{context.origin}/", "/")
        result = await context.client.get(url)
        context.shared["homepage_response"] = result
        evidence = [evidence_from_fetch(result)]
        if result.error is not None:
            context.errors.append(ProbeError(probe=self.name, message=result.error))
            return {
                "human.homepage_accessible": observation(
                    None,
                    confidence=Confidence.UNKNOWN,
                    score=0.0,
                    method="homepage fetch failed",
                    evidence=evidence,
                )
            }

        status = result.status_code
        accessible = status is not None and 200 <= status < 400
        context.shared["homepage_evidence"] = evidence[0]
        content_type = result.headers.get("content-type", "").lower()
        if (
            status is not None
            and 200 <= status < 300
            and ("text/html" in content_type or "application/xhtml+xml" in content_type)
        ):
            context.shared["homepage_html"] = result.text

        return {
            "human.homepage_accessible": observation(
                accessible,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="HTTP response status; browser validation not yet applied",
                evidence=evidence,
            ),
            "human.homepage_status": observation(
                status,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="HTTP status",
                evidence=evidence,
            ),
            "human.homepage_final_url": observation(
                result.final_url,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="HTTP redirect resolution",
                evidence=evidence,
            ),
            "human.homepage_content_type": observation(
                result.headers.get("content-type"),
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="HTTP response header",
                evidence=evidence,
            ),
        }
