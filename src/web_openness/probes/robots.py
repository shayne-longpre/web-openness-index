from dataclasses import dataclass
from urllib.parse import urljoin

from protego import Protego

from web_openness.models import Confidence, Observation, ProbeError
from web_openness.probes.base import ProbeContext, evidence_from_fetch, observation

KNOWN_AI_AGENTS = {
    "amazonbot",
    "anthropic-ai",
    "bytespider",
    "ccbot",
    "chatgpt-user",
    "claude-web",
    "cohere-ai",
    "google-extended",
    "gptbot",
    "meta-externalagent",
    "perplexitybot",
}


@dataclass(frozen=True, slots=True)
class ParsedRobots:
    user_agents: tuple[str, ...]
    ai_user_agents: tuple[str, ...]
    crawl_delays: dict[str, str]
    sitemaps: tuple[str, ...]
    policy: Protego


def _declared_user_agents(text: str) -> set[str]:
    """Extract declaration names for evidence; Protego owns policy evaluation."""

    user_agents: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.split("#", maxsplit=1)[0].strip()
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() == "user-agent" and value.strip():
            user_agents.add(value.strip().lower())
    return user_agents


def _format_crawl_delay(delay: float) -> str:
    return f"{delay:g}"


def parse_robots(text: str) -> ParsedRobots:
    policy = Protego.parse(text)
    user_agents = _declared_user_agents(text)
    crawl_delays = {
        agent: _format_crawl_delay(delay)
        for agent in user_agents
        if (delay := policy.crawl_delay(agent)) is not None
    }

    ai_user_agents = tuple(sorted(user_agents & KNOWN_AI_AGENTS))
    return ParsedRobots(
        user_agents=tuple(sorted(user_agents)),
        ai_user_agents=ai_user_agents,
        crawl_delays=dict(sorted(crawl_delays.items())),
        sitemaps=tuple(sorted(set(policy.sitemaps))),
        policy=policy,
    )


class RobotsProbe:
    name = "robots"

    async def collect(self, context: ProbeContext) -> dict[str, Observation]:
        url = urljoin(f"{context.origin}/", "robots.txt")
        result = await context.client.get(url)
        evidence = [evidence_from_fetch(result)]
        status = result.status_code

        if result.error is not None:
            context.shared["robots_allows_followup"] = False
            context.errors.append(ProbeError(probe=self.name, message=result.error))
            return {
                "crawler.robots_exists": observation(
                    None,
                    confidence=Confidence.UNKNOWN,
                    score=0.0,
                    method="robots.txt fetch failed",
                    evidence=evidence,
                )
            }

        if status in {404, 410}:
            await context.client.set_domain_delay(url, context.config.request_delay_seconds)
            context.shared["robots_allows_followup"] = True
            return {
                "crawler.robots_exists": observation(
                    False,
                    confidence=Confidence.CONFIRMED,
                    score=1.0,
                    method="robots.txt returned a not-found status",
                    evidence=evidence,
                ),
                "crawler.robots_status": observation(
                    status,
                    confidence=Confidence.CONFIRMED,
                    score=1.0,
                    method="HTTP status",
                    evidence=evidence,
                ),
                "crawler.ai_homepage_policies": observation(
                    dict.fromkeys(sorted(KNOWN_AI_AGENTS), True),
                    confidence=Confidence.CONFIRMED,
                    score=1.0,
                    method="no robots.txt restrictions were present",
                    evidence=evidence,
                ),
                "crawler.homepage_policy_allowed": observation(
                    True,
                    confidence=Confidence.CONFIRMED,
                    score=1.0,
                    method="no robots.txt restrictions were present",
                    evidence=evidence,
                ),
            }

        if status != 200:
            context.shared["robots_allows_followup"] = False
            return {
                "crawler.robots_exists": observation(
                    None,
                    confidence=Confidence.UNKNOWN,
                    score=0.2,
                    method="robots.txt returned an inconclusive status",
                    evidence=evidence,
                ),
                "crawler.robots_status": observation(
                    status,
                    confidence=Confidence.CONFIRMED,
                    score=1.0,
                    method="HTTP status",
                    evidence=evidence,
                ),
            }

        parsed = parse_robots(result.text)
        crawl_delay = parsed.policy.crawl_delay(context.config.user_agent_token)
        await context.client.set_domain_delay(
            url,
            crawl_delay if crawl_delay is not None else context.config.request_delay_seconds,
        )
        homepage_url = urljoin(f"{context.origin}/", "/")
        allows_homepage = parsed.policy.can_fetch(homepage_url, context.config.user_agent_token)
        ai_homepage_policies = {
            agent: parsed.policy.can_fetch(homepage_url, agent) for agent in sorted(KNOWN_AI_AGENTS)
        }
        context.shared["robots_policy"] = parsed.policy
        context.shared["robots_allows_followup"] = allows_homepage
        context.shared["robots_sitemaps"] = list(parsed.sitemaps)

        return {
            "crawler.robots_exists": observation(
                True,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="robots.txt returned HTTP 200",
                evidence=evidence,
            ),
            "crawler.robots_status": observation(
                status,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="HTTP status",
                evidence=evidence,
            ),
            "crawler.user_agents": observation(
                list(parsed.user_agents),
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="robots.txt directive parsing",
                evidence=evidence,
            ),
            "crawler.ai_specific_user_agents": observation(
                list(parsed.ai_user_agents),
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="robots.txt user-agent matching",
                evidence=evidence,
            ),
            "crawler.ai_homepage_policies": observation(
                ai_homepage_policies,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="robots.txt evaluation for known AI crawler user agents",
                evidence=evidence,
            ),
            "crawler.crawl_delays": observation(
                parsed.crawl_delays,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="robots.txt directive parsing",
                evidence=evidence,
            ),
            "crawler.sitemaps": observation(
                list(parsed.sitemaps),
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method="robots.txt sitemap directives",
                evidence=evidence,
            ),
            "crawler.homepage_policy_allowed": observation(
                allows_homepage,
                confidence=Confidence.CONFIRMED,
                score=1.0,
                method=f"robots.txt evaluation for {context.config.user_agent_token}",
                evidence=evidence,
            ),
        }


def policy_allows(context: ProbeContext, url: str) -> bool:
    policy = context.shared.get("robots_policy")
    if isinstance(policy, Protego):
        return policy.can_fetch(url, context.config.user_agent_token)
    return context.shared.get("robots_allows_followup") is True
