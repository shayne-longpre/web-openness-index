from web_openness.probes.robots import parse_robots


def test_parse_robots_extracts_agents_delays_and_sitemaps() -> None:
    parsed = parse_robots(
        """
        User-agent: *
        Crawl-delay: 2
        Allow: /

        User-agent: GPTBot
        User-agent: Google-Extended
        Disallow: /

        Sitemap: https://example.org/sitemap.xml
        """
    )

    assert parsed.user_agents == ("*", "google-extended", "gptbot")
    assert parsed.ai_user_agents == ("google-extended", "gptbot")
    assert parsed.crawl_delays == {"*": "2"}
    assert parsed.sitemaps == ("https://example.org/sitemap.xml",)


def test_parse_robots_uses_longest_matching_rule() -> None:
    parsed = parse_robots(
        """
        User-agent: *
        Disallow: /private/

        User-agent: WebOpennessBot
        Allow: /private/public$
        Disallow: /private/
        """
    )

    assert parsed.policy.can_fetch("https://example.org/private/public", "WebOpennessBot/0.1")
    assert not parsed.policy.can_fetch(
        "https://example.org/private/elsewhere", "WebOpennessBot/0.1"
    )


def test_parse_robots_preserves_declared_agent_for_evidence() -> None:
    parsed = parse_robots("User-agent: Example*Bot\nDisallow: /")

    assert parsed.user_agents == ("example*bot",)
