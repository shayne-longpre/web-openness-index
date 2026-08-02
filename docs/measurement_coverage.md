# Measurement coverage

This page maps the current collector to the original research specification. “Implemented” means
the collector emits direct evidence or a deliberately conservative inference. “Partial” means it
emits a candidate or hint but cannot yet establish the full research claim. A missing signal is
never converted to `false`.

The operational catalog currently has **102 implemented keys out of 110**. That ratio describes
software coverage, not completion of the research program: several implemented keys are
supporting metadata or explicitly probabilistic hints.

At the original Priority-1 requirement-group level, the collector has **23 fully implemented, 7
partial, and 0 not yet supported**. Browser-versus-HTTP comparison is now implemented. Human barrier
classification remains partial: the renderer can confirm visible high-precision login, paywall,
consent, and CAPTCHA markers, but it does not interact with or attempt to bypass them.

## Priority 1

| Area | Implemented | Partial | Not yet supported |
| --- | --- | --- | --- |
| Human access | HTTP and browser homepage reachability; visible rendered login, paywall, consent, and CAPTCHA markers | Active/soft/hard barrier classification, geographic restriction, JavaScript requirement | — |
| Crawler access | `robots.txt`, AI-agent rules, crawl delay, user-agent targeting, sitemap discovery, scan-wide HTTP status distribution, 403 rate, 429 rate, browser-versus-HTTP comparison | — | — |
| Infrastructure | DNS and hosting hints, CDN/edge hints, explicit WAF/challenge hints, TLS, HTTP version | Exact vendor product and feature configuration is intentionally not inferred without direct evidence | — |
| Public metadata | JSON-LD/Schema.org types, Open Graph, RSS/Atom/JSON Feed links, sitemap, `robots.txt`, `llms.txt` | — | — |

HTTP 451 is recorded as a possible geographic or jurisdictional restriction, not proof of the
site's reason. Barrier markup and vendor fingerprints similarly retain confidence and method
labels rather than being promoted to facts.

## Later priorities

| Area | Current evidence | Main gap |
| --- | --- | --- |
| Agent access | Bounded candidate links for OpenAPI, GraphQL, OAuth, API docs, MCP, A2A, and agent cards | Safe verification, structured commerce, and the capability ladder |
| Legal access | Candidate policy/license links and explicit homepage license declarations | Policy-text extraction and validated restrictions taxonomy |
| Economic access | Candidate pricing/registration links and explicit JSON-LD subscription declarations | Free/registration/metering/enterprise/API-pricing classification |
| Preservation | Cache-related response headers | Archive coverage, archive blocking, validated cache behavior, and ephemeral-content indicators |
| Research outputs | Immutable JSON snapshots and smoke reports | Scoring, longitudinal aggregates, screenshots, public API, and dashboard |

## Interpretation

The collector is suitable for a bounded pilot and missingness analysis. The optional browser pass
closes the HTTP/render comparison gap, but a defensible openness index still requires detector
validation sets, sampling, scoring, and a longitudinal release methodology.
