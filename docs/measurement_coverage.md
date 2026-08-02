# Measurement coverage

This page maps the current collector to the original research specification. “Implemented” means
the collector emits direct evidence or a deliberately conservative inference. “Partial” means it
emits a candidate or hint but cannot yet establish the full research claim. A missing signal is
never converted to `false`.

The operational catalog currently has **94 implemented keys out of 103**. That ratio describes
software coverage, not completion of the research program: several implemented keys are
supporting metadata or explicitly probabilistic hints.

At the original Priority-1 requirement-group level, the current HTTP/DNS collector has **22 fully
implemented, 7 partial, and 1 not yet supported**. The partial measurements are the seven human
barrier types that still need rendered-browser confirmation; the missing measurement is the
browser-versus-HTTP comparison.

## Priority 1

| Area | Implemented | Partial | Not yet supported |
| --- | --- | --- | --- |
| Human access | HTTP homepage reachability | Login, soft/hard paywalls, cookie walls, CAPTCHAs, geographic restriction, JavaScript requirement | Rendered confirmation for every barrier subtype |
| Crawler access | `robots.txt`, AI-agent rules, crawl delay, user-agent targeting, sitemap discovery, scan-wide HTTP status distribution, 403 rate, 429 rate | — | Browser-versus-HTTP comparison |
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

The HTTP/DNS collector is suitable for a bounded pilot and missingness analysis. It is not yet
sufficient for a defensible openness index: browser validation, detector validation sets,
sampling, scoring, and longitudinal release methodology remain research gates.
