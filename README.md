# Web Openness Observatory

The Web Openness Observatory is an early-stage research project for measuring how accessible the public web is to humans, crawlers, and AI agents—and how that accessibility changes over time.

The project is designed around **measurement, not circumvention**. It characterizes public interfaces with a transparent methodology while respecting `robots.txt`, authentication boundaries, rate limits, paywalls, CAPTCHAs, and other standard access controls.

## Research questions

- How open is today's web?
- How is web openness changing over time?
- How do sectors such as news, government, academia, commerce, and forums differ?
- Is the web becoming less crawlable while becoming more agent-accessible?
- Which technical, legal, and economic barriers are driving these changes?

## What the observatory measures

Each domain receives a timestamped evidence record. Scores and aggregate indices are derived later from versioned methodology, so the underlying observations remain inspectable and reproducible.

| Dimension | Example signals | Planned output |
| --- | --- | --- |
| Human access | Homepage availability, login requirements, paywalls, cookie walls, CAPTCHAs, geographic restrictions, JavaScript requirements | Human Accessibility Index |
| Crawler access | `robots.txt`, AI-specific directives, crawl delay, sitemaps, HTTP status, 403/429 responses, browser-versus-HTTP differences | Crawl Accessibility Index |
| Agent access | Public APIs, OpenAPI, GraphQL, OAuth metadata, MCP, A2A, agent cards, structured commerce interfaces | Agent Accessibility Index |
| Legal access | Scraping, AI, commercial-use, licensing, API-term, and research restrictions | Legal Restrictiveness Index |
| Economic access | Registration, metering, subscriptions, enterprise access, and API pricing | Economic Accessibility Index |
| Infrastructure | CDN, WAF, DNS and hosting providers, TLS configuration, HTTP version | Infrastructure Hardening Index |
| Preservation | Internet Archive coverage, archive blocking, cache behavior, ephemeral-content indicators | Preservation Index |

Machine-readable metadata—including Schema.org, Open Graph, RSS/Atom/JSON feeds, sitemaps, `robots.txt`, and `llms.txt`—is retained as supporting evidence.

## Current status

This repository contains the first collector skeleton and the infrastructure plan. The current collector:

- normalizes a domain into a reproducible scan target;
- records bounded DNS resolution and TLS negotiation evidence;
- fetches `robots.txt` with a transparent user agent;
- obeys applicable `robots.txt` rules before requesting other paths;
- discovers and safely classifies one sitemap without recursively crawling it;
- records homepage availability and response metadata;
- records HTTP protocol, cache/security headers, and conservative CDN hints;
- detects structured metadata, canonical/feed/manifest/OpenSearch links, and candidate public
  interface links in the homepage HTML;
- checks for a public `llms.txt` when policy allows;
- rejects local, private, reserved, and otherwise non-public network destinations;
- emits a versioned JSON snapshot with evidence, confidence, request records, and errors;
- enforces a per-domain request budget and delay.

It does **not** yet produce an openness score. Score definitions will be added only after the measurement schema, sampling strategy, and validation protocol are documented and tested.

## Quick start

Prerequisites: Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --all-groups
uv run web-openness scan example.org
```

Snapshots are written under `data/snapshots/<date>/<domain>/` by default. To inspect a result directly:

```bash
uv run web-openness scan example.org --json
```

Run the complete local check suite with:

```bash
make check
```

The tests use deterministic mock HTTP responses and do not contact live websites.

To run the small diagnostic canary and produce a JSON plus Markdown coverage report:

```bash
uv run web-openness smoke \
  --domains-file examples/smoke_domains.txt \
  --concurrency 3
```

This is an operational smoke test, not a research sample or ranking. See
[docs/smoke_test.md](docs/smoke_test.md) for its outputs and interpretation.

## Measurement workflow

For each domain, the intended collection sequence is:

1. Resolve and validate the target.
2. Fetch and parse `robots.txt`.
3. Discover sitemaps and well-known metadata.
4. Fetch the homepage over HTTP when allowed.
5. Render the homepage in an isolated browser worker when allowed.
6. Parse HTML, headers, infrastructure signals, and public machine interfaces.
7. Store an immutable, structured evidence snapshot.
8. Validate the snapshot against the versioned schema.
9. Derive scores and longitudinal aggregates from frozen methodology versions.

The target budget is roughly 5–15 requests per domain. This is domain characterization, not large-scale crawling.

## Confidence and evidence

Measurements are not assumed to be binary. Each observation carries:

- a value;
- a confidence label: `confirmed`, `likely`, `possible`, `no_evidence`, or `unknown`;
- a numeric confidence score;
- the method that produced it;
- supporting evidence such as URL, status, timestamp, and content hash.

`No evidence` is distinct from `false`, and collection failure is represented as `unknown`. This distinction is essential for longitudinal analysis and defensible scoring.

## Agent capability ladder

Agent-facing access will be classified progressively:

0. Blocked
1. Readable
2. Machine-interpretable
3. Searchable or queryable
4. Authenticated API
5. Actionable API
6. Agent-native (for example, MCP or A2A)
7. Delegable with verification

The observatory measures only publicly discoverable interfaces and never attempts authenticated actions.

## Repository layout

```text
.
├── docs/
│   ├── architecture.md       # System boundaries, infrastructure, and delivery plan
│   └── methodology/          # Sampling and research methodology
├── schemas/                  # Committed, versioned evidence contracts
├── scripts/                  # Reproducible schema and maintenance commands
├── src/web_openness/
│   ├── probes/               # Independently testable measurement modules
│   ├── client.py             # Budgeted, rate-limited HTTP access
│   ├── models.py             # Versioned evidence schema
│   ├── pipeline.py           # Probe orchestration
│   └── storage.py            # Immutable local snapshots
├── tests/                    # Offline unit and integration-style tests
└── .github/workflows/ci.yml  # Formatting, linting, typing, and test checks
```

See [docs/architecture.md](docs/architecture.md) for the proposed production architecture, scaling path, and phase-by-phase acceptance criteria. The first pilot design is specified in [docs/methodology/pilot_sampling.md](docs/methodology/pilot_sampling.md).

## Priorities

### Priority 1: measurement MVP

- Human access signals
- Crawler access and policy signals
- Infrastructure inference
- Public metadata discovery
- Versioned raw snapshots and a defensible sample

### Priority 2: agent access

- OpenAPI, GraphQL, OAuth, MCP, A2A, and agent-card discovery
- Public API documentation and structured-commerce detection
- Agent capability classification

### Priority 3: legal, economic, and preservation access

- Rule-based policy and terms extraction, followed by validated model-assisted extraction
- Paywall and pricing taxonomy
- Archive coverage and cache behavior

## Engineering principles

- Respect `robots.txt` and explicit access controls.
- Use a transparent user agent and publish the methodology.
- Apply conservative per-domain rate limits and bounded concurrency.
- Retry only failures that are clearly transient.
- Never bypass CAPTCHAs, authentication, paywalls, or geographic restrictions.
- Never spoof users or use residential proxies.
- Preserve raw evidence separately from derived classifications and scores.
- Version schemas, detectors, sampling frames, and scoring methodology.
- Make every production result reproducible from code, configuration, and immutable inputs.

The goal is to measure barriers, not defeat them.

## Success criterion

The observatory should make it possible to answer not only **“Can this content be accessed?”**, but **“Who can access it, under what conditions, through which interfaces, and how is that changing over time?”**
