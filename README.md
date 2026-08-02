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
| Agent access | Candidate links for APIs, OpenAPI, GraphQL, OAuth metadata, MCP, A2A, agent cards, and API documentation | Agent Accessibility Index |
| Legal access | Candidate policy and license links; planned analysis of scraping, AI, commercial-use, and research restrictions | Legal Restrictiveness Index |
| Economic access | Candidate pricing and registration links; planned analysis of metering, subscriptions, and API pricing | Economic Accessibility Index |
| Infrastructure | CDN, WAF, DNS and hosting providers, TLS configuration, HTTP version | Infrastructure Hardening Index |
| Preservation | Cache-header hints; planned archive coverage, archive blocking, and validated cache behavior | Preservation Index |

Machine-readable metadata—including Schema.org, Open Graph, RSS/Atom/JSON feeds, sitemaps, `robots.txt`, and `llms.txt`—is retained as supporting evidence.

## Current status

This repository contains a working HTTP measurement collector and a lean persistent batch runner.
The current collector:

- normalizes a domain into a reproducible scan target;
- records bounded DNS resolution, CNAME, nameserver, SOA, and TLS negotiation evidence;
- fetches `robots.txt` with a transparent user agent;
- obeys applicable `robots.txt` rules before requesting other paths;
- discovers and safely classifies one sitemap without recursively crawling it;
- records homepage availability and response metadata;
- summarizes the status distribution and HTTP 403/429 frequency across every recorded scan
  attempt, including redirects and retries;
- records HTTP protocol and HTTP/3 advertisements, security headers, exact per-response cache
  outcomes when exposed, edge-location hints, and conservative CDN/edge/DNS/hosting attribution;
- separates explicit challenge/block evidence, bot-management cookie-name fingerprints,
  load-balancer hints, and acceleration headers instead of treating them all as generic WAF use;
- checks public DNS for a conventional `tollbit.<domain>` gateway without requesting it;
- records conservative homepage paywall, consent, CAPTCHA, and JavaScript-required markers without
  claiming to observe rendered state, and records HTTP 451 only as a possible geographic or
  jurisdictional restriction;
- detects structured metadata, canonical/feed/manifest/OpenSearch links, and bounded candidate
  agent-interface, legal-policy, license, pricing, and registration links in homepage HTML without
  fetching or claiming to verify those candidates;
- checks for a public `llms.txt` when policy allows;
- rejects local, private, reserved, and otherwise non-public network destinations;
- emits a schema `0.2.0` JSON snapshot with explicit `observed`, `no_evidence`, `skipped`, and
  `error` outcomes, plus confidence, evidence, attempt-level request records, and errors;
- enforces the request budget across redirects and retries;
- persists pacing by registrable domain in SQLite across workers and runs, applies effective
  `robots.txt` `Crawl-delay`, honors `Retry-After` on HTTP 429/503, retries a transient GET at most
  once, and temporarily ceases a domain after repeated transient failures.

It does **not** yet produce an openness score. Score definitions will be added only after the measurement schema, sampling strategy, and validation protocol are documented and tested.

See [the measurement coverage matrix](docs/measurement_coverage.md) for a requirement-by-requirement
accounting. The operational catalog currently supports 94 of 103 keys, but candidate links and
probabilistic hints should not be mistaken for completed research measurements.

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

Apply a reviewed cease list before any live collection:

```bash
uv run web-openness scan example.org \
  --cease-list examples/cease_list.txt
```

Run the complete local check suite with:

```bash
make check
```

The tests use deterministic mock HTTP responses and do not contact live websites.

The collector publishes a neutral [scanner identity and opt-out process](docs/scanner.md). Before
sustained live collection, review the [deployment checklist](docs/deployment.md), load a canonical
cease list, and deploy the [RFC 9511 attribution template](deploy/scanner-site/README.md).
Application checks do not replace production network egress controls. HTTP collection remains the
default. To enable the optional, non-interactive Chromium pass:

```bash
uv sync --extra browser
uv run playwright install chromium
uv run web-openness scan example.org --browser --json
```

The browser pass uses a fresh context, keeps the same public identity and robots decision, blocks
cross-site top-level redirects, and does not click, type, submit forms, or retain page content.
Its requests and transferred bytes are reported under `browser.network_summary` rather than mixed
into the direct HTTP request budget.

To run the small diagnostic canary and produce a JSON plus Markdown coverage report:

```bash
uv run web-openness smoke \
  --domains-file examples/smoke_domains.txt \
  --cease-list examples/cease_list.txt \
  --concurrency 3
```

This is an operational smoke test, not a research sample or ranking. See
[docs/smoke_test.md](docs/smoke_test.md) for its outputs and interpretation.

For restart-safe multi-domain collection, use the persistent batch runner:

```bash
uv run web-openness batch \
  --domains-file examples/smoke_domains.txt \
  --cease-list examples/cease_list.txt \
  --concurrency 3 \
  --json-progress
```

The command prints a run ID. Inspect, stop, or resume it with `batch-status`, `batch-stop`, and
`batch --run-id RUN_ID`; see [docs/operations.md](docs/operations.md) for the concise runbook.

## Measurement workflow

For each domain, the implemented HTTP collection sequence is:

1. Resolve and validate the target, then collect bounded public DNS metadata.
2. Fetch and parse `robots.txt`.
3. Apply the effective crawler policy and persistent registrable-domain pacing.
4. Fetch one bounded sitemap and the homepage when allowed and within budget.
5. Parse HTML, structured declarations, response headers, conservative infrastructure/barrier
   hints, and candidate interface/policy links.
6. Optionally render the homepage once to compare HTTP and browser access, record bounded rendered
   metadata, and identify visible high-precision barrier markers.
7. Fetch `llms.txt`, summarize all recorded HTTP outcomes, and store an immutable schema `0.2.0`
   evidence snapshot.

HTTP paywall, consent-wall, CAPTCHA, and JavaScript findings remain conservative markup/resource
hints. Optional browser findings report visible selectors, not a claim that a barrier is active or
impossible to bypass. Verified interface probing, policy-text interpretation, screenshots, scoring,
and longitudinal aggregation remain later stages.

The target HTTP budget is roughly 5–15 requests per domain. DNS metadata uses six concurrent,
bounded lookups and is reported separately from the HTTP request count. This is domain
characterization, not large-scale crawling.

## Confidence and evidence

Measurements are not assumed to be binary. Each observation carries:

- a value;
- a collection outcome: `observed`, `no_evidence`, `skipped`, or `error`;
- a confidence label: `confirmed`, `likely`, `possible`, `no_evidence`, or `unknown`;
- a numeric confidence score;
- the method that produced it;
- supporting evidence such as URL, status, timestamp, and content hash.

`No evidence` is distinct from `false`; skipped work and collection errors are also represented
separately. This distinction is essential for longitudinal analysis and defensible scoring.

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
│   ├── client.py             # Budgeted, safety-checked HTTP access
│   ├── politeness.py         # Persistent pacing, retry, and circuit state
│   ├── models.py             # Versioned evidence schema
│   ├── pipeline.py           # Probe orchestration
│   ├── runner.py             # Restart-safe batch coordination
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
