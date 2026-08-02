# Live smoke test

The smoke test scans a small, reviewed domain list to expose collector gaps before a research
pilot. It is diagnostic: do not mix its results into a research sample or treat them as an
openness ranking.

Run the checked-in canaries with the reviewed cease list:

```bash
uv run web-openness smoke \
  --domains-file examples/smoke_domains.txt \
  --cease-list examples/cease_list.txt \
  --concurrency 3
```

Add `--browser` only after installing the optional runtime and reviewing its tighter per-domain
request and transfer limits.

Successful scans write immutable schema `0.2.0` snapshots under `data/snapshots/`. The command
also writes JSON and Markdown coverage reports under `data/smoke-runs/` and prints the compact
report. Each observation has an explicit outcome:

- `collected` maps to `observed`, including valid negative values such as `false`;
- `no_evidence` means the probe ran but found no evidence;
- `skipped` means policy, applicability, pacing, or budget prevented collection;
- `error` means collection or parsing failed;
- `not_yet_supported` is a report-only marker for planned measurements.

## What this run exercises

- **Direct evidence:** DNS addresses/CNAME/NS/SOA, TLS, actual HTTP attempts and protocol,
  `robots.txt`, bounded sitemap structure, homepage status and metadata, scan-wide status
  distribution and HTTP 403/429 frequencies, security headers, exact response cache outcomes when
  exposed, and `llms.txt`. With `--browser`, this also includes navigation status, rendered-document
  counts, transfer totals, and a direct HTTP/render comparison.
- **Conservative hints:** CDN, edge, DNS, hosting, bot-management, load-balancer, acceleration, and
  explicit challenge/block evidence plus known paywall, consent-management, CAPTCHA, and explicit
  JavaScript-required markup. HTTP 451 is only a possible geographic or jurisdictional restriction.
  Provider attribution remains probabilistic, and a single response does not establish a site's
  complete product configuration or general cache behavior.
- **Conventional discovery:** bounded public DNS queries for `tollbit.<domain>`; a record is not a
  claim that TollBit enforcement is active on every path.
- **Explicit declarations:** `rel=license`, JSON-LD `license`, `isAccessibleForFree`, and
  `requiresSubscription` values found in the bounded homepage response.
- **Candidate discovery:** strongly named homepage links for OpenAPI, GraphQL, OAuth, MCP, A2A,
  agent cards, API documentation, legal/license policies, pricing, and registration. Candidates
  are recorded but not fetched or verified.
- **Not yet supported:** authenticated interfaces, policy-text interpretation, archive coverage,
  screenshots, and validated cache behavior. Browser-versus-HTTP confirmation is available only
  with `--browser`.

## Fetch and politeness semantics

The default budget is eight actual HTTP attempts per scan. Redirect hops and the optional retry
each consume budget and remain in the snapshot. If an initial HTTP 429 is followed by a successful
retry, both attempts remain evidence and rate limiting is still reported.

Public DNS metadata uses six concurrent bounded lookups per domain: homepage CNAME, registrable
domain NS and SOA, and A/CNAME/NS for `tollbit.<domain>`. An A-only TollBit candidate is ignored
because it cannot be distinguished reliably from wildcard hosting. These lookups do not consume
the HTTP budget.

Pacing state is persisted in `data/politeness.sqlite3` by registrable domain, so sibling hosts and
later runs share the same interval. The collector applies the effective `robots.txt`
`Crawl-delay`, honors valid `Retry-After` values on HTTP 429/503, retries a transient GET at most
once, and opens a temporary per-domain circuit after repeated transient failures. Delays beyond
the bounded inline wait cease/defer follow-up work instead of tying up a worker.

The cease list is checked before DNS, TLS, HTTP, or optional browser-adapter work. Keep both input
files small and review them before every live run. Application destination checks are useful but
do not replace the production egress controls described in [deployment.md](deployment.md). Browser
collection is disabled unless `--browser` is passed and the optional runtime is installed.

For a restart-safe run after the canary is reviewed, use the batch command:

```bash
uv run web-openness batch \
  --domains-file examples/smoke_domains.txt \
  --cease-list examples/cease_list.txt \
  --concurrency 3 \
  --json-progress
```

Use `batch-status RUN_ID`, `batch-stop RUN_ID`, and `batch --run-id RUN_ID` to inspect, stop, and
resume. See [operations.md](operations.md) for the batch lifecycle rather than treating this smoke
guide as an operations runbook.
