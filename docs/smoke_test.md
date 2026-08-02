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

Successful scans write immutable schema `0.2.0` snapshots under `data/snapshots/`. The command
also writes JSON and Markdown coverage reports under `data/smoke-runs/` and prints the compact
report. Each observation has an explicit outcome:

- `collected` maps to `observed`, including valid negative values such as `false`;
- `no_evidence` means the probe ran but found no evidence;
- `skipped` means policy, applicability, pacing, or budget prevented collection;
- `error` means collection or parsing failed;
- `not_yet_supported` is a report-only marker for planned measurements.

## What this run exercises

- **Direct evidence:** DNS and TLS, actual HTTP attempts and protocol, `robots.txt`, bounded
  sitemap structure, homepage status and metadata, security headers, and `llms.txt`.
- **Conservative hints:** CDN and cache-header hints. Headers do not establish provider
  attribution or observed cache behavior.
- **Candidate discovery:** strongly named homepage links for OpenAPI, GraphQL, OAuth, MCP, A2A,
  agent cards, API documentation, legal/license policies, pricing, and registration. Candidates
  are recorded but not fetched or verified.
- **Not yet supported:** browser-versus-HTTP comparison, visual/JavaScript barriers, authenticated
  interfaces, policy-text interpretation, archive coverage, and validated cache behavior.

## Fetch and politeness semantics

The default budget is eight actual HTTP attempts per scan. Redirect hops and the optional retry
each consume budget and remain in the snapshot. If an initial HTTP 429 is followed by a successful
retry, both attempts remain evidence and rate limiting is still reported.

Pacing state is persisted in `data/politeness.sqlite3` by registrable domain, so sibling hosts and
later runs share the same interval. The collector applies the effective `robots.txt`
`Crawl-delay`, honors valid `Retry-After` values on HTTP 429/503, retries a transient GET at most
once, and opens a temporary per-domain circuit after repeated transient failures. Delays beyond
the bounded inline wait cease/defer follow-up work instead of tying up a worker.

The cease list is checked before DNS, TLS, HTTP, or optional browser-adapter work. Keep both input
files small and review them before every live run. Application destination checks are useful but
do not replace the production egress controls described in [deployment.md](deployment.md); no
browser runtime is integrated in the current collector.

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
