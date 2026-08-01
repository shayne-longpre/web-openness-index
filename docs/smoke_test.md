# Live smoke test

The live smoke test scans a small, explicit domain list to find collector gaps before a
research pilot. It is diagnostic: its results must not be mixed into the research dataset or
treated as an openness ranking.

Run the checked-in set with:

```bash
uv run web-openness smoke \
  --domains-file examples/smoke_domains.txt \
  --concurrency 3
```

Each successful domain scan writes the same immutable snapshot as `web-openness scan` under
`data/snapshots/`. The command also writes one JSON coverage summary and one Markdown report
under `data/smoke-runs/`, then prints the compact report to the terminal.

The report classifies every domain-signal result as:

- `collected`: the probe returned a positive or negative observation;
- `no_evidence`: the probe was skipped or could not make a supported conclusion;
- `error`: collection or parsing failed;
- `not_yet_supported`: the measurement remains on the planned coverage checklist.

The default policy permits at most eight requests per domain, waits one second between requests
to the same domain, and scans at most three domains concurrently. Keep the domain file small and
review it explicitly before every live run.

## Interpreting the first tranche

The current collector separates signals by how much interpretation they require:

- **Direct evidence:** DNS addresses, TLS negotiation, actual HTTP protocol and statuses,
  `robots.txt` policy, bounded sitemap structure, response headers, and explicit homepage tags.
- **Candidate evidence:** CDN header hints and strongly named public-interface links. These are
  labeled as hints and are not treated as verified provider or API detections.
- **Not yet supported:** browser-versus-HTTP behavior, JavaScript and visual access barriers,
  authenticated interfaces, legal and economic terms, and archive coverage.

Redirects count as real requests and each hop is preserved in the snapshot. A redirect-heavy
domain can therefore reach the budget before the last probe; the run report surfaces that as a
scan note rather than silently treating the missing observation as a negative result.
