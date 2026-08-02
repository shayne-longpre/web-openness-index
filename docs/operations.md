# Restart-safe batch runs

The persistent batch runner is the smallest operational layer around the collector. SQLite holds
only run and job state; immutable evidence remains in the normal snapshot tree.

Start a run from an explicit target file:

```bash
uv run web-openness batch \
  --domains-file examples/smoke_domains.txt \
  --concurrency 3 \
  --json-progress
```

The command prints the run ID before collection begins. Resume interrupted work without scanning
completed domains again:

```bash
uv run web-openness batch --run-id RUN_ID --json-progress
```

Inspect progress or request a graceful stop from another terminal:

```bash
uv run web-openness batch-status RUN_ID
uv run web-openness batch-stop RUN_ID
uv run web-openness batch-stop-all
```

Clear the database-wide stop only after the operator has reviewed the cause:

```bash
uv run web-openness batch-clear-stop
```

`Ctrl-C`, `SIGTERM`, and `batch-stop` stop new jobs from starting. `batch-stop-all` applies the same
control to every run sharing the state database. In-flight domain scans finish so their evidence is
not discarded; unstarted jobs remain pending for the next resume. Failed jobs are retried on an
explicit resume, while completed jobs are never reset.

One coordinator holds a renewable lease for a run. A second live resume is refused; a resume can
recover `running` jobs only after the prior lease expires. This gives the local runner at-least-once
recovery for an interrupted in-flight job without duplicating a scan owned by a live process.

If persistent pacing or a circuit breaker cannot permit the first HTTP request within the configured
wait, the diagnostic snapshot is retained and the job finishes as `deferred` for this run. It is not
automatically restarted because doing so can repeatedly rediscover and reset a long `Crawl-delay`.
An explicit resume retries a deferred job once its `not_before` time has passed. Operators can raise
`--max-politeness-wait` deliberately when the per-domain `--domain-timeout` leaves enough room.

Concurrency is a global worker limit. The queue also allows at most one active scan for any
registrable domain, so targets such as `www.example.org` and `docs.example.org` cannot issue
requests concurrently. Progress output is JSON Lines with durable job counts and recorded request
counts. Clean completions, completions with snapshot notes, deferrals, ceased domains, and runner
failures remain separate counts.
