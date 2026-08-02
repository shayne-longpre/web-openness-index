# Scanner identity and opt-out

The Web Openness Observatory makes low-volume requests to public websites to study whether the
web remains accessible to people, conventional crawlers, and emerging machine interfaces. It is
domain characterization, not vulnerability scanning or bulk content collection.

## How to identify the collector

HTTP requests use a stable product token and link back to this repository:

```text
WebOpennessObservatory/0.1 (+https://github.com/shayne-longpre/web-openness-index; contact=https://github.com/shayne-longpre/web-openness-index/issues)
```

A deployed worker must also publish its static source addresses, reverse DNS name, and an RFC 9511
probe description at `https://<reverse-dns-name>/.well-known/probing.txt`. The deployment template
is in [`deploy/scanner-site`](../deploy/scanner-site/README.md).

## What the collector does

- resolves the submitted hostname and performs a TLS handshake when applicable;
- fetches `robots.txt`, then honors the applicable policy before follow-up HTTP requests;
- fetches at most one sitemap, the homepage, and `llms.txt` when policy permits;
- limits requests, redirects, elapsed time, and response bytes;
- does not authenticate, submit forms, bypass access controls, or follow sitemap entries;
- keeps optional browser collection disabled unless an isolated worker and explicit limits are
  configured.

The checked-in smoke set is diagnostic and is not a research sample or ranking. Exact behavior and
limits can change as detectors are validated; each released dataset must identify the collector and
configuration version it used.

## Corrections and opt-out

Site operators can request a correction, reduced collection, or complete cessation through the
[repository issue tracker](https://github.com/shayne-longpre/web-openness-index/issues). A production
deployment should additionally publish a monitored group email address in its scanner page and
`probing.txt` file.

An opt-out request should identify the domain and desired scope. Maintainers authenticate control
proportionately—for example through a standard domain contact, a temporary DNS TXT record, or a
file under the site operator's control. Do not send passwords, API keys, or other secrets.

Once accepted, the canonical domain is added to the operational cease list. An entry covers the
domain and its subdomains and must be checked before DNS, TLS, HTTP, or browser work begins. The
operator records only the domain, scope, effective time, verification method, and internal request
reference needed for an audit. Opt-outs remain a distinct collection disposition; they are not
reported as ordinary connection failures or evidence that a site is closed.

The deployment must provide a global stop control for urgent complaints or unexpected load. The
policy for already published data is separate from stopping future collection and requires the
project's applicable ethics and legal review.
