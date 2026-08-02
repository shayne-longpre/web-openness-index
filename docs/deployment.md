# Minimal collector deployment

Start with one dedicated worker and one stable public egress address. This is enough to operate a
small canary, understand resource use, and give site operators a source they can identify or block.
Do not add a queue cluster, Kubernetes, or a browser fleet before the measured workload requires it.

## Network boundary

Application URL checks reduce mistakes but cannot eliminate DNS rebinding or resolver-to-connect
races. Enforce the same policy outside the Python process:

1. Give the worker no cloud-control credentials and no access to private services.
2. Route all collection traffic through one dedicated static IPv4 address, and a static IPv6 address
   only if IPv6 egress receives the same controls.
3. Deny loopback, RFC 1918, carrier-grade NAT, link-local, multicast, reserved, IPv6 ULA, and cloud
   metadata ranges at the host or subnet firewall. Deny other internal organization ranges too.
4. Permit DNS only to the chosen recursive resolver. Permit outbound TCP 80 and 443 only to public
   destinations; deny other collection egress by default.
5. Keep the browser adapter in an ephemeral sandbox or container with the same egress policy, no
   persistent profile, no mounted credentials, and no route to the control plane.

The static address should have one reverse DNS name. That name should resolve back to the worker
address and serve the project description and `/.well-known/probing.txt` over HTTPS. Keep the RFC
9511 `Expires` value current and less than a year ahead.

## Identity and complaints

Before sending a live canary:

- publish the [scanner page](scanner.md), source addresses, monitored group contact, and opt-out
  instructions;
- render and deploy the [`probing.txt` template](../deploy/scanner-site/.well-known/probing.txt.example);
- confirm the HTTP user agent links to a page that already resolves;
- load the reviewed cease list before creating jobs;
- test the global stop control and preserve the run ID in complaint records.

The repository default identifies this project. A different deployment can construct a neutral
identity without editing request code:

```python
from web_openness.config import CollectorIdentity, ScanConfig

identity = CollectorIdentity(
    product="PublicWebStudy",
    version="1.0",
    scanner_page_url="https://scanner.example.org/",
    contact_uri="mailto:web-study@example.org",
)
config = ScanConfig(user_agent=identity.user_agent)
```

For a one-off CLI run, pass the same string with `--user-agent`. Keep the product token stable because
it is also used to select the applicable `robots.txt` group.

## Optional browser worker

HTTP collection remains the default. Install the `browser` extra plus Chromium, then pass
`--browser` to run one Playwright render per domain. `BrowserPolicy` defaults to disabled and caps
wall time, total requests, third-party requests, bytes per response, and total transferred bytes.

The integrated adapter creates a fresh context, blocks service workers and downloads, checks every
request destination, applies the cease list to resource hosts, applies the target robots policy to
same-site paths, and blocks cross-site top-level navigation. It never clicks, types, submits forms,
or interacts with authentication, consent, CAPTCHA, or checkout controls. Chromium transfer events
enforce and report response-byte limits; the production egress boundary remains necessary because
application callbacks are not a substitute for network isolation.

The adapter boundary remains injectable through `BrowserWorker`, so a production deployment can run
the same contract in an ephemeral container without changing probes or stored evidence.

## First deployment gate

Run offline tests, then scan only the reviewed canary file. Watch request counts, statuses, timeouts,
and complaints; stop the run if behavior exceeds the published limits. Do not schedule recurring or
larger batches until the canary report has been reviewed and obvious detector failures have fixtures.
