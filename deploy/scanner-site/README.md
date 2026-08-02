# Scanner attribution site

Serve the contents of this directory from the hostname in the dedicated worker's reverse DNS.

1. Copy `.well-known/probing.txt.example` to `.well-known/probing.txt`.
2. Replace every `scanner.example.org` and `example.org` value with controlled, monitored endpoints.
3. Set `Expires` to a valid RFC 3339 timestamp less than one year ahead and renew it operationally.
4. Serve the file over HTTPS as UTF-8 `text/plain` without authentication.
5. Confirm both the reverse DNS hostname and the worker's literal IP URL expose an identical file
   where the hosting arrangement permits it.

RFC 9511 defines the well-known path and recommends `Canonical`, `Contact`, `Expires`,
`Preferred-Languages`, and the one-line `Description` field. This is a deployment template, not a
claim that the example endpoints exist.
