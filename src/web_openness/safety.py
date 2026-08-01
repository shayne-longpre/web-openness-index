"""Network destination checks for the public-web collector.

The checks here are a preflight guard, not a complete sandbox. HTTPX resolves the
hostname again when it opens the connection, so DNS can theoretically change
between validation and connection. Redirects are checked before each request and
environment proxies are disabled by :class:`~web_openness.client.SiteClient`, but
production deployments should still enforce an outbound network policy.
"""

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Sequence

import httpx

AddressResolver = Callable[[str, int], Awaitable[Sequence[str]]]


class URLSafetyError(ValueError):
    """Raised when a URL is not a permitted public HTTP(S) destination."""


async def resolve_host_addresses(hostname: str, port: int) -> tuple[str, ...]:
    """Resolve every TCP address currently advertised for a hostname."""

    loop = asyncio.get_running_loop()
    try:
        answers = await loop.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except OSError as exc:
        raise URLSafetyError(f"DNS resolution failed for {hostname!r}") from exc

    addresses = tuple(sorted({answer[4][0] for answer in answers}))
    if not addresses:
        raise URLSafetyError(f"DNS returned no addresses for {hostname!r}")
    return addresses


async def validate_public_url(
    url: str | httpx.URL,
    *,
    resolve_dns: bool = True,
    resolver: AddressResolver = resolve_host_addresses,
) -> tuple[str, ...]:
    """Validate a URL and return its checked IP addresses, when resolved.

    Only ordinary HTTP and HTTPS origins on their default ports are allowed.
    Requiring a fully qualified hostname avoids probing machine-local search
    domains. Every resolved address must be globally routable.
    """

    try:
        parsed = httpx.URL(url)
    except httpx.InvalidURL as exc:
        raise URLSafetyError("URL is invalid") from exc

    if parsed.scheme not in {"http", "https"}:
        raise URLSafetyError("URL scheme must be http or https")
    if parsed.userinfo:
        raise URLSafetyError("URL must not include credentials")

    hostname = parsed.host.rstrip(".").lower()
    if not hostname:
        raise URLSafetyError("URL must include a hostname")
    if parsed.port is not None:
        raise URLSafetyError("URL must use the scheme's default port")
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise URLSafetyError("localhost destinations are not allowed")
    if "%" in hostname:
        raise URLSafetyError("scoped IP addresses are not allowed")

    try:
        literal_address = ipaddress.ip_address(hostname)
    except ValueError:
        literal_address = None

    if literal_address is not None:
        require_public_address(literal_address)
        return (str(literal_address),)

    if "." not in hostname:
        raise URLSafetyError("hostname must be fully qualified")
    if not resolve_dns:
        return ()

    port = 443 if parsed.scheme == "https" else 80
    addresses = tuple(await resolver(hostname, port))
    if not addresses:
        raise URLSafetyError(f"DNS returned no addresses for {hostname!r}")
    for address_text in addresses:
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError as exc:
            raise URLSafetyError("DNS returned an invalid IP address") from exc
        require_public_address(address)
    return addresses


def require_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    """Reject an IP address that is not globally routable."""

    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise URLSafetyError(f"destination address {address} is not globally routable")
