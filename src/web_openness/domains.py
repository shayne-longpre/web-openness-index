import re

import tldextract

_EXTRACT = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
    fallback_to_snapshot=True,
    include_psl_private_domains=True,
)
_VALID_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def canonical_hostname(hostname: str) -> str:
    """Return a lowercase ASCII hostname, without a trailing root dot."""

    candidate = hostname.strip().rstrip(".")
    if not candidate:
        raise ValueError("hostname must not be empty")
    try:
        normalized = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"hostname is not valid IDNA: {hostname!r}") from exc

    labels = normalized.split(".")
    if len(normalized) > 253 or any(not _VALID_LABEL.fullmatch(label) for label in labels):
        raise ValueError(f"hostname is not valid: {hostname!r}")
    return normalized


def registrable_domain(hostname: str) -> str:
    """Return the registrable domain using tldextract's bundled PSL snapshot."""

    normalized = canonical_hostname(hostname)
    extracted = _EXTRACT(normalized)
    if not extracted.domain or not extracted.suffix:
        raise ValueError(f"hostname has no recognized public suffix: {hostname!r}")
    return f"{extracted.domain}.{extracted.suffix}"
