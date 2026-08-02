from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from web_openness.domains import canonical_hostname


class CollectionCeased(ValueError):
    """Raised before network work for a domain on the operational cease list."""


@dataclass(frozen=True, slots=True)
class CeaseList:
    """Domains excluded from all collection, including their subdomains."""

    domains: frozenset[str]

    @classmethod
    def empty(cls) -> "CeaseList":
        return cls(frozenset())

    @classmethod
    def from_lines(cls, lines: Iterable[str]) -> "CeaseList":
        domains: set[str] = set()
        for line_number, raw_line in enumerate(lines, start=1):
            value = raw_line.split("#", maxsplit=1)[0].strip()
            if not value:
                continue
            if "://" in value or value.startswith("*."):
                raise ValueError(
                    f"cease-list line {line_number} must be a hostname without a scheme or wildcard"
                )
            try:
                domains.add(canonical_hostname(value))
            except ValueError as exc:
                raise ValueError(f"invalid cease-list line {line_number}: {exc}") from exc
        return cls(frozenset(domains))

    @classmethod
    def load(cls, path: Path) -> "CeaseList":
        return cls.from_lines(path.read_text(encoding="utf-8").splitlines())

    def matching_domain(self, hostname: str) -> str | None:
        normalized = canonical_hostname(hostname)
        matches = (
            domain
            for domain in self.domains
            if normalized == domain or normalized.endswith(f".{domain}")
        )
        return max(matches, key=len, default=None)

    def blocks(self, hostname: str) -> bool:
        return self.matching_domain(hostname) is not None

    def require_allowed(self, hostname: str) -> None:
        if match := self.matching_domain(hostname):
            raise CollectionCeased(
                f"collection ceased for {hostname}; matched operational entry {match}"
            )
