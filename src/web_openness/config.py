import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from web_openness.browser_policy import BrowserPolicy

DEFAULT_SCANNER_PAGE_URL = "https://github.com/shayne-longpre/web-openness-index"
DEFAULT_CONTACT_URI = "https://github.com/shayne-longpre/web-openness-index/issues"
_HTTP_TOKEN = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+\Z")


def _require_https_url(value: str, field_name: str) -> None:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{field_name} must be a public HTTPS URL without credentials")


def _require_contact_uri(value: str) -> None:
    parsed = urlsplit(value)
    valid_https = parsed.scheme == "https" and parsed.hostname is not None
    valid_mailto = parsed.scheme == "mailto" and bool(parsed.path)
    if (
        not (valid_https or valid_mailto)
        or parsed.username is not None
        or parsed.password is not None
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("contact_uri must be an HTTPS or mailto URI without credentials")


@dataclass(frozen=True, slots=True)
class CollectorIdentity:
    """Public identity used in requests and scanner-attribution material."""

    product: str = "WebOpennessObservatory"
    version: str = "0.1"
    scanner_page_url: str = DEFAULT_SCANNER_PAGE_URL
    contact_uri: str = DEFAULT_CONTACT_URI

    def __post_init__(self) -> None:
        if not _HTTP_TOKEN.fullmatch(self.product):
            raise ValueError("collector product must be a valid HTTP product token")
        if not _HTTP_TOKEN.fullmatch(self.version):
            raise ValueError("collector version must be a valid HTTP product token")
        _require_https_url(self.scanner_page_url, "scanner_page_url")
        _require_contact_uri(self.contact_uri)

    @property
    def user_agent(self) -> str:
        return (
            f"{self.product}/{self.version} (+{self.scanner_page_url}; contact={self.contact_uri})"
        )


DEFAULT_COLLECTOR_IDENTITY = CollectorIdentity()
DEFAULT_USER_AGENT = DEFAULT_COLLECTOR_IDENTITY.user_agent


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Explicit network and evidence limits for one domain scan."""

    user_agent: str = DEFAULT_USER_AGENT
    request_budget: int = 8
    request_delay_seconds: float = 1.0
    timeout_seconds: float = 15.0
    domain_timeout_seconds: float = 120.0
    max_response_bytes: int = 1_000_000
    max_redirects: int = 5
    politeness_db_path: Path | None = Path("data/politeness.sqlite3")
    max_politeness_wait_seconds: float = 5.0
    transient_retry_limit: int = 1
    circuit_failure_threshold: int = 2
    circuit_cooldown_seconds: float = 300.0
    cease_list_path: Path | None = None
    browser_policy: BrowserPolicy = field(default_factory=BrowserPolicy)

    def __post_init__(self) -> None:
        if not self.user_agent.strip():
            raise ValueError("user_agent must not be empty")
        if any(ord(character) < 32 or ord(character) == 127 for character in self.user_agent):
            raise ValueError("user_agent must not contain control characters")
        if self.request_budget < 1:
            raise ValueError("request_budget must be at least 1")
        if self.request_delay_seconds < 0:
            raise ValueError("request_delay_seconds must not be negative")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.domain_timeout_seconds <= 0:
            raise ValueError("domain_timeout_seconds must be positive")
        if self.max_response_bytes < 1:
            raise ValueError("max_response_bytes must be at least 1")
        if self.max_redirects < 0:
            raise ValueError("max_redirects must not be negative")
        if self.max_politeness_wait_seconds < 0:
            raise ValueError("max_politeness_wait_seconds must not be negative")
        if self.transient_retry_limit not in {0, 1}:
            raise ValueError("transient_retry_limit must be zero or one")
        if self.circuit_failure_threshold < 1:
            raise ValueError("circuit_failure_threshold must be at least one")
        if self.circuit_cooldown_seconds < 0:
            raise ValueError("circuit_cooldown_seconds must not be negative")

    @property
    def user_agent_token(self) -> str:
        """Return the product token used for robots.txt matching."""

        return self.user_agent.split("/", maxsplit=1)[0].strip()
