import pytest

from web_openness.config import (
    DEFAULT_CONTACT_URI,
    DEFAULT_SCANNER_PAGE_URL,
    DEFAULT_USER_AGENT,
    CollectorIdentity,
    ScanConfig,
)


def test_default_identity_is_public_and_neutral() -> None:
    assert DEFAULT_SCANNER_PAGE_URL in DEFAULT_USER_AGENT
    assert DEFAULT_CONTACT_URI in DEFAULT_USER_AGENT
    assert DEFAULT_USER_AGENT.startswith("WebOpennessObservatory/")


def test_custom_identity_builds_user_agent() -> None:
    identity = CollectorIdentity(
        product="PublicWebStudy",
        version="2026.1",
        scanner_page_url="https://scanner.example.org/about",
        contact_uri="mailto:web-study@example.org",
    )

    assert identity.user_agent == (
        "PublicWebStudy/2026.1 "
        "(+https://scanner.example.org/about; contact=mailto:web-study@example.org)"
    )
    assert ScanConfig(user_agent=identity.user_agent).user_agent_token == "PublicWebStudy"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"product": "not a token"},
        {"scanner_page_url": "http://scanner.example.org/about"},
        {"scanner_page_url": "https://user:secret@scanner.example.org/about"},
        {"contact_uri": "ftp://scanner.example.org/contact"},
        {"contact_uri": "mailto:"},
    ],
)
def test_identity_rejects_ambiguous_or_unsafe_values(kwargs: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        CollectorIdentity(**kwargs)


def test_scan_config_rejects_header_control_characters() -> None:
    with pytest.raises(ValueError, match="control characters"):
        ScanConfig(user_agent="PublicWebStudy/1.0\r\nX-Test: injected")
