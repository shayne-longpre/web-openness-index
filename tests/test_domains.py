import pytest

from web_openness.domains import canonical_hostname, registrable_domain


def test_canonical_hostname_normalizes_case_root_dot_and_idn() -> None:
    assert canonical_hostname(" BÜCHER.Example. ") == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        ("news.bbc.co.uk", "bbc.co.uk"),
        ("www.example.com", "example.com"),
        ("project.github.io", "project.github.io"),
        ("www.bücher.de", "xn--bcher-kva.de"),
    ],
)
def test_registrable_domain_uses_bundled_public_suffix_snapshot(
    hostname: str, expected: str
) -> None:
    assert registrable_domain(hostname) == expected


@pytest.mark.parametrize("hostname", ["", "localhost", "127.0.0.1", "bad_name.example"])
def test_registrable_domain_rejects_non_public_or_invalid_hosts(hostname: str) -> None:
    with pytest.raises(ValueError):
        registrable_domain(hostname)
