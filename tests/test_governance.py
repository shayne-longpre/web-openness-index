from pathlib import Path

import pytest

from web_openness.governance import CeaseList, CollectionCeased


def test_cease_list_blocks_domains_and_their_subdomains() -> None:
    cease_list = CeaseList.from_lines(
        ["# accepted requests", "Example.COM. # ticket 12", "bücher.de"]
    )

    assert cease_list.blocks("example.com")
    assert cease_list.blocks("news.example.com")
    assert cease_list.blocks("www.bücher.de")
    assert not cease_list.blocks("notexample.com")
    assert cease_list.matching_domain("deep.news.example.com") == "example.com"


def test_cease_list_loads_utf8_file(tmp_path: Path) -> None:
    path = tmp_path / "cease-list.txt"
    path.write_text("example.org\n", encoding="utf-8")

    assert CeaseList.load(path).domains == frozenset({"example.org"})


def test_cease_list_raises_a_distinct_preflight_disposition() -> None:
    cease_list = CeaseList.from_lines(["example.org"])

    with pytest.raises(CollectionCeased, match=r"operational entry example\.org"):
        cease_list.require_allowed("www.example.org")


@pytest.mark.parametrize("line", ["https://example.org", "*.example.org", "bad_name.example"])
def test_cease_list_rejects_ambiguous_entries(line: str) -> None:
    with pytest.raises(ValueError):
        CeaseList.from_lines([line])
