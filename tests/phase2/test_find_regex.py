"""Unit tests for the ``find_regex`` use-case and its wire view (no IDA).

``find_regex`` reuses the same :class:`StringsRepository` as ``list_strings`` and
filters the materialized string set by a Python regular expression in the
application layer. A fake repository over a fixed, address-ordered row list
exercises the ``re.search`` filter, the ``limit`` clamping and truncation
inference, multi-page walking, and the invalid-pattern-to-``ValueError``
normalization — all without a database. The ``FindRegexView`` projection is
covered over hand-built results.
"""

from __future__ import annotations

from typing import List

import pytest

from idamesh.application.contexts.find_regex import FindRegexUseCase
from idamesh.application.dto.find_regex import (
    DEFAULT_REGEX_LIMIT,
    MAX_REGEX_LIMIT,
    FindRegexCommand,
    FindRegexResult,
)
from idamesh.domain.entities.string_item import StringItem
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import MAX_COUNT, Page, PageRequest
from idamesh.interface.catalog.find_regex import find_regex_view, regex_match_view


class _FakeStringsRepository:
    """An in-memory ``StringsRepository`` over a fixed, address-ordered row list.

    Slices the requested window like the real materialized-cache adapter and
    records each :class:`PageRequest` so the use-case's page walk can be asserted.
    """

    def __init__(self, rows: List[StringItem]) -> None:
        self._rows = rows
        self.requests: List[PageRequest] = []

    def list(self, page: PageRequest) -> Page[StringItem]:
        self.requests.append(page)
        start = page.offset
        stop = start + page.count
        window = self._rows[start:stop]
        return Page(
            items=window,
            offset=start,
            count=page.count,
            total=len(self._rows),
            truncated=stop < len(self._rows),
        )

    def count(self) -> int:
        return len(self._rows)


def _item(index: int, value: str) -> StringItem:
    return StringItem(
        address=Address(0x140001000 + index * 0x10),
        length=len(value),
        kind="C",
        value=value,
    )


def _rows(values: List[str]) -> List[StringItem]:
    return [_item(i, value) for i, value in enumerate(values)]


# -- filtering ------------------------------------------------------------


def test_use_case_returns_only_matching_strings():
    repo = _FakeStringsRepository(
        _rows(["http://host", "GET /index", "https://host", "kernel32.dll"])
    )
    use_case = FindRegexUseCase(repo)

    result = use_case.execute(FindRegexCommand(pattern=r"https?://"))

    assert result.pattern == r"https?://"
    assert [m.value for m in result.matches] == ["http://host", "https://host"]
    assert all(isinstance(m, StringItem) for m in result.matches)
    assert result.truncated is False


def test_use_case_uses_search_not_fullmatch():
    # ``re.search`` matches anywhere in the value, not just at the start.
    repo = _FakeStringsRepository(_rows(["prefix_TOKEN_suffix", "nope"]))
    use_case = FindRegexUseCase(repo)

    result = use_case.execute(FindRegexCommand(pattern=r"TOKEN"))

    assert [m.value for m in result.matches] == ["prefix_TOKEN_suffix"]


def test_use_case_no_match_returns_empty_untruncated():
    repo = _FakeStringsRepository(_rows(["alpha", "beta", "gamma"]))
    use_case = FindRegexUseCase(repo)

    result = use_case.execute(FindRegexCommand(pattern=r"\d{4}"))

    assert result.matches == ()
    assert result.truncated is False


def test_use_case_preserves_matched_string_metadata():
    repo = _FakeStringsRepository(_rows(["password=1234"]))
    use_case = FindRegexUseCase(repo)

    (match,) = use_case.execute(FindRegexCommand(pattern=r"password")).matches

    assert match.address == Address(0x140001000)
    assert match.value == "password=1234"
    assert match.kind == "C"


# -- invalid pattern ------------------------------------------------------


def test_use_case_invalid_regex_raises_value_error():
    repo = _FakeStringsRepository(_rows(["anything"]))
    use_case = FindRegexUseCase(repo)

    # An unbalanced group is a malformed pattern; ``re.error`` is normalized to
    # ``ValueError`` so the interface renders it as an ``isError`` result.
    with pytest.raises(ValueError):
        use_case.execute(FindRegexCommand(pattern=r"(unterminated"))


def test_use_case_invalid_regex_reports_the_pattern():
    repo = _FakeStringsRepository(_rows(["anything"]))
    use_case = FindRegexUseCase(repo)

    with pytest.raises(ValueError) as excinfo:
        use_case.execute(FindRegexCommand(pattern=r"a(b"))

    assert "a(b" in str(excinfo.value)


# -- limit / truncation ---------------------------------------------------


def test_use_case_truncates_when_more_matches_than_limit():
    repo = _FakeStringsRepository(_rows([f"m{i}" for i in range(10)]))
    use_case = FindRegexUseCase(repo)

    result = use_case.execute(FindRegexCommand(pattern=r"m", limit=4))

    assert [m.value for m in result.matches] == ["m0", "m1", "m2", "m3"]
    assert result.truncated is True


def test_use_case_exact_fill_is_not_truncated():
    # Exactly ``limit`` matches exist and no more: the scan self-exhausts, so the
    # use-case can report the precise, un-truncated result.
    repo = _FakeStringsRepository(_rows(["m0", "x", "m1", "y", "m2"]))
    use_case = FindRegexUseCase(repo)

    result = use_case.execute(FindRegexCommand(pattern=r"m", limit=3))

    assert [m.value for m in result.matches] == ["m0", "m1", "m2"]
    assert result.truncated is False


def test_use_case_zero_limit_returns_empty_and_is_not_truncated():
    repo = _FakeStringsRepository(_rows(["m0", "m1"]))
    use_case = FindRegexUseCase(repo)

    result = use_case.execute(FindRegexCommand(pattern=r"m", limit=0))

    assert result.matches == ()
    assert result.truncated is False


def test_use_case_negative_limit_clamped_to_zero():
    repo = _FakeStringsRepository(_rows(["m0", "m1"]))
    use_case = FindRegexUseCase(repo)

    result = use_case.execute(FindRegexCommand(pattern=r"m", limit=-5))

    assert result.matches == ()
    assert result.truncated is False


def test_use_case_clamps_limit_to_server_maximum():
    # More matches than the hard ceiling, with a requested limit above it: the
    # returned set is capped at MAX_REGEX_LIMIT and flagged truncated.
    repo = _FakeStringsRepository(_rows([f"m{i}" for i in range(MAX_REGEX_LIMIT + 5)]))
    use_case = FindRegexUseCase(repo)

    result = use_case.execute(
        FindRegexCommand(pattern=r"m", limit=MAX_REGEX_LIMIT + 1000)
    )

    assert len(result.matches) == MAX_REGEX_LIMIT
    assert result.truncated is True


def test_use_case_default_limit_when_omitted():
    repo = _FakeStringsRepository(_rows([f"m{i}" for i in range(DEFAULT_REGEX_LIMIT + 3)]))
    use_case = FindRegexUseCase(repo)

    result = use_case.execute(FindRegexCommand(pattern=r"m"))

    assert len(result.matches) == DEFAULT_REGEX_LIMIT
    assert result.truncated is True


# -- multi-page walk ------------------------------------------------------


def test_use_case_walks_all_pages_to_find_late_matches():
    # More strings than a single page: a match living past the first page is only
    # found if the use-case pages through the whole materialized set.
    total = MAX_COUNT + 5
    values = ["noise"] * (MAX_COUNT + 2) + ["NEEDLE_here"] + ["noise"] * 2
    repo = _FakeStringsRepository(_rows(values))
    use_case = FindRegexUseCase(repo)

    result = use_case.execute(FindRegexCommand(pattern=r"NEEDLE"))

    assert [m.value for m in result.matches] == ["NEEDLE_here"]
    assert result.truncated is False
    # The walk requested a second page (the needle is past the first MAX_COUNT).
    assert len(repo.requests) >= 2
    assert repo.requests[0].offset == 0
    assert repo.requests[1].offset == MAX_COUNT
    assert total == len(values)


def test_use_case_stops_paging_once_budget_exhausted():
    # With plenty of first-page matches and a small limit, the walk must not
    # request further pages once the cap is proven exceeded.
    values = [f"m{i}" for i in range(MAX_COUNT + 50)]
    repo = _FakeStringsRepository(_rows(values))
    use_case = FindRegexUseCase(repo)

    result = use_case.execute(FindRegexCommand(pattern=r"m", limit=3))

    assert len(result.matches) == 3
    assert result.truncated is True
    # Everything needed was on the first page; no second page was fetched.
    assert len(repo.requests) == 1


# -- empty database -------------------------------------------------------


def test_use_case_empty_string_set():
    repo = _FakeStringsRepository([])
    use_case = FindRegexUseCase(repo)

    result = use_case.execute(FindRegexCommand(pattern=r".*"))

    assert result.matches == ()
    assert result.truncated is False


# -- view projection ------------------------------------------------------


def test_regex_match_view_projects_single_match():
    view = regex_match_view(
        StringItem(
            address=Address(0x401000),
            length=5,
            kind="C",
            value="hello",
        )
    )

    assert view == {"address": "0x401000", "value": "hello"}


def test_view_projects_result_to_wire_shape():
    result = FindRegexResult(
        pattern=r"https?://",
        matches=(
            _item(0, "http://a"),
            _item(1, "https://b"),
        ),
        truncated=True,
    )

    view = find_regex_view(result)

    assert view["pattern"] == r"https?://"
    assert view["matches"] == [
        {"address": "0x140001000", "value": "http://a"},
        {"address": "0x140001010", "value": "https://b"},
    ]
    assert view["truncated"] is True


def test_view_projects_empty_match_set():
    view = find_regex_view(
        FindRegexResult(pattern=r"\d+", matches=(), truncated=False)
    )

    assert view["pattern"] == r"\d+"
    assert view["matches"] == []
    assert view["truncated"] is False
