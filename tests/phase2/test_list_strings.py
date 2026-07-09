"""Unit tests for the ``list_strings`` use-case, adapter, and wire view (no IDA).

A fake :class:`StringsRepository` stands in for the IDA adapter so the use-case's
paging/clamping contract and the ``ListStringsView`` projection are exercised
without a database. The adapter's own slice logic is covered separately over a
fake cache whose ``rows()`` returns a fixed, address-ordered tuple, keeping the
whole module IDA-free.
"""

from __future__ import annotations

from typing import Tuple

from idamesh.application.contexts.list_strings import ListStringsUseCase
from idamesh.application.dto.list_strings import ListStringsCommand
from idamesh.domain.entities.string_item import StringItem
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import MAX_COUNT, Page, PageRequest
from idamesh.infrastructure.ida.strings_adapter import IdaStringsRepository
from idamesh.interface.catalog.list_strings import (
    list_strings_view,
    string_item_view,
)


class _FakeStringsRepository:
    """An in-memory ``StringsRepository`` over a fixed, address-ordered list."""

    def __init__(self, rows: list[StringItem]) -> None:
        self._rows = rows
        self.requests: list[PageRequest] = []

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


class _FakeCache:
    """A stand-in for ``StringsCache`` that hands back a fixed row tuple."""

    def __init__(self, rows: Tuple[StringItem, ...]) -> None:
        self._rows = rows
        self.calls = 0

    def rows(self) -> Tuple[StringItem, ...]:
        self.calls += 1
        return self._rows


def _rows(n: int) -> list[StringItem]:
    return [
        StringItem(
            address=Address(0x140001000 + i * 0x10),
            length=8,
            kind="C",
            value=f"s_{i}",
        )
        for i in range(n)
    ]


# -- use-case -------------------------------------------------------------


def test_use_case_returns_requested_page():
    repo = _FakeStringsRepository(_rows(10))
    use_case = ListStringsUseCase(repo)

    result = use_case.execute(ListStringsCommand(offset=2, count=3))

    page = result.page
    assert [s.value for s in page.items] == ["s_2", "s_3", "s_4"]
    assert page.offset == 2
    assert page.count == 3
    assert page.total == 10
    assert page.truncated is True


def test_use_case_clamps_count_to_server_maximum():
    repo = _FakeStringsRepository(_rows(3))
    use_case = ListStringsUseCase(repo)

    use_case.execute(ListStringsCommand(offset=0, count=10_000))

    # The repository sees a clamped request, never the raw oversized count.
    assert repo.requests[-1].count == MAX_COUNT


def test_use_case_normalizes_negative_offset_and_count():
    repo = _FakeStringsRepository(_rows(4))
    use_case = ListStringsUseCase(repo)

    use_case.execute(ListStringsCommand(offset=-5, count=-1))

    request = repo.requests[-1]
    assert request.offset == 0
    # A negative count falls back to the default page size, then is clamped.
    assert 0 < request.count <= MAX_COUNT


def test_use_case_defaults_apply_for_last_page():
    repo = _FakeStringsRepository(_rows(5))
    use_case = ListStringsUseCase(repo)

    result = use_case.execute(ListStringsCommand(offset=3, count=100))

    assert [s.value for s in result.page.items] == ["s_3", "s_4"]
    assert result.page.truncated is False


# -- adapter slice over a fake cache --------------------------------------


def test_adapter_slices_the_requested_window_from_the_cache():
    rows = tuple(_rows(10))
    cache = _FakeCache(rows)
    repo = IdaStringsRepository(cache)  # type: ignore[arg-type]

    page = repo.list(PageRequest(offset=4, count=3))

    assert [s.value for s in page.items] == ["s_4", "s_5", "s_6"]
    assert page.offset == 4
    assert page.count == 3
    assert page.total == 10
    assert page.truncated is True


def test_adapter_last_page_is_not_truncated():
    rows = tuple(_rows(6))
    repo = IdaStringsRepository(_FakeCache(rows))  # type: ignore[arg-type]

    page = repo.list(PageRequest(offset=4, count=100))

    assert [s.value for s in page.items] == ["s_4", "s_5"]
    assert page.truncated is False
    assert page.total == 6


def test_adapter_clamps_oversized_count():
    rows = tuple(_rows(3))
    repo = IdaStringsRepository(_FakeCache(rows))  # type: ignore[arg-type]

    page = repo.list(PageRequest(offset=0, count=10_000))

    assert page.count == MAX_COUNT
    assert [s.value for s in page.items] == ["s_0", "s_1", "s_2"]
    assert page.truncated is False


def test_adapter_count_reports_cache_size():
    repo = IdaStringsRepository(_FakeCache(tuple(_rows(7))))  # type: ignore[arg-type]

    assert repo.count() == 7


# -- view projection ------------------------------------------------------


def test_string_item_view_projects_single_row():
    view = string_item_view(
        StringItem(
            address=Address(0x140001000),
            length=12,
            kind="unicode",
            value="hello world",
        )
    )

    assert view == {
        "address": "0x140001000",
        "length": 12,
        "type": "unicode",
        "value": "hello world",
    }


def test_view_projects_strings_to_wire_shape():
    page: Page[StringItem] = Page(
        items=[
            StringItem(
                address=Address(0x401000),
                length=5,
                kind="C",
                value="hello",
            ),
            StringItem(
                address=Address(0x401010),
                length=6,
                kind="unicode",
                value="wide",
            ),
        ],
        offset=0,
        count=2,
        total=2,
        truncated=False,
    )

    view = list_strings_view(page)

    assert view["items"][0] == {
        "address": "0x401000",
        "length": 5,
        "type": "C",
        "value": "hello",
    }
    # The domain ``kind`` is projected to the wire key ``type``.
    assert view["items"][1]["type"] == "unicode"
    assert view["items"][1]["address"] == "0x401010"
    assert view["offset"] == 0
    assert view["count"] == 2
    assert view["total"] == 2
    assert view["truncated"] is False
    assert view["next_cursor"] is None
