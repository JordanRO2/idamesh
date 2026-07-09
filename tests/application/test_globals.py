"""Unit tests for the ``list_globals`` use-case and its wire view (no IDA).

A fake :class:`GlobalRepository` stands in for the IDA adapter, so the use-case's
paging/clamping contract and the ``ListGlobalsView`` projection are exercised
without a database.
"""

from __future__ import annotations

from idamesh.application.contexts.globals import ListGlobalsUseCase
from idamesh.application.dto.globals import ListGlobalsCommand
from idamesh.domain.entities.data import Global
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import MAX_COUNT, Page, PageRequest
from idamesh.interface.catalog.views import list_globals_view


class _FakeGlobalRepository:
    """An in-memory ``GlobalRepository`` over a fixed, address-ordered list."""

    def __init__(self, rows: list[Global]) -> None:
        self._rows = rows
        self.requests: list[PageRequest] = []

    def list(self, page: PageRequest) -> Page[Global]:
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


def _rows(n: int) -> list[Global]:
    return [
        Global(ea=Address(0x600000 + i * 8), name=f"g_{i}", size=8, type_name="int")
        for i in range(n)
    ]


def test_use_case_returns_requested_page():
    repo = _FakeGlobalRepository(_rows(10))
    use_case = ListGlobalsUseCase(repo)

    result = use_case.execute(ListGlobalsCommand(offset=2, count=3))

    page = result.page
    assert [g.name for g in page.items] == ["g_2", "g_3", "g_4"]
    assert page.offset == 2
    assert page.count == 3
    assert page.total == 10
    assert page.truncated is True


def test_use_case_clamps_count_to_server_maximum():
    repo = _FakeGlobalRepository(_rows(3))
    use_case = ListGlobalsUseCase(repo)

    use_case.execute(ListGlobalsCommand(offset=0, count=10_000))

    # The repository sees a clamped request, never the raw oversized count.
    assert repo.requests[-1].count == MAX_COUNT


def test_use_case_defaults_apply_for_last_page():
    repo = _FakeGlobalRepository(_rows(5))
    use_case = ListGlobalsUseCase(repo)

    result = use_case.execute(ListGlobalsCommand(offset=3, count=100))

    assert [g.name for g in result.page.items] == ["g_3", "g_4"]
    assert result.page.truncated is False


def test_view_projects_globals_to_wire_shape():
    page: Page[Global] = Page(
        items=[
            Global(ea=Address(0x601000), name="g_flag", size=4, type_name="int"),
            Global(ea=Address(0x601010), name="g_buf", size=64, type_name=None),
        ],
        offset=0,
        count=2,
        total=2,
        truncated=False,
    )

    view = list_globals_view(page)

    assert view["items"][0] == {
        "name": "g_flag",
        "address": "0x601000",
        "size": 4,
        "type": "int",
    }
    assert view["items"][1]["type"] is None
    assert view["items"][1]["address"] == "0x601010"
    assert view["offset"] == 0
    assert view["total"] == 2
    assert view["truncated"] is False
    assert view["next_cursor"] is None
