"""Unit tests for the ``imports`` use-case and its wire view (no IDA).

A fake :class:`ImportRepository` stands in for the IDA adapter, so the
use-case's paging/clamping contract and the ``ListImportsView`` projection are
exercised without a database.
"""

from __future__ import annotations

from idamesh.application.contexts.imports import ListImportsUseCase
from idamesh.application.dto.imports import ListImportsCommand
from idamesh.domain.entities.imports import Import
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import MAX_COUNT, Page, PageRequest
from idamesh.interface.catalog.imports import import_view, list_imports_view


class _FakeImportRepository:
    """An in-memory ``ImportRepository`` over a fixed, table-ordered list."""

    def __init__(self, rows: list[Import]) -> None:
        self._rows = rows
        self.requests: list[PageRequest] = []

    def list(self, page: PageRequest) -> Page[Import]:
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


def _rows(n: int) -> list[Import]:
    return [
        Import(
            ea=Address(0x402000 + i * 8),
            name=f"imp_{i}",
            module="kernel32.dll",
            ordinal=i + 1,
        )
        for i in range(n)
    ]


def test_use_case_returns_requested_page():
    repo = _FakeImportRepository(_rows(10))
    use_case = ListImportsUseCase(repo)

    result = use_case.execute(ListImportsCommand(offset=2, count=3))

    page = result.page
    assert [imp.name for imp in page.items] == ["imp_2", "imp_3", "imp_4"]
    assert page.offset == 2
    assert page.count == 3
    assert page.total == 10
    assert page.truncated is True


def test_use_case_clamps_count_to_server_maximum():
    repo = _FakeImportRepository(_rows(3))
    use_case = ListImportsUseCase(repo)

    use_case.execute(ListImportsCommand(offset=0, count=10_000))

    # The repository sees a clamped request, never the raw oversized count.
    assert repo.requests[-1].count == MAX_COUNT


def test_use_case_normalizes_negative_offset_and_count():
    repo = _FakeImportRepository(_rows(4))
    use_case = ListImportsUseCase(repo)

    use_case.execute(ListImportsCommand(offset=-5, count=-1))

    request = repo.requests[-1]
    assert request.offset == 0
    # A negative count falls back to the default page size, then is clamped.
    assert request.count <= MAX_COUNT
    assert request.count > 0


def test_use_case_defaults_apply_for_last_page():
    repo = _FakeImportRepository(_rows(5))
    use_case = ListImportsUseCase(repo)

    result = use_case.execute(ListImportsCommand(offset=3, count=100))

    assert [imp.name for imp in result.page.items] == ["imp_3", "imp_4"]
    assert result.page.truncated is False


def test_import_view_projects_single_row():
    view = import_view(
        Import(ea=Address(0x401000), name="CreateFileW", module="kernel32.dll", ordinal=42)
    )

    assert view == {
        "name": "CreateFileW",
        "address": "0x401000",
        "module": "kernel32.dll",
        "ordinal": 42,
    }


def test_view_projects_imports_to_wire_shape():
    page: Page[Import] = Page(
        items=[
            Import(
                ea=Address(0x402000),
                name="recv",
                module="ws2_32.dll",
                ordinal=None,
            ),
            Import(
                ea=Address(0x402008),
                name="",
                module="ws2_32.dll",
                ordinal=115,
            ),
        ],
        offset=0,
        count=2,
        total=2,
        truncated=False,
    )

    view = list_imports_view(page)

    assert view["items"][0] == {
        "name": "recv",
        "address": "0x402000",
        "module": "ws2_32.dll",
        "ordinal": None,
    }
    # An ordinal-only import carries an empty name and its ordinal.
    assert view["items"][1]["name"] == ""
    assert view["items"][1]["ordinal"] == 115
    assert view["items"][1]["address"] == "0x402008"
    assert view["offset"] == 0
    assert view["count"] == 2
    assert view["total"] == 2
    assert view["truncated"] is False
    assert view["next_cursor"] is None
