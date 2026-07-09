"""Unit tests for the ``export_funcs`` use-case and its wire view (no IDA).

A fake :class:`FunctionRepository` stands in for the IDA adapter so the
use-case's paging/clamping contract and the compact ``Function`` -> ``FuncRef``
projection — plus the ``ExportFuncsView`` shape — are exercised without a
database. Only the repository's ``list`` slice is consulted by the use-case, so
the fake records each :class:`PageRequest` it is handed to assert clamping.
"""

from __future__ import annotations

from typing import List

from idamesh.application.contexts.export_funcs import ExportFuncsUseCase
from idamesh.application.dto.export_funcs import (
    DEFAULT_EXPORT_COUNT,
    ExportFuncsCommand,
)
from idamesh.domain.entities.func_ref import FuncRef
from idamesh.domain.entities.function import Function
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import MAX_COUNT, Page, PageRequest
from idamesh.interface.catalog.export_funcs import (
    export_funcs_view,
    func_ref_view,
)


class _FakeFunctionRepository:
    """An in-memory ``FunctionRepository`` over a fixed, address-ordered list.

    Honors the port contract of returning the requested ``[offset, offset+count)``
    window with the total count and a truncation flag, and records each
    :class:`PageRequest` so the use-case's clamping/normalization can be asserted.
    """

    def __init__(self, rows: List[Function]) -> None:
        self._rows = rows
        self.requests: List[PageRequest] = []

    def list(self, page: PageRequest) -> Page[Function]:
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


def _funcs(n: int) -> List[Function]:
    return [
        Function(
            ea=Address(0x140001000 + i * 0x20),
            name=f"sub_{i}",
            size=0x20,
        )
        for i in range(n)
    ]


# -- use-case -------------------------------------------------------------


def test_use_case_projects_functions_to_compact_refs():
    repo = _FakeFunctionRepository(_funcs(5))
    use_case = ExportFuncsUseCase(repo)

    result = use_case.execute(ExportFuncsCommand(offset=1, count=2))

    page = result.page
    assert all(isinstance(ref, FuncRef) for ref in page.items)
    assert [(ref.name, ref.address) for ref in page.items] == [
        ("sub_1", Address(0x140001020)),
        ("sub_2", Address(0x140001040)),
    ]


def test_use_case_carries_pagination_metadata_through():
    repo = _FakeFunctionRepository(_funcs(10))
    use_case = ExportFuncsUseCase(repo)

    result = use_case.execute(ExportFuncsCommand(offset=2, count=3))

    page = result.page
    assert [ref.name for ref in page.items] == ["sub_2", "sub_3", "sub_4"]
    assert page.offset == 2
    assert page.count == 3
    assert page.total == 10
    assert page.truncated is True
    assert page.next_cursor is None


def test_use_case_last_page_is_not_truncated():
    repo = _FakeFunctionRepository(_funcs(5))
    use_case = ExportFuncsUseCase(repo)

    result = use_case.execute(ExportFuncsCommand(offset=3, count=100))

    assert [ref.name for ref in result.page.items] == ["sub_3", "sub_4"]
    assert result.page.truncated is False
    assert result.page.total == 5


def test_use_case_clamps_count_to_server_maximum():
    repo = _FakeFunctionRepository(_funcs(3))
    use_case = ExportFuncsUseCase(repo)

    use_case.execute(ExportFuncsCommand(offset=0, count=10_000))

    # The repository sees a clamped request, never the raw oversized count.
    assert repo.requests[-1].count == MAX_COUNT


def test_use_case_normalizes_negative_offset_and_count():
    repo = _FakeFunctionRepository(_funcs(4))
    use_case = ExportFuncsUseCase(repo)

    use_case.execute(ExportFuncsCommand(offset=-5, count=-1))

    request = repo.requests[-1]
    assert request.offset == 0
    # A negative count falls back to the default page size, then is clamped.
    assert 0 < request.count <= MAX_COUNT


def test_use_case_applies_default_count_when_omitted():
    repo = _FakeFunctionRepository(_funcs(2))
    use_case = ExportFuncsUseCase(repo)

    use_case.execute(ExportFuncsCommand())

    assert repo.requests[-1].count == DEFAULT_EXPORT_COUNT


def test_use_case_empty_database_yields_empty_page():
    repo = _FakeFunctionRepository(_funcs(0))
    use_case = ExportFuncsUseCase(repo)

    result = use_case.execute(ExportFuncsCommand(offset=0, count=50))

    assert list(result.page.items) == []
    assert result.page.total == 0
    assert result.page.truncated is False


# -- view projection ------------------------------------------------------


def test_func_ref_view_projects_single_row():
    view = func_ref_view(FuncRef(address=Address(0x401000), name="main"))

    assert view == {"name": "main", "address": "0x401000"}


def test_view_projects_page_to_wire_shape():
    page: Page[FuncRef] = Page(
        items=[
            FuncRef(address=Address(0x401000), name="main"),
            FuncRef(address=Address(0x40100A), name="helper"),
        ],
        offset=0,
        count=2,
        total=2,
        truncated=False,
    )

    view = export_funcs_view(page)

    assert view["items"] == [
        {"name": "main", "address": "0x401000"},
        {"name": "helper", "address": "0x40100a"},
    ]
    assert view["offset"] == 0
    assert view["count"] == 2
    assert view["total"] == 2
    assert view["truncated"] is False
    assert view["next_cursor"] is None


def test_view_carries_truncation_and_cursor():
    page: Page[FuncRef] = Page(
        items=[FuncRef(address=Address(0x401000), name="sub_0")],
        offset=0,
        count=1,
        total=42,
        truncated=True,
        next_cursor="opaque-token",
    )

    view = export_funcs_view(page)

    assert view["truncated"] is True
    assert view["total"] == 42
    assert view["next_cursor"] == "opaque-token"
