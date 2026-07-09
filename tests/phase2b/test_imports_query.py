"""Unit tests for the ``imports_query`` use-case and its wire view (no IDA).

An in-memory :class:`ImportRepository` stands in for the IDA adapter, so the
filter grammar (case-insensitive symbol/module substrings combined as a
conjunction), the ``limit`` clamping / one-beyond-limit ``truncated`` detection,
the hard scan ceiling, and the ``ImportsQueryView`` projection are all exercised
on synthetic rows with no database present.
"""

from __future__ import annotations

from idamesh.application.contexts.imports_query import ImportsQueryUseCase
from idamesh.application.dto.imports_query import (
    MAX_IMPORTS_QUERY_LIMIT,
    MAX_IMPORTS_QUERY_SCAN,
    ImportsQueryCommand,
)
from idamesh.domain.entities.imports import Import
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import MAX_COUNT, Page, PageRequest
from idamesh.interface.catalog.imports_query import (
    import_match_view,
    imports_query_view,
)


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


class _UnboundedImportRepository:
    """A repository that never runs dry: every page is a full, ``truncated``
    :data:`MAX_COUNT` window of the same non-matching rows. Used to prove the
    use-case's hard scan ceiling terminates the walk."""

    def __init__(self) -> None:
        self.requests: list[PageRequest] = []
        # One reusable full page of rows whose names never match the filters
        # exercised against this fake.
        self._page = [
            Import(ea=Address(0x400000 + i * 4), name=f"zzz_{i}", module="none.dll")
            for i in range(MAX_COUNT)
        ]

    def list(self, page: PageRequest) -> Page[Import]:
        self.requests.append(page)
        return Page(
            items=self._page,
            offset=page.offset,
            count=page.count,
            total=None,
            truncated=True,
        )

    def count(self) -> int:  # pragma: no cover - not consulted by the use-case
        return MAX_COUNT


def _win32_rows() -> list[Import]:
    """A small, mixed-module import table."""
    return [
        Import(ea=Address(0x401000), name="CreateFileW", module="kernel32.dll", ordinal=None),
        Import(ea=Address(0x401004), name="CreateThread", module="kernel32.dll", ordinal=None),
        Import(ea=Address(0x401008), name="connect", module="ws2_32.dll", ordinal=4),
        Import(ea=Address(0x40100C), name="recv", module="ws2_32.dll", ordinal=16),
        Import(ea=Address(0x401010), name="RegOpenKeyExW", module="advapi32.dll", ordinal=None),
    ]


def _names(result) -> list[str]:
    return [item.name for item in result.matches]


# -- name / module filtering -------------------------------------------------


def test_name_substring_is_case_insensitive():
    use_case = ImportsQueryUseCase(_FakeImportRepository(_win32_rows()))

    result = use_case.execute(ImportsQueryCommand(name="create"))

    assert _names(result) == ["CreateFileW", "CreateThread"]
    assert result.truncated is False


def test_module_substring_is_case_insensitive():
    use_case = ImportsQueryUseCase(_FakeImportRepository(_win32_rows()))

    result = use_case.execute(ImportsQueryCommand(module="WS2_32"))

    assert _names(result) == ["connect", "recv"]


def test_name_and_module_combine_as_conjunction():
    use_case = ImportsQueryUseCase(_FakeImportRepository(_win32_rows()))

    # ``C`` matches CreateFileW, CreateThread and connect; the module clause then
    # keeps only the kernel32 pair — the ws2_32 ``connect`` is filtered out.
    result = use_case.execute(ImportsQueryCommand(name="C", module="kernel32"))

    assert _names(result) == ["CreateFileW", "CreateThread"]


def test_empty_query_returns_every_import():
    rows = _win32_rows()
    use_case = ImportsQueryUseCase(_FakeImportRepository(rows))

    result = use_case.execute(ImportsQueryCommand())

    assert _names(result) == [item.name for item in rows]
    assert result.truncated is False


def test_whitespace_only_filters_are_treated_as_unset():
    rows = _win32_rows()
    use_case = ImportsQueryUseCase(_FakeImportRepository(rows))

    result = use_case.execute(ImportsQueryCommand(name="   ", module="\t"))

    assert len(result.matches) == len(rows)


def test_no_match_yields_empty_untruncated_result():
    use_case = ImportsQueryUseCase(_FakeImportRepository(_win32_rows()))

    result = use_case.execute(ImportsQueryCommand(name="does-not-exist"))

    assert result.matches == ()
    assert result.truncated is False


def test_ordinal_only_import_is_preserved_through_the_use_case():
    rows = [Import(ea=Address(0x402000), name="", module="ws2_32.dll", ordinal=115)]
    use_case = ImportsQueryUseCase(_FakeImportRepository(rows))

    result = use_case.execute(ImportsQueryCommand(module="ws2_32"))

    assert len(result.matches) == 1
    match = result.matches[0]
    assert match.name == ""
    assert match.ordinal == 115


# -- limit clamping / truncation --------------------------------------------


def _matching_rows(n: int) -> list[Import]:
    return [
        Import(ea=Address(0x403000 + i * 4), name=f"api_{i}", module="lib.dll")
        for i in range(n)
    ]


def test_truncated_when_matches_exceed_limit():
    # limit + 1 matches are needed before the one-beyond-limit probe trips.
    use_case = ImportsQueryUseCase(_FakeImportRepository(_matching_rows(5)))

    result = use_case.execute(ImportsQueryCommand(name="api", limit=3))

    assert len(result.matches) == 3
    assert result.truncated is True


def test_not_truncated_when_matches_equal_limit_exactly():
    use_case = ImportsQueryUseCase(_FakeImportRepository(_matching_rows(3)))

    result = use_case.execute(ImportsQueryCommand(name="api", limit=3))

    assert len(result.matches) == 3
    assert result.truncated is False


def test_zero_limit_returns_nothing_but_flags_truncation_when_items_exist():
    use_case = ImportsQueryUseCase(_FakeImportRepository(_matching_rows(2)))

    result = use_case.execute(ImportsQueryCommand(name="api", limit=0))

    assert result.matches == ()
    assert result.truncated is True


def test_zero_limit_with_no_matches_is_not_truncated():
    use_case = ImportsQueryUseCase(_FakeImportRepository(_win32_rows()))

    result = use_case.execute(ImportsQueryCommand(name="nope", limit=0))

    assert result.matches == ()
    assert result.truncated is False


def test_negative_limit_is_clamped_to_zero():
    use_case = ImportsQueryUseCase(_FakeImportRepository(_matching_rows(4)))

    result = use_case.execute(ImportsQueryCommand(name="api", limit=-10))

    assert result.matches == ()
    assert result.truncated is True


def test_limit_is_clamped_to_server_maximum():
    # More matches than the ceiling, with a requested limit far above it: the
    # reply is capped at MAX_IMPORTS_QUERY_LIMIT and flagged truncated.
    rows = _matching_rows(MAX_IMPORTS_QUERY_LIMIT + 2)
    use_case = ImportsQueryUseCase(_FakeImportRepository(rows))

    result = use_case.execute(ImportsQueryCommand(name="api", limit=1_000_000))

    assert len(result.matches) == MAX_IMPORTS_QUERY_LIMIT
    assert result.truncated is True


# -- paging / scan bounds ----------------------------------------------------


def test_walk_pages_past_a_full_page_of_non_matches():
    # A full first page of non-matching rows, then the matches on page two: the
    # walk must request a second page and keep the filter applied across it.
    skip = [
        Import(ea=Address(0x410000 + i * 4), name=f"skip_{i}", module="other.dll")
        for i in range(MAX_COUNT)
    ]
    hits = [
        Import(ea=Address(0x500000 + i * 4), name=f"target_{i}", module="user32.dll")
        for i in range(5)
    ]
    repo = _FakeImportRepository(skip + hits)
    use_case = ImportsQueryUseCase(repo)

    result = use_case.execute(ImportsQueryCommand(name="target"))

    assert _names(result) == [f"target_{i}" for i in range(5)]
    assert result.truncated is False
    # Two pages were fetched, the second starting at the MAX_COUNT boundary.
    assert len(repo.requests) == 2
    assert repo.requests[0].offset == 0
    assert repo.requests[1].offset == MAX_COUNT
    # Every page request is clamped to the server page size.
    assert all(req.count == MAX_COUNT for req in repo.requests)


def test_scan_ceiling_bounds_an_unbounded_repository():
    repo = _UnboundedImportRepository()
    use_case = ImportsQueryUseCase(repo)

    # No row matches, so the walk would run forever were it not for the ceiling.
    result = use_case.execute(ImportsQueryCommand(name="createfile"))

    assert result.matches == ()
    assert result.truncated is False
    # Exactly MAX_IMPORTS_QUERY_SCAN items scanned = that many / MAX_COUNT pages.
    assert len(repo.requests) == MAX_IMPORTS_QUERY_SCAN // MAX_COUNT


# -- wire-shape projection ---------------------------------------------------


def test_import_match_view_projects_single_row():
    view = import_match_view(
        Import(ea=Address(0x401000), name="CreateFileW", module="kernel32.dll", ordinal=42)
    )

    assert view == {
        "name": "CreateFileW",
        "address": "0x401000",
        "module": "kernel32.dll",
        "ordinal": 42,
    }


def test_import_match_view_carries_null_ordinal():
    view = import_match_view(
        Import(ea=Address(0x402008), name="recv", module="ws2_32.dll", ordinal=None)
    )

    assert view["ordinal"] is None
    assert view["address"] == "0x402008"


def test_imports_query_view_projects_matches_and_truncated_flag():
    from idamesh.application.dto.imports_query import ImportsQueryResult

    result = ImportsQueryResult(
        matches=(
            Import(ea=Address(0x401000), name="CreateFileW", module="kernel32.dll"),
            Import(ea=Address(0x401008), name="connect", module="ws2_32.dll", ordinal=4),
        ),
        truncated=True,
    )

    view = imports_query_view(result)

    assert view["truncated"] is True
    assert [m["name"] for m in view["matches"]] == ["CreateFileW", "connect"]
    assert view["matches"][0]["ordinal"] is None
    assert view["matches"][1] == {
        "name": "connect",
        "address": "0x401008",
        "module": "ws2_32.dll",
        "ordinal": 4,
    }


def test_imports_query_view_of_empty_result():
    from idamesh.application.dto.imports_query import ImportsQueryResult

    view = imports_query_view(ImportsQueryResult(matches=(), truncated=False))

    assert view == {"matches": [], "truncated": False}
