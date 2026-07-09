"""Unit tests for the ``lookup_funcs`` use-case and wire view (no IDA).

A fake :class:`FunctionRepository` stands in for the IDA adapter so the
use-case's substring-filter, case-insensitivity, limit/truncation and paging
contract are exercised without a database. The ``LookupFuncsView`` projection is
covered over hand-built results, keeping the whole module IDA-free.
"""

from __future__ import annotations

from typing import List, Optional

from idamesh.application.contexts.lookup_funcs import LookupFuncsUseCase
from idamesh.application.dto.lookup_funcs import (
    MAX_LOOKUP_LIMIT,
    LookupFuncsCommand,
    LookupFuncsResult,
)
from idamesh.domain.entities.func_ref import FuncRef
from idamesh.domain.entities.function import Function
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import MAX_COUNT, Page, PageRequest
from idamesh.interface.catalog.lookup_funcs import (
    lookup_funcs_view,
    lookup_match_view,
)


class _FakeFunctionRepository:
    """An in-memory ``FunctionRepository`` over a fixed, address-ordered list."""

    def __init__(self, funcs: List[Function]) -> None:
        self._funcs = funcs
        self.requests: List[PageRequest] = []

    def list(self, page: PageRequest) -> Page[Function]:
        self.requests.append(page)
        start = page.offset
        stop = start + page.count
        window = self._funcs[start:stop]
        return Page(
            items=window,
            offset=start,
            count=page.count,
            total=len(self._funcs),
            truncated=stop < len(self._funcs),
        )

    def count(self) -> int:
        return len(self._funcs)

    def get(self, ea: Address) -> Optional[Function]:  # pragma: no cover - unused
        for func in self._funcs:
            if func.ea == ea:
                return func
        return None

    def get_containing(
        self, ea: Address
    ) -> Optional[Function]:  # pragma: no cover - unused
        return None


def _func(addr: int, name: str) -> Function:
    return Function(ea=Address(addr), name=name, size=0x10)


def _funcs(names: List[str]) -> List[Function]:
    return [_func(0x140001000 + i * 0x10, name) for i, name in enumerate(names)]


# -- substring matching ---------------------------------------------------


def test_matches_by_name_substring():
    repo = _FakeFunctionRepository(
        _funcs(["main", "sub_encrypt", "helper", "encrypt_block"])
    )
    use_case = LookupFuncsUseCase(repo)

    result = use_case.execute(LookupFuncsCommand(query="encrypt"))

    assert [m.name for m in result.matches] == ["sub_encrypt", "encrypt_block"]
    assert result.truncated is False


def test_match_is_case_insensitive():
    repo = _FakeFunctionRepository(_funcs(["DecryptBuffer", "main", "sub_ENCRYPT"]))
    use_case = LookupFuncsUseCase(repo)

    # Lowercase query hits mixed-/upper-case names.
    result = use_case.execute(LookupFuncsCommand(query="crypt"))

    assert [m.name for m in result.matches] == ["DecryptBuffer", "sub_ENCRYPT"]


def test_query_case_does_not_matter():
    repo = _FakeFunctionRepository(_funcs(["MainLoop", "run"]))
    use_case = LookupFuncsUseCase(repo)

    # Upper-case query hits a lower-fragment name.
    result = use_case.execute(LookupFuncsCommand(query="MAIN"))

    assert [m.name for m in result.matches] == ["MainLoop"]


def test_no_matches_yields_empty_untruncated():
    repo = _FakeFunctionRepository(_funcs(["alpha", "beta", "gamma"]))
    use_case = LookupFuncsUseCase(repo)

    result = use_case.execute(LookupFuncsCommand(query="zzz"))

    assert result.matches == ()
    assert result.truncated is False


def test_empty_repository_yields_empty():
    use_case = LookupFuncsUseCase(_FakeFunctionRepository([]))

    result = use_case.execute(LookupFuncsCommand(query="anything"))

    assert result.matches == ()
    assert result.truncated is False


def test_empty_query_matches_every_function():
    repo = _FakeFunctionRepository(_funcs(["a", "b", "c"]))
    use_case = LookupFuncsUseCase(repo)

    result = use_case.execute(LookupFuncsCommand(query=""))

    assert [m.name for m in result.matches] == ["a", "b", "c"]


# -- projection to FuncRef ------------------------------------------------


def test_projects_matched_function_to_funcref():
    repo = _FakeFunctionRepository([_func(0x401234, "target")])
    use_case = LookupFuncsUseCase(repo)

    result = use_case.execute(LookupFuncsCommand(query="target"))

    (ref,) = result.matches
    assert isinstance(ref, FuncRef)
    assert ref.name == "target"
    assert ref.address == Address(0x401234)


def test_result_echoes_original_query_verbatim():
    repo = _FakeFunctionRepository(_funcs(["Init"]))
    use_case = LookupFuncsUseCase(repo)

    result = use_case.execute(LookupFuncsCommand(query="INIT"))

    # The echoed query preserves the caller's original casing.
    assert result.query == "INIT"


# -- limit and truncation -------------------------------------------------


def test_limit_caps_matches_and_flags_truncated():
    repo = _FakeFunctionRepository(_funcs(["fn0", "fn1", "fn2", "fn3", "fn4"]))
    use_case = LookupFuncsUseCase(repo)

    result = use_case.execute(LookupFuncsCommand(query="fn", limit=2))

    assert [m.name for m in result.matches] == ["fn0", "fn1"]
    assert result.truncated is True


def test_exact_limit_is_not_truncated():
    repo = _FakeFunctionRepository(_funcs(["fn0", "fn1", "fn2"]))
    use_case = LookupFuncsUseCase(repo)

    result = use_case.execute(LookupFuncsCommand(query="fn", limit=3))

    assert len(result.matches) == 3
    assert result.truncated is False


def test_negative_limit_returns_no_matches_but_flags_truncated():
    repo = _FakeFunctionRepository(_funcs(["fn0", "fn1"]))
    use_case = LookupFuncsUseCase(repo)

    result = use_case.execute(LookupFuncsCommand(query="fn", limit=-1))

    # A negative limit degenerates to zero; the existence of matches is still
    # signalled through ``truncated``.
    assert result.matches == ()
    assert result.truncated is True


def test_limit_clamped_to_server_maximum():
    # More matches than the hard ceiling, spread across the paging boundary.
    names = [f"fn_{i}" for i in range(MAX_LOOKUP_LIMIT + 5)]
    repo = _FakeFunctionRepository(_funcs(names))
    use_case = LookupFuncsUseCase(repo)

    result = use_case.execute(LookupFuncsCommand(query="fn_", limit=10_000_000))

    assert len(result.matches) == MAX_LOOKUP_LIMIT
    assert result.truncated is True


# -- paging across repository round-trips ---------------------------------


def test_enumerates_across_multiple_pages():
    # One matching function lives strictly beyond the first repository page,
    # so it is only found if the use-case walks past the page boundary.
    names = [f"filler_{i}" for i in range(MAX_COUNT)] + ["needle_fn"]
    repo = _FakeFunctionRepository(_funcs(names))
    use_case = LookupFuncsUseCase(repo)

    result = use_case.execute(LookupFuncsCommand(query="needle"))

    assert [m.name for m in result.matches] == ["needle_fn"]
    assert result.truncated is False
    # It took a second round-trip past the first full page to reach the match.
    assert len(repo.requests) >= 2
    assert repo.requests[1].offset == MAX_COUNT


# -- view projection ------------------------------------------------------


def test_lookup_match_view_projects_single_ref():
    view = lookup_match_view(FuncRef(address=Address(0x140001000), name="sub_x"))

    assert view == {"name": "sub_x", "address": "0x140001000"}


def test_view_projects_result_to_wire_shape():
    result = LookupFuncsResult(
        query="enc",
        matches=(
            FuncRef(address=Address(0x401000), name="encrypt"),
            FuncRef(address=Address(0x401080), name="do_encode"),
        ),
        truncated=True,
    )

    view = lookup_funcs_view(result)

    assert view["query"] == "enc"
    assert view["truncated"] is True
    assert view["matches"] == [
        {"name": "encrypt", "address": "0x401000"},
        {"name": "do_encode", "address": "0x401080"},
    ]
