"""Unit tests for the ``func_query`` use-case and wire view (no IDA).

A fake :class:`~idamesh.domain.ports.functions.FunctionRepository` stands in for
the IDA adapter, so the tri-state / size-band / name-substring conjunction, the
limit/truncation contract, and the multi-page sweep are exercised on synthetic
:class:`~idamesh.domain.entities.function.Function` values with no database
present. The ``FuncQueryView`` projection is covered over hand-built results,
keeping the whole module IDA-free.
"""

from __future__ import annotations

from typing import List, Optional

from idamesh.application.contexts.func_query import FuncQueryUseCase
from idamesh.application.dto.func_query import (
    DEFAULT_FUNC_QUERY_LIMIT,
    MAX_FUNC_QUERY_LIMIT,
    FuncQueryCommand,
    FuncQueryResult,
)
from idamesh.domain.entities.function import Function
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import MAX_COUNT, Page, PageRequest
from idamesh.interface.catalog.func_query import func_match_view, func_query_view


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


def _func(
    addr: int,
    name: str,
    size: int = 0x10,
    *,
    is_library: bool = False,
    is_thunk: bool = False,
) -> Function:
    return Function(
        ea=Address(addr),
        name=name,
        size=size,
        is_library=is_library,
        is_thunk=is_thunk,
    )


def _use_case(funcs: List[Function]) -> FuncQueryUseCase:
    return FuncQueryUseCase(_FakeFunctionRepository(funcs))


def _names(result: FuncQueryResult) -> List[str]:
    return [f.name for f in result.matches]


# -- name substring -------------------------------------------------------


def test_name_substring_is_case_insensitive():
    use_case = _use_case(
        [
            _func(0x1000, "main"),
            _func(0x1010, "Sub_Encrypt"),
            _func(0x1020, "helper"),
            _func(0x1030, "encrypt_block"),
        ]
    )

    result = use_case.execute(FuncQueryCommand(name="ENCRYPT"))

    assert _names(result) == ["Sub_Encrypt", "encrypt_block"]
    assert result.truncated is False


def test_empty_name_matches_every_function():
    use_case = _use_case([_func(0x1000, "a"), _func(0x1010, "b"), _func(0x1020, "c")])

    result = use_case.execute(FuncQueryCommand(name=""))

    assert _names(result) == ["a", "b", "c"]


def test_whitespace_only_name_does_not_filter():
    use_case = _use_case([_func(0x1000, "alpha"), _func(0x1010, "beta")])

    # A name of only whitespace strips to empty and adds no predicate.
    result = use_case.execute(FuncQueryCommand(name="   "))

    assert _names(result) == ["alpha", "beta"]


# -- size band ------------------------------------------------------------


def test_min_size_is_an_inclusive_lower_bound():
    use_case = _use_case(
        [
            _func(0x1000, "small", size=0x10),
            _func(0x1010, "edge", size=0x20),
            _func(0x1020, "big", size=0x40),
        ]
    )

    result = use_case.execute(FuncQueryCommand(min_size=0x20))

    # 0x20 is kept (inclusive); 0x10 is dropped.
    assert _names(result) == ["edge", "big"]


def test_max_size_is_an_inclusive_upper_bound():
    use_case = _use_case(
        [
            _func(0x1000, "small", size=0x10),
            _func(0x1010, "edge", size=0x20),
            _func(0x1020, "big", size=0x40),
        ]
    )

    result = use_case.execute(FuncQueryCommand(max_size=0x20))

    # 0x20 is kept (inclusive); 0x40 is dropped.
    assert _names(result) == ["small", "edge"]


def test_size_band_keeps_functions_between_bounds():
    use_case = _use_case(
        [
            _func(0x1000, "tiny", size=0x10),
            _func(0x1010, "lo", size=0x20),
            _func(0x1020, "hi", size=0x30),
            _func(0x1030, "huge", size=0x40),
        ]
    )

    result = use_case.execute(FuncQueryCommand(min_size=0x20, max_size=0x30))

    assert _names(result) == ["lo", "hi"]


def test_zero_max_size_leaves_upper_end_unbounded():
    use_case = _use_case(
        [
            _func(0x1000, "small", size=0x10),
            _func(0x1010, "mid", size=0x20),
            _func(0x1020, "enormous", size=0x100000),
        ]
    )

    result = use_case.execute(FuncQueryCommand(min_size=0x20, max_size=0))

    assert _names(result) == ["mid", "enormous"]


def test_zero_min_size_leaves_lower_end_unbounded():
    use_case = _use_case(
        [
            _func(0x1000, "tiny", size=0x08),
            _func(0x1010, "mid", size=0x20),
            _func(0x1020, "big", size=0x40),
        ]
    )

    result = use_case.execute(FuncQueryCommand(min_size=0, max_size=0x20))

    assert _names(result) == ["tiny", "mid"]


# -- tri-state flags ------------------------------------------------------


def test_is_library_true_keeps_only_library_functions():
    use_case = _use_case(
        [
            _func(0x1000, "user_fn", is_library=False),
            _func(0x1010, "lib_fn", is_library=True),
        ]
    )

    result = use_case.execute(FuncQueryCommand(is_library=True))

    assert _names(result) == ["lib_fn"]


def test_is_library_false_keeps_only_non_library_functions():
    use_case = _use_case(
        [
            _func(0x1000, "user_fn", is_library=False),
            _func(0x1010, "lib_fn", is_library=True),
        ]
    )

    result = use_case.execute(FuncQueryCommand(is_library=False))

    assert _names(result) == ["user_fn"]


def test_is_library_none_ignores_the_flag():
    use_case = _use_case(
        [
            _func(0x1000, "user_fn", is_library=False),
            _func(0x1010, "lib_fn", is_library=True),
        ]
    )

    result = use_case.execute(FuncQueryCommand(is_library=None))

    assert _names(result) == ["user_fn", "lib_fn"]


def test_is_thunk_true_keeps_only_thunks():
    use_case = _use_case(
        [
            _func(0x1000, "real_fn", is_thunk=False),
            _func(0x1010, "thunk_fn", is_thunk=True),
        ]
    )

    result = use_case.execute(FuncQueryCommand(is_thunk=True))

    assert _names(result) == ["thunk_fn"]


def test_is_thunk_false_keeps_only_non_thunks():
    use_case = _use_case(
        [
            _func(0x1000, "real_fn", is_thunk=False),
            _func(0x1010, "thunk_fn", is_thunk=True),
        ]
    )

    result = use_case.execute(FuncQueryCommand(is_thunk=False))

    assert _names(result) == ["real_fn"]


def test_flags_combine_as_a_conjunction():
    use_case = _use_case(
        [
            _func(0x1000, "lib_thunk", is_library=True, is_thunk=True),
            _func(0x1010, "lib_real", is_library=True, is_thunk=False),
            _func(0x1020, "user_thunk", is_library=False, is_thunk=True),
        ]
    )

    # Library AND non-thunk: only lib_real satisfies both.
    result = use_case.execute(FuncQueryCommand(is_library=True, is_thunk=False))

    assert _names(result) == ["lib_real"]


# -- cross-dimension conjunction ------------------------------------------


def test_name_size_and_flag_combine_as_conjunction():
    use_case = _use_case(
        [
            # Matches every clause.
            _func(0x1000, "aes_encrypt", size=0x80, is_library=False),
            # Right name/flag, size too small.
            _func(0x1010, "aes_decrypt", size=0x10, is_library=False),
            # Right name/size, but a library function.
            _func(0x1020, "aes_expand", size=0x80, is_library=True),
            # Right size/flag, wrong name.
            _func(0x1030, "memcpy", size=0x80, is_library=False),
        ]
    )

    result = use_case.execute(
        FuncQueryCommand(
            name="aes", min_size=0x40, max_size=0x100, is_library=False
        )
    )

    assert _names(result) == ["aes_encrypt"]


# -- limit and truncation -------------------------------------------------


def test_limit_caps_matches_and_flags_truncated():
    use_case = _use_case([_func(0x1000 + i * 0x10, f"fn{i}") for i in range(5)])

    result = use_case.execute(FuncQueryCommand(name="fn", limit=2))

    assert _names(result) == ["fn0", "fn1"]
    assert result.truncated is True


def test_exact_limit_is_not_truncated():
    use_case = _use_case([_func(0x1000 + i * 0x10, f"fn{i}") for i in range(3)])

    result = use_case.execute(FuncQueryCommand(name="fn", limit=3))

    assert len(result.matches) == 3
    assert result.truncated is False


def test_negative_limit_yields_no_matches_but_flags_truncated():
    use_case = _use_case([_func(0x1000, "fn0"), _func(0x1010, "fn1")])

    result = use_case.execute(FuncQueryCommand(name="fn", limit=-1))

    # A negative limit degenerates to zero; the presence of matches is still
    # signalled through ``truncated``.
    assert result.matches == ()
    assert result.truncated is True


def test_limit_clamped_to_server_maximum():
    # More matches than the hard ceiling, spread across the paging boundary.
    funcs = [
        _func(0x140000000 + i * 0x10, f"fn_{i}")
        for i in range(MAX_FUNC_QUERY_LIMIT + 5)
    ]
    use_case = _use_case(funcs)

    result = use_case.execute(FuncQueryCommand(name="fn_", limit=10_000_000))

    assert len(result.matches) == MAX_FUNC_QUERY_LIMIT
    assert result.truncated is True


# -- paging across repository round-trips ---------------------------------


def test_enumerates_across_multiple_pages():
    # One matching function lives strictly beyond the first repository page,
    # so it is only found if the use-case walks past the page boundary.
    funcs = [_func(0x1000 + i * 0x10, f"filler_{i}") for i in range(MAX_COUNT)]
    funcs.append(_func(0x1000 + MAX_COUNT * 0x10, "needle_fn"))
    repo = _FakeFunctionRepository(funcs)
    use_case = FuncQueryUseCase(repo)

    result = use_case.execute(FuncQueryCommand(name="needle"))

    assert _names(result) == ["needle_fn"]
    assert result.truncated is False
    # It took a second round-trip past the first full page to reach the match.
    assert len(repo.requests) >= 2
    assert repo.requests[1].offset == MAX_COUNT


# -- degenerate repositories ----------------------------------------------


def test_empty_repository_yields_empty():
    use_case = _use_case([])

    result = use_case.execute(FuncQueryCommand(name="anything"))

    assert result.matches == ()
    assert result.truncated is False


def test_no_matches_yields_empty_untruncated():
    use_case = _use_case([_func(0x1000, "alpha"), _func(0x1010, "beta")])

    result = use_case.execute(FuncQueryCommand(name="zzz"))

    assert result.matches == ()
    assert result.truncated is False


# -- view projection ------------------------------------------------------


def test_func_match_view_projects_single_function():
    view = func_match_view(
        _func(0x140001000, "sub_x", size=0x2A, is_library=True, is_thunk=False)
    )

    assert view == {
        "name": "sub_x",
        "address": "0x140001000",
        "size": 0x2A,
        "is_library": True,
        "is_thunk": False,
    }


def test_func_query_view_projects_result_to_wire_shape():
    result = FuncQueryResult(
        matches=(
            _func(0x401000, "encrypt", size=0x40, is_library=False, is_thunk=False),
            _func(0x401080, "puts", size=0x08, is_library=True, is_thunk=True),
        ),
        truncated=True,
    )

    view = func_query_view(result)

    assert view["truncated"] is True
    assert view["matches"] == [
        {
            "name": "encrypt",
            "address": "0x401000",
            "size": 0x40,
            "is_library": False,
            "is_thunk": False,
        },
        {
            "name": "puts",
            "address": "0x401080",
            "size": 0x08,
            "is_library": True,
            "is_thunk": True,
        },
    ]


def test_empty_result_view_has_no_matches():
    view = func_query_view(FuncQueryResult(matches=(), truncated=False))

    assert view == {"matches": [], "truncated": False}


# -- command defaults -----------------------------------------------------


def test_command_defaults_are_the_frozen_contract():
    command = FuncQueryCommand()

    assert command.name == ""
    assert command.min_size == 0
    assert command.max_size == 0
    assert command.is_library is None
    assert command.is_thunk is None
    assert command.limit == DEFAULT_FUNC_QUERY_LIMIT
