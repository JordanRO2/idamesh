"""Unit tests for the ``search_structs`` use-case and wire view (no IDA).

A fake :class:`StructGateway` stands in for the IDA adapter so the use-case's
substring-filter, case-insensitivity, and limit/truncation contract are exercised
without a database. The fake mirrors the adapter's port promise — a
case-insensitive substring filter that returns at most ``limit`` summaries in
enumeration order — so the use-case's "ask for one past the cap" truncation probe
is driven honestly. The ``SearchStructsView`` projection is covered over
hand-built results, keeping the whole module IDA-free.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from idamesh.application.contexts.search_structs import SearchStructsUseCase
from idamesh.application.dto.search_structs import (
    MAX_SEARCH_STRUCTS_LIMIT,
    SearchStructsCommand,
    SearchStructsResult,
)
from idamesh.domain.entities.struct_layout import StructLayout
from idamesh.domain.entities.struct_summary import StructSummary
from idamesh.interface.catalog.search_structs import (
    search_structs_view,
    struct_match_view,
)


class _FakeStructGateway:
    """In-memory ``StructGateway`` over a fixed, ordered list of summaries.

    ``list_structs`` reproduces the adapter's contract: a case-insensitive
    substring match (empty query matches all) yielding at most ``limit`` rows in
    the stored order. Every requested ``(query, limit)`` is recorded so tests can
    assert the use-case's one-past-the-cap probe.
    """

    def __init__(self, structs: List[StructSummary]) -> None:
        self._structs = structs
        self.requests: List[Tuple[str, int]] = []

    def list_structs(self, query: str, limit: int) -> List[StructSummary]:
        self.requests.append((query, limit))
        if limit <= 0:
            return []
        needle = query.casefold()
        hits = [s for s in self._structs if needle in s.name.casefold()]
        return hits[:limit]

    def layout(self, name: str) -> Optional[StructLayout]:  # pragma: no cover
        for s in self._structs:
            if s.name == name:
                return StructLayout(name=s.name, size=s.size)
        return None


def _summary(name: str, size: int = 8, members: int = 2) -> StructSummary:
    return StructSummary(name=name, size=size, member_count=members)


def _summaries(names: List[str]) -> List[StructSummary]:
    return [_summary(name) for name in names]


# -- substring matching ---------------------------------------------------


def test_matches_by_name_substring():
    gw = _FakeStructGateway(
        _summaries(["RUNTIME_FUNCTION", "UNWIND_INFO", "FuncInfo", "UnwindMapEntry"])
    )
    use_case = SearchStructsUseCase(gw)

    result = use_case.execute(SearchStructsCommand(query="Unwind"))

    assert [m.name for m in result.matches] == ["UNWIND_INFO", "UnwindMapEntry"]
    assert result.truncated is False


def test_match_is_case_insensitive():
    gw = _FakeStructGateway(_summaries(["_FILETIME", "LargeInteger", "m128a"]))
    use_case = SearchStructsUseCase(gw)

    # Lowercase query hits mixed-/upper-case names.
    result = use_case.execute(SearchStructsCommand(query="time"))

    assert [m.name for m in result.matches] == ["_FILETIME"]


def test_query_case_does_not_matter():
    gw = _FakeStructGateway(_summaries(["XMM_SAVE_AREA32", "M128A"]))
    use_case = SearchStructsUseCase(gw)

    # Upper-case query hits a lower-fragment name.
    result = use_case.execute(SearchStructsCommand(query="M128"))

    assert [m.name for m in result.matches] == ["M128A"]


def test_no_matches_yields_empty_untruncated():
    gw = _FakeStructGateway(_summaries(["alpha", "beta", "gamma"]))
    use_case = SearchStructsUseCase(gw)

    result = use_case.execute(SearchStructsCommand(query="zzz"))

    assert result.matches == ()
    assert result.truncated is False


def test_empty_gateway_yields_empty():
    use_case = SearchStructsUseCase(_FakeStructGateway([]))

    result = use_case.execute(SearchStructsCommand(query="anything"))

    assert result.matches == ()
    assert result.truncated is False


def test_empty_query_matches_every_struct():
    gw = _FakeStructGateway(_summaries(["a", "b", "c"]))
    use_case = SearchStructsUseCase(gw)

    result = use_case.execute(SearchStructsCommand(query=""))

    assert [m.name for m in result.matches] == ["a", "b", "c"]


# -- summary fields carried through ---------------------------------------


def test_summary_fields_are_carried_verbatim():
    gw = _FakeStructGateway([_summary("RUNTIME_FUNCTION", size=12, members=3)])
    use_case = SearchStructsUseCase(gw)

    (match,) = use_case.execute(SearchStructsCommand(query="RUNTIME")).matches

    assert isinstance(match, StructSummary)
    assert (match.name, match.size, match.member_count) == ("RUNTIME_FUNCTION", 12, 3)


def test_result_echoes_original_query_verbatim():
    gw = _FakeStructGateway(_summaries(["Init"]))
    use_case = SearchStructsUseCase(gw)

    result = use_case.execute(SearchStructsCommand(query="INIT"))

    # The echoed query preserves the caller's original casing.
    assert result.query == "INIT"


# -- limit and truncation -------------------------------------------------


def test_limit_caps_matches_and_flags_truncated():
    gw = _FakeStructGateway(_summaries(["s0", "s1", "s2", "s3", "s4"]))
    use_case = SearchStructsUseCase(gw)

    result = use_case.execute(SearchStructsCommand(query="s", limit=2))

    assert [m.name for m in result.matches] == ["s0", "s1"]
    assert result.truncated is True


def test_use_case_probes_one_past_the_cap():
    gw = _FakeStructGateway(_summaries(["s0", "s1", "s2"]))
    use_case = SearchStructsUseCase(gw)

    use_case.execute(SearchStructsCommand(query="s", limit=2))

    # A single gateway round-trip requesting one summary beyond the cap.
    assert gw.requests == [("s", 3)]


def test_exact_limit_is_not_truncated():
    gw = _FakeStructGateway(_summaries(["s0", "s1", "s2"]))
    use_case = SearchStructsUseCase(gw)

    result = use_case.execute(SearchStructsCommand(query="s", limit=3))

    assert len(result.matches) == 3
    assert result.truncated is False


def test_negative_limit_returns_no_matches_but_flags_truncated():
    gw = _FakeStructGateway(_summaries(["s0", "s1"]))
    use_case = SearchStructsUseCase(gw)

    result = use_case.execute(SearchStructsCommand(query="s", limit=-1))

    # A negative limit degenerates to zero; the existence of matches is still
    # signalled through ``truncated``.
    assert result.matches == ()
    assert result.truncated is True


def test_negative_limit_on_empty_set_is_not_truncated():
    gw = _FakeStructGateway([])
    use_case = SearchStructsUseCase(gw)

    result = use_case.execute(SearchStructsCommand(query="s", limit=-1))

    assert result.matches == ()
    assert result.truncated is False


def test_limit_clamped_to_server_maximum():
    names = [f"s_{i}" for i in range(MAX_SEARCH_STRUCTS_LIMIT + 5)]
    gw = _FakeStructGateway(_summaries(names))
    use_case = SearchStructsUseCase(gw)

    result = use_case.execute(SearchStructsCommand(query="s_", limit=10_000_000))

    assert len(result.matches) == MAX_SEARCH_STRUCTS_LIMIT
    assert result.truncated is True
    # The gateway was probed with the clamped cap plus one, never the raw request.
    assert gw.requests == [("s_", MAX_SEARCH_STRUCTS_LIMIT + 1)]


def test_default_limit_is_applied_when_unspecified():
    names = [f"s{i}" for i in range(MAX_SEARCH_STRUCTS_LIMIT + 5)]
    gw = _FakeStructGateway(_summaries(names))
    use_case = SearchStructsUseCase(gw)

    # Omitting ``limit`` uses the command default, not an unbounded scan.
    result = use_case.execute(SearchStructsCommand(query="s"))

    assert len(result.matches) <= MAX_SEARCH_STRUCTS_LIMIT
    assert result.truncated is True


# -- view projection ------------------------------------------------------


def test_struct_match_view_projects_single_summary():
    view = struct_match_view(_summary("RUNTIME_FUNCTION", size=12, members=3))

    assert view == {"name": "RUNTIME_FUNCTION", "size": 12, "member_count": 3}


def test_view_projects_result_to_wire_shape():
    result = SearchStructsResult(
        query="Unwind",
        matches=(
            _summary("UNWIND_INFO", size=4, members=6),
            _summary("UnwindMapEntry", size=8, members=2),
        ),
        truncated=True,
    )

    view = search_structs_view(result)

    assert view["query"] == "Unwind"
    assert view["truncated"] is True
    assert view["matches"] == [
        {"name": "UNWIND_INFO", "size": 4, "member_count": 6},
        {"name": "UnwindMapEntry", "size": 8, "member_count": 2},
    ]
