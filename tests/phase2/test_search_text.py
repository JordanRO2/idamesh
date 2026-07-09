"""Unit tests for the ``search_text`` use-case and its wire view (no IDA).

A fake :class:`ListingSearchGateway` stands in for the IDA adapter, so the
use-case's limit clamping and truncation inference — plus the ``SearchTextView``
projection — are exercised without a database.
"""

from __future__ import annotations

from typing import List, Tuple

from idamesh.application.contexts.search_text import SearchTextUseCase
from idamesh.application.dto.search_text import (
    DEFAULT_SEARCH_TEXT_LIMIT,
    MAX_SEARCH_TEXT_LIMIT,
    SearchTextCommand,
    SearchTextResult,
)
from idamesh.domain.entities.text_match import TextMatch
from idamesh.domain.values.address import Address


class _FakeListingSearch:
    """A ``ListingSearchGateway`` that emits up to ``produced`` synthetic hits.

    It never returns more than the requested ``limit`` (honoring the gateway
    contract) and records each ``(text, limit)`` call so the use-case's clamping
    can be asserted.
    """

    def __init__(self, produced: int) -> None:
        self._produced = produced
        self.calls: List[Tuple[str, int]] = []

    def search(self, text: str, limit: int) -> List[TextMatch]:
        self.calls.append((text, limit))
        n = min(self._produced, limit) if limit > 0 else 0
        return [
            TextMatch(address=Address(0x401000 + i * 0x10), line=f"line_{i} {text}")
            for i in range(n)
        ]


def test_use_case_returns_and_maps_matches():
    gateway = _FakeListingSearch(produced=3)
    use_case = SearchTextUseCase(gateway)

    result = use_case.execute(SearchTextCommand(text="mov", limit=10))

    assert result.text == "mov"
    assert [match.line for match in result.matches] == [
        "line_0 mov",
        "line_1 mov",
        "line_2 mov",
    ]
    assert [match.address for match in result.matches] == [
        Address(0x401000),
        Address(0x401010),
        Address(0x401020),
    ]
    # Fewer hits than the budget: the walk ran out, so nothing was truncated.
    assert result.truncated is False
    assert gateway.calls == [("mov", 10)]


def test_use_case_flags_truncation_when_budget_filled():
    gateway = _FakeListingSearch(produced=100)
    use_case = SearchTextUseCase(gateway)

    result = use_case.execute(SearchTextCommand(text="call", limit=5))

    assert len(result.matches) == 5
    assert result.truncated is True
    assert gateway.calls[-1] == ("call", 5)


def test_use_case_clamps_limit_to_server_maximum():
    gateway = _FakeListingSearch(produced=0)
    use_case = SearchTextUseCase(gateway)

    use_case.execute(SearchTextCommand(text="jmp", limit=10_000_000))

    # The gateway sees a clamped budget, never the raw oversized limit.
    assert gateway.calls[-1] == ("jmp", MAX_SEARCH_TEXT_LIMIT)


def test_use_case_applies_default_limit_when_omitted():
    gateway = _FakeListingSearch(produced=1)
    use_case = SearchTextUseCase(gateway)

    result = use_case.execute(SearchTextCommand(text="push"))

    assert len(result.matches) == 1
    assert result.truncated is False
    assert gateway.calls[-1] == ("push", DEFAULT_SEARCH_TEXT_LIMIT)


def test_use_case_zero_limit_returns_empty_and_not_truncated():
    gateway = _FakeListingSearch(produced=100)
    use_case = SearchTextUseCase(gateway)

    result = use_case.execute(SearchTextCommand(text="ret", limit=0))

    assert result.matches == ()
    assert result.truncated is False
    assert gateway.calls[-1] == ("ret", 0)


def test_use_case_negative_limit_is_clamped_to_zero():
    gateway = _FakeListingSearch(produced=100)
    use_case = SearchTextUseCase(gateway)

    result = use_case.execute(SearchTextCommand(text="ret", limit=-5))

    assert result.matches == ()
    assert result.truncated is False
    assert gateway.calls[-1] == ("ret", 0)


def test_use_case_exactly_filling_budget_is_truncated():
    # Boundary: as many hits as the budget marks the set truncated, since a
    # later match may have been elided by the cap.
    gateway = _FakeListingSearch(produced=4)
    use_case = SearchTextUseCase(gateway)

    result = use_case.execute(SearchTextCommand(text="lea", limit=4))

    assert len(result.matches) == 4
    assert result.truncated is True


def test_use_case_empty_query_is_passed_through():
    gateway = _FakeListingSearch(produced=2)
    use_case = SearchTextUseCase(gateway)

    result = use_case.execute(SearchTextCommand(text="", limit=10))

    assert result.text == ""
    assert gateway.calls[-1] == ("", 10)
    assert len(result.matches) == 2


def test_view_projects_matches_to_wire_shape():
    from idamesh.interface.catalog.search_text import search_text_view

    result = SearchTextResult(
        text="mov",
        matches=(
            TextMatch(address=Address(0x401000), line="mov rbp, rsp"),
            TextMatch(address=Address(0x401004), line="mov eax, 1"),
        ),
        truncated=True,
    )

    view = search_text_view(result)

    assert view["text"] == "mov"
    assert view["truncated"] is True
    assert view["matches"] == [
        {"address": "0x401000", "line": "mov rbp, rsp"},
        {"address": "0x401004", "line": "mov eax, 1"},
    ]


def test_view_projects_empty_result():
    from idamesh.interface.catalog.search_text import search_text_view

    view = search_text_view(
        SearchTextResult(text="absent", matches=(), truncated=False)
    )

    assert view["text"] == "absent"
    assert view["matches"] == []
    assert view["truncated"] is False


def test_single_match_view_shape():
    from idamesh.interface.catalog.search_text import text_match_view

    view = text_match_view(TextMatch(address=Address(0x1000), line="nop"))

    assert view == {"address": "0x1000", "line": "nop"}
