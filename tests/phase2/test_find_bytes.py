"""Unit tests for the ``find_bytes`` use-case and its wire view (no IDA).

A fake :class:`SearchGateway` stands in for the IDA adapter, so the use-case's
limit clamping, truncation inference, and unparseable-pattern propagation — plus
the ``FindBytesView`` projection — are exercised without a database.
"""

from __future__ import annotations

from typing import List

import pytest

from idamesh.application.contexts.find_bytes import FindBytesUseCase
from idamesh.application.dto.find_bytes import (
    DEFAULT_MATCH_LIMIT,
    MAX_MATCH_LIMIT,
    FindBytesCommand,
    FindBytesResult,
)
from idamesh.domain.entities.byte_match import ByteMatch
from idamesh.domain.values.address import Address
from idamesh.interface.catalog.find_bytes import byte_match_view, find_bytes_view


class _FakeSearchGateway:
    """An in-memory ``SearchGateway`` over a fixed pool of match addresses.

    Honors the port contract of returning *at most* ``limit`` addresses and
    records each ``(pattern, limit)`` call so the use-case's clamping can be
    asserted. A configured ``bad_pattern`` raises ``ValueError`` to model an
    unparseable pattern the adapter would reject.
    """

    def __init__(self, pool: List[int], *, bad_pattern: str | None = None) -> None:
        self._pool = pool
        self._bad_pattern = bad_pattern
        self.calls: List[tuple[str, int]] = []

    def find_bytes(self, pattern: str, limit: int) -> List[Address]:
        self.calls.append((pattern, limit))
        if self._bad_pattern is not None and pattern == self._bad_pattern:
            raise ValueError(f"unparseable byte pattern: {pattern!r}")
        return [Address(ea) for ea in self._pool[:limit]]


def _pool(n: int) -> List[int]:
    return [0x401000 + i * 4 for i in range(n)]


def test_use_case_returns_matches_as_byte_match_entities():
    gateway = _FakeSearchGateway(_pool(3))
    use_case = FindBytesUseCase(gateway)

    result = use_case.execute(FindBytesCommand(pattern="48 8B ?? 05", limit=10))

    assert result.pattern == "48 8B ?? 05"
    assert all(isinstance(m, ByteMatch) for m in result.matches)
    assert [m.address for m in result.matches] == [
        Address(0x401000),
        Address(0x401004),
        Address(0x401008),
    ]
    # Fewer hits than the budget: the whole image was scanned, nothing elided.
    assert result.truncated is False
    assert gateway.calls == [("48 8B ?? 05", 10)]


def test_use_case_flags_truncation_when_budget_filled():
    gateway = _FakeSearchGateway(_pool(100))
    use_case = FindBytesUseCase(gateway)

    result = use_case.execute(FindBytesCommand(pattern="90", limit=5))

    assert len(result.matches) == 5
    assert result.truncated is True
    assert gateway.calls[-1] == ("90", 5)


def test_use_case_clamps_limit_to_server_maximum():
    gateway = _FakeSearchGateway(_pool(0))
    use_case = FindBytesUseCase(gateway)

    use_case.execute(FindBytesCommand(pattern="cc", limit=1_000_000))

    # The gateway sees a clamped budget, never the raw oversized limit.
    assert gateway.calls[-1] == ("cc", MAX_MATCH_LIMIT)


def test_use_case_applies_default_limit_when_omitted():
    gateway = _FakeSearchGateway(_pool(2))
    use_case = FindBytesUseCase(gateway)

    result = use_case.execute(FindBytesCommand(pattern="ff"))

    assert gateway.calls[-1] == ("ff", DEFAULT_MATCH_LIMIT)
    assert result.truncated is False


def test_use_case_empty_result_is_not_truncated():
    gateway = _FakeSearchGateway(_pool(0))
    use_case = FindBytesUseCase(gateway)

    result = use_case.execute(FindBytesCommand(pattern="de ad be ef", limit=100))

    assert result.matches == ()
    assert result.truncated is False


def test_use_case_negative_limit_is_clamped_to_zero():
    gateway = _FakeSearchGateway(_pool(100))
    use_case = FindBytesUseCase(gateway)

    result = use_case.execute(FindBytesCommand(pattern="90", limit=-5))

    # A clamped-to-zero budget returns nothing and is never a truncation.
    assert result.matches == ()
    assert result.truncated is False
    assert gateway.calls[-1] == ("90", 0)


def test_use_case_propagates_unparseable_pattern():
    gateway = _FakeSearchGateway(_pool(0), bad_pattern="zz zz")
    use_case = FindBytesUseCase(gateway)

    with pytest.raises(ValueError):
        use_case.execute(FindBytesCommand(pattern="zz zz", limit=10))


def test_byte_match_view_projects_single_hit():
    assert byte_match_view(ByteMatch(address=Address(0x401000))) == {
        "address": "0x401000"
    }


def test_view_projects_result_to_wire_shape():
    result = FindBytesResult(
        pattern="48 8B ?? 05",
        matches=(
            ByteMatch(address=Address(0x401000)),
            ByteMatch(address=Address(0x40100A)),
        ),
        truncated=True,
    )

    view = find_bytes_view(result)

    assert view["pattern"] == "48 8B ?? 05"
    assert view["matches"] == [{"address": "0x401000"}, {"address": "0x40100a"}]
    assert view["truncated"] is True


def test_view_projects_empty_match_set():
    view = find_bytes_view(
        FindBytesResult(pattern="cc", matches=(), truncated=False)
    )

    assert view["pattern"] == "cc"
    assert view["matches"] == []
    assert view["truncated"] is False
