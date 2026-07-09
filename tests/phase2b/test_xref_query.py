"""Unit tests for the ``xref_query`` use-case and view (no IDA).

``xref_query`` is the filtered cross-reference read tool: it resolves the
polymorphic ``address`` anchor, pulls the inbound edges (``direction="to"`` →
:meth:`XrefRepository.refs_to`) or the owning function's outbound call edges
(``direction="from"`` → :meth:`XrefRepository.callees`), and keeps the edges that
satisfy the shared pure :class:`Query` assembled from the ``kind`` / ``type``
filters, capped at a clamped ``limit``. A fake :class:`XrefRepository` and a
resolver-backed fake database gateway stand in for the IDA adapter, so
direction routing, kind/type filtering, filter-then-cap truncation, limit
clamping, enum validation, and the wire projection are all exercised without a
database present.
"""

from __future__ import annotations

import pytest

from idamesh.application.contexts.xref_query import XrefQueryUseCase
from idamesh.application.dto.xref_query import (
    DEFAULT_XREF_QUERY_LIMIT,
    MAX_XREF_QUERY_LIMIT,
    XrefQueryCommand,
    XrefQueryResult,
)
from idamesh.domain.entities.xref import Xref, XrefKind, XrefType
from idamesh.domain.values.address import Address, Selector
from idamesh.interface.catalog.xref_query import xref_edge_view, xref_query_view


class _FakeDatabase:
    """A resolver-backed database gateway over a fixed symbol table."""

    def __init__(self, symbols: dict[str, int] | None = None) -> None:
        self._symbols = symbols or {}

    def resolve_symbol(self, name: str) -> int | None:
        return self._symbols.get(name)

    def resolve(self, selector: Selector) -> Address:
        # Mirror the real gateway: numeric kinds parse directly, symbols look up.
        return selector.resolve(self)


class _FakeXrefRepository:
    """An in-memory ``XrefRepository`` over fixed inbound/outbound edge maps."""

    def __init__(
        self,
        refs: dict[int, list[Xref]] | None = None,
        calls: dict[int, list[Xref]] | None = None,
    ) -> None:
        self._refs = refs or {}
        self._calls = calls or {}
        self.refs_to_seen: list[Address] = []
        self.callees_seen: list[Address] = []

    def refs_to(self, ea: Address) -> list[Xref]:
        self.refs_to_seen.append(ea)
        return list(self._refs.get(int(ea), []))

    def callees(self, ea: Address) -> list[Xref]:
        self.callees_seen.append(ea)
        return list(self._calls.get(int(ea), []))


def _edge(
    src: int,
    dst: int,
    kind: XrefKind = XrefKind.CODE,
    ref_type: XrefType = XrefType.CALL,
    func: str | None = None,
    name: str | None = None,
) -> Xref:
    return Xref(
        source=Address(src),
        target=Address(dst),
        kind=kind,
        ref_type=ref_type,
        source_func=func,
        target_name=name,
    )


# -- direction routing ------------------------------------------------------


def test_direction_to_resolves_hex_and_pulls_inbound_edges():
    anchor = 0x401000
    repo = _FakeXrefRepository(
        refs={
            anchor: [
                _edge(0x401500, anchor, func="caller_a"),
                _edge(0x402200, anchor, func="caller_b"),
            ]
        },
        calls={anchor: [_edge(0x401010, 0x900000, name="unused")]},
    )
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    result = use_case.execute(XrefQueryCommand(address="0x401000"))

    assert result.anchor == Address(anchor)
    assert result.direction == "to"
    # Inbound path is chosen; the outbound map is left untouched.
    assert repo.refs_to_seen == [Address(anchor)]
    assert repo.callees_seen == []
    assert [edge.source_func for edge in result.xrefs] == ["caller_a", "caller_b"]
    assert result.truncated is False


def test_direction_from_pulls_outbound_call_edges():
    anchor = 0x401000
    repo = _FakeXrefRepository(
        refs={anchor: [_edge(0x500000, anchor, name="unused")]},
        calls={
            anchor: [
                _edge(0x401010, 0x402000, name="helper"),
                _edge(0x401030, 0x403000, name="printf"),
            ]
        },
    )
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    result = use_case.execute(XrefQueryCommand(address="0x401000", direction="from"))

    assert result.direction == "from"
    assert repo.callees_seen == [Address(anchor)]
    assert repo.refs_to_seen == []
    assert [edge.target.value for edge in result.xrefs] == [0x402000, 0x403000]


def test_direction_is_normalized_and_echoed():
    anchor = 0x401000
    repo = _FakeXrefRepository(refs={anchor: [_edge(0x401500, anchor)]})
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    result = use_case.execute(XrefQueryCommand(address=hex(anchor), direction="  TO  "))

    assert result.direction == "to"
    assert repo.refs_to_seen == [Address(anchor)]


# -- address resolution -----------------------------------------------------


def test_resolves_decimal_and_symbol_anchor():
    sym_ea = 0x404040
    repo = _FakeXrefRepository(refs={4198400: [], sym_ea: []})
    database = _FakeDatabase(symbols={"handler": sym_ea})
    use_case = XrefQueryUseCase(repo, database)

    dec = use_case.execute(XrefQueryCommand(address="4198400"))
    assert dec.anchor == Address(4198400)

    sym = use_case.execute(XrefQueryCommand(address="handler"))
    assert sym.anchor == Address(sym_ea)


def test_unresolvable_symbol_raises():
    use_case = XrefQueryUseCase(_FakeXrefRepository(), _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(XrefQueryCommand(address="nope"))


# -- kind / type filtering --------------------------------------------------


def test_any_kind_and_type_leaves_stream_unfiltered():
    anchor = 0x401000
    edges = [
        _edge(0x1000, anchor, XrefKind.CODE, XrefType.CALL),
        _edge(0x2000, anchor, XrefKind.DATA, XrefType.READ),
        _edge(0x3000, anchor, XrefKind.CODE, XrefType.JUMP),
    ]
    repo = _FakeXrefRepository(refs={anchor: edges})
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    result = use_case.execute(XrefQueryCommand(address=hex(anchor)))

    assert len(result.xrefs) == 3


def test_kind_filter_keeps_only_matching_kind():
    anchor = 0x401000
    edges = [
        _edge(0x1000, anchor, XrefKind.CODE, XrefType.CALL),
        _edge(0x2000, anchor, XrefKind.DATA, XrefType.READ),
        _edge(0x3000, anchor, XrefKind.DATA, XrefType.WRITE),
    ]
    repo = _FakeXrefRepository(refs={anchor: edges})
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    result = use_case.execute(XrefQueryCommand(address=hex(anchor), kind="data"))

    assert {edge.kind for edge in result.xrefs} == {XrefKind.DATA}
    assert len(result.xrefs) == 2


def test_kind_filter_is_case_insensitive():
    anchor = 0x401000
    edges = [
        _edge(0x1000, anchor, XrefKind.CODE, XrefType.CALL),
        _edge(0x2000, anchor, XrefKind.DATA, XrefType.READ),
    ]
    repo = _FakeXrefRepository(refs={anchor: edges})
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    result = use_case.execute(XrefQueryCommand(address=hex(anchor), kind="  CODE "))

    assert [edge.kind for edge in result.xrefs] == [XrefKind.CODE]


def test_type_filter_keeps_only_matching_type():
    anchor = 0x401000
    edges = [
        _edge(0x1000, anchor, XrefKind.CODE, XrefType.CALL),
        _edge(0x2000, anchor, XrefKind.CODE, XrefType.JUMP),
        _edge(0x3000, anchor, XrefKind.CODE, XrefType.CALL),
    ]
    repo = _FakeXrefRepository(refs={anchor: edges})
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    result = use_case.execute(XrefQueryCommand(address=hex(anchor), type="jump"))

    assert [edge.ref_type for edge in result.xrefs] == [XrefType.JUMP]


def test_kind_and_type_filters_are_conjunctive():
    anchor = 0x401000
    edges = [
        _edge(0x1000, anchor, XrefKind.DATA, XrefType.WRITE),  # keep
        _edge(0x2000, anchor, XrefKind.DATA, XrefType.READ),  # wrong type
        _edge(0x3000, anchor, XrefKind.CODE, XrefType.WRITE),  # wrong kind
        _edge(0x4000, anchor, XrefKind.DATA, XrefType.WRITE),  # keep
    ]
    repo = _FakeXrefRepository(refs={anchor: edges})
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    result = use_case.execute(
        XrefQueryCommand(address=hex(anchor), kind="data", type="write")
    )

    assert [edge.source.value for edge in result.xrefs] == [0x1000, 0x4000]


# -- filter-then-cap truncation --------------------------------------------


def test_truncates_when_matches_exceed_limit():
    anchor = 0x410000
    edges = [_edge(0x420000 + i * 4, anchor) for i in range(5)]
    repo = _FakeXrefRepository(refs={anchor: edges})
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    result = use_case.execute(XrefQueryCommand(address=hex(anchor), limit=2))

    assert len(result.xrefs) == 2
    assert result.truncated is True


def test_exactly_at_limit_is_not_truncated():
    anchor = 0x411000
    edges = [_edge(0x430000 + i * 4, anchor) for i in range(2)]
    repo = _FakeXrefRepository(refs={anchor: edges})
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    result = use_case.execute(XrefQueryCommand(address=hex(anchor), limit=2))

    assert len(result.xrefs) == 2
    assert result.truncated is False


def test_non_matching_edges_do_not_count_toward_limit_or_truncate():
    # Only edges passing the filter consume the budget; a non-matching tail must
    # not falsely flag truncation.
    anchor = 0x412000
    edges = [
        _edge(0x1000, anchor, XrefKind.DATA),  # keep 1
        _edge(0x2000, anchor, XrefKind.CODE),  # skip
        _edge(0x3000, anchor, XrefKind.DATA),  # keep 2
        _edge(0x4000, anchor, XrefKind.CODE),  # skip
        _edge(0x5000, anchor, XrefKind.CODE),  # skip (tail, non-matching)
    ]
    repo = _FakeXrefRepository(refs={anchor: edges})
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    result = use_case.execute(
        XrefQueryCommand(address=hex(anchor), kind="data", limit=2)
    )

    assert [edge.source.value for edge in result.xrefs] == [0x1000, 0x3000]
    assert result.truncated is False


def test_matching_edge_beyond_limit_flags_truncation_across_skips():
    anchor = 0x413000
    edges = [
        _edge(0x1000, anchor, XrefKind.DATA),  # keep 1
        _edge(0x2000, anchor, XrefKind.CODE),  # skip
        _edge(0x3000, anchor, XrefKind.DATA),  # keep 2
        _edge(0x4000, anchor, XrefKind.CODE),  # skip
        _edge(0x5000, anchor, XrefKind.DATA),  # matching, beyond limit -> truncate
    ]
    repo = _FakeXrefRepository(refs={anchor: edges})
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    result = use_case.execute(
        XrefQueryCommand(address=hex(anchor), kind="data", limit=2)
    )

    assert [edge.source.value for edge in result.xrefs] == [0x1000, 0x3000]
    assert result.truncated is True


def test_default_limit_caps_the_stream():
    anchor = 0x414000
    edges = [
        _edge(0x420000 + i * 4, anchor)
        for i in range(DEFAULT_XREF_QUERY_LIMIT + 20)
    ]
    repo = _FakeXrefRepository(refs={anchor: edges})
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    result = use_case.execute(XrefQueryCommand(address=hex(anchor)))

    assert len(result.xrefs) == DEFAULT_XREF_QUERY_LIMIT
    assert result.truncated is True


# -- limit clamping ---------------------------------------------------------


def test_limit_is_clamped_to_server_maximum():
    anchor = 0x415000
    edges = [
        _edge(0x440000 + i * 4, anchor)
        for i in range(MAX_XREF_QUERY_LIMIT + 1)
    ]
    repo = _FakeXrefRepository(refs={anchor: edges})
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    result = use_case.execute(
        XrefQueryCommand(address=hex(anchor), limit=MAX_XREF_QUERY_LIMIT + 500)
    )

    assert len(result.xrefs) == MAX_XREF_QUERY_LIMIT
    assert result.truncated is True


def test_negative_limit_clamps_to_zero_and_truncates_when_matches_exist():
    anchor = 0x416000
    repo = _FakeXrefRepository(refs={anchor: [_edge(0x1000, anchor)]})
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    result = use_case.execute(XrefQueryCommand(address=hex(anchor), limit=-5))

    assert result.xrefs == ()
    assert result.truncated is True


def test_zero_limit_with_no_matches_is_not_truncated():
    anchor = 0x417000
    # A single non-matching edge with a limit of zero: nothing to emit and no
    # matching edge is ever reached, so truncation stays False.
    repo = _FakeXrefRepository(refs={anchor: [_edge(0x1000, anchor, XrefKind.CODE)]})
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    result = use_case.execute(
        XrefQueryCommand(address=hex(anchor), kind="data", limit=0)
    )

    assert result.xrefs == ()
    assert result.truncated is False


# -- enum validation --------------------------------------------------------


def test_invalid_direction_raises_value_error():
    use_case = XrefQueryUseCase(_FakeXrefRepository(), _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(XrefQueryCommand(address="0x1000", direction="sideways"))


def test_invalid_kind_raises_value_error():
    use_case = XrefQueryUseCase(_FakeXrefRepository(), _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(XrefQueryCommand(address="0x1000", kind="pointer"))


def test_invalid_type_raises_value_error():
    use_case = XrefQueryUseCase(_FakeXrefRepository(), _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(XrefQueryCommand(address="0x1000", type="callish"))


def test_enum_validation_precedes_address_resolution():
    # An invalid enum must be rejected before the (unresolvable) anchor is
    # touched, and the repository is never consulted.
    repo = _FakeXrefRepository()
    use_case = XrefQueryUseCase(repo, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(XrefQueryCommand(address="unknown_symbol", kind="bogus"))

    assert repo.refs_to_seen == []
    assert repo.callees_seen == []


# -- wire projection --------------------------------------------------------


def test_xref_edge_view_projects_full_edge():
    view = xref_edge_view(
        _edge(
            0x401500,
            0x401000,
            XrefKind.CODE,
            XrefType.CALL,
            func="main",
            name="target_fn",
        )
    )

    assert view == {
        "from": "0x401500",
        "to": "0x401000",
        "kind": "code",
        "type": "call",
        "func": "main",
        "name": "target_fn",
    }


def test_xref_edge_view_carries_optional_nulls():
    view = xref_edge_view(
        _edge(0x403000, 0x601020, XrefKind.DATA, XrefType.WRITE)
    )

    assert view["kind"] == "data"
    assert view["type"] == "write"
    assert view["func"] is None
    assert view["name"] is None


def test_xref_query_view_projects_result():
    result = XrefQueryResult(
        anchor=Address(0x401000),
        direction="to",
        xrefs=(
            _edge(0x401500, 0x401000, func="a"),
            _edge(0x402000, 0x401000, XrefKind.DATA, XrefType.READ),
        ),
        truncated=True,
    )

    view = xref_query_view(result)

    assert view["anchor"] == "0x401000"
    assert view["direction"] == "to"
    assert len(view["xrefs"]) == 2
    assert view["xrefs"][0]["from"] == "0x401500"
    assert view["xrefs"][1]["kind"] == "data"
    assert view["truncated"] is True
