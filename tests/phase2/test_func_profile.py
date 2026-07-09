"""Unit tests for the ``func_profile`` use-case and view (no IDA).

Fakes for the three consumed ports — a resolver-backed database gateway, a
function repository answering containment, a cross-reference repository, and a
basic-block gateway — stand in for the IDA adapters, so selector resolution,
entry-point anchoring, metric aggregation (block/edge/caller/callee counts), and
wire projection are all exercised without a database. The fake gateway resolves
through the real :class:`Selector`, covering hex, decimal, and symbol inputs plus
the unresolved-symbol and out-of-function failure paths.
"""

from __future__ import annotations

import pytest

from idamesh.application.contexts.func_profile import FuncProfileUseCase
from idamesh.application.dto.func_profile import (
    FuncProfileCommand,
    FuncProfileResult,
)
from idamesh.domain.entities.basic_block import BasicBlock
from idamesh.domain.entities.func_profile import FuncProfile
from idamesh.domain.entities.function import Function
from idamesh.domain.entities.xref import Xref, XrefKind, XrefType
from idamesh.domain.values.address import Address, Selector
from idamesh.interface.catalog.func_profile import func_profile_view


class _FakeDatabase:
    """A resolver-backed database gateway over a fixed symbol table."""

    def __init__(self, symbols: dict[str, int] | None = None) -> None:
        self._symbols = symbols or {}

    def resolve_symbol(self, name: str) -> int | None:
        return self._symbols.get(name)

    def resolve(self, selector: Selector) -> Address:
        # Mirror the real gateway: numeric kinds parse directly, symbols look up.
        return selector.resolve(self)


class _FakeFunctions:
    """An in-memory ``FunctionRepository`` answering containment lookups."""

    def __init__(self, containing: dict[int, Function] | None = None) -> None:
        self._containing = containing or {}
        self.get_containing_seen: list[Address] = []

    def get_containing(self, ea: Address) -> Function | None:
        self.get_containing_seen.append(ea)
        return self._containing.get(int(ea))


class _FakeXrefs:
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


class _FakeBlocks:
    """An in-memory ``BasicBlockGateway`` over a fixed per-entry block map."""

    def __init__(self, blocks: dict[int, list[BasicBlock]] | None = None) -> None:
        self._blocks = blocks or {}
        self.blocks_seen: list[Address] = []

    def blocks(self, ea: Address) -> list[BasicBlock]:
        self.blocks_seen.append(ea)
        return list(self._blocks.get(int(ea), []))


def _function(ea: int, name: str, size: int) -> Function:
    return Function(ea=Address(ea), name=name, size=size)


def _block(start: int, end: int, *successors: int) -> BasicBlock:
    return BasicBlock(
        start=Address(start),
        end=Address(end),
        successors=tuple(Address(s) for s in successors),
    )


def _inbound(src: int, dst: int, func: str | None) -> Xref:
    return Xref(
        source=Address(src),
        target=Address(dst),
        kind=XrefKind.CODE,
        ref_type=XrefType.CALL,
        source_func=func,
    )


def _call_edge(src: int, dst: int, name: str | None) -> Xref:
    return Xref(
        source=Address(src),
        target=Address(dst),
        kind=XrefKind.CODE,
        ref_type=XrefType.CALL,
        target_name=name,
    )


# -- use-case ---------------------------------------------------------------


def test_func_profile_resolves_hex_and_aggregates_all_metrics():
    entry = 0x401000
    func = _function(entry, "process", size=0x120)
    functions = _FakeFunctions(containing={entry: func})
    blocks = _FakeBlocks(
        blocks={
            entry: [
                _block(0x401000, 0x401010, 0x401010, 0x401030),
                _block(0x401010, 0x401030, 0x401030),
                _block(0x401030, 0x401120),
            ]
        }
    )
    xrefs = _FakeXrefs(
        refs={entry: [_inbound(0x402000, entry, "a"), _inbound(0x403000, entry, "b")]},
        calls={entry: [_call_edge(0x401014, 0x409000, "helper")]},
    )
    use_case = FuncProfileUseCase(functions, xrefs, blocks, _FakeDatabase())

    result = use_case.execute(FuncProfileCommand(address="0x401000"))

    profile = result.profile
    assert profile.address == Address(entry)
    assert profile.name == "process"
    assert profile.size == 0x120
    assert profile.block_count == 3
    # Edge count is the sum of every block's successor fan-out (2 + 1 + 0).
    assert profile.edge_count == 3
    assert profile.caller_count == 2
    assert profile.callee_count == 1


def test_func_profile_resolves_symbol_anchor():
    entry = 0x408000
    func = _function(entry, "start", size=0x40)
    functions = _FakeFunctions(containing={entry: func})
    blocks = _FakeBlocks(blocks={entry: [_block(0x408000, 0x408040)]})
    xrefs = _FakeXrefs()
    database = _FakeDatabase(symbols={"start": entry})
    use_case = FuncProfileUseCase(functions, xrefs, blocks, database)

    result = use_case.execute(FuncProfileCommand(address="start"))

    assert result.profile.address == Address(entry)
    assert result.profile.name == "start"


def test_func_profile_resolves_decimal():
    entry = 4198400  # 0x401000
    func = _function(entry, "dec_fn", size=0x10)
    functions = _FakeFunctions(containing={entry: func})
    use_case = FuncProfileUseCase(functions, _FakeXrefs(), _FakeBlocks(), _FakeDatabase())

    result = use_case.execute(FuncProfileCommand(address="4198400"))

    assert result.profile.address == Address(entry)


def test_func_profile_anchors_metrics_at_entry_not_interior_address():
    entry = 0x401000
    interior = 0x401044
    func = _function(entry, "outer", size=0x80)
    # An interior address maps to the same owning function as the entry.
    functions = _FakeFunctions(containing={entry: func, interior: func})
    blocks = _FakeBlocks(blocks={entry: [_block(0x401000, 0x401080)]})
    xrefs = _FakeXrefs(
        refs={entry: [_inbound(0x402000, entry, "caller")]},
        calls={entry: [_call_edge(0x401010, 0x409000, "callee")]},
    )
    use_case = FuncProfileUseCase(functions, xrefs, blocks, _FakeDatabase())

    result = use_case.execute(FuncProfileCommand(address=hex(interior)))

    # The profile reports the entry, and every port was queried at the entry.
    assert result.profile.address == Address(entry)
    assert blocks.blocks_seen == [Address(entry)]
    assert xrefs.refs_to_seen == [Address(entry)]
    assert xrefs.callees_seen == [Address(entry)]
    assert result.profile.caller_count == 1
    assert result.profile.callee_count == 1


def test_func_profile_empty_function_yields_zero_counts():
    entry = 0x401000
    func = _function(entry, "leaf", size=0x8)
    functions = _FakeFunctions(containing={entry: func})
    blocks = _FakeBlocks(blocks={entry: [_block(0x401000, 0x401008)]})
    use_case = FuncProfileUseCase(functions, _FakeXrefs(), blocks, _FakeDatabase())

    result = use_case.execute(FuncProfileCommand(address="0x401000"))

    assert result.profile.block_count == 1
    assert result.profile.edge_count == 0
    assert result.profile.caller_count == 0
    assert result.profile.callee_count == 0


def test_func_profile_out_of_function_raises():
    orphan = 0x600100
    functions = _FakeFunctions(containing={})  # get_containing -> None
    use_case = FuncProfileUseCase(functions, _FakeXrefs(), _FakeBlocks(), _FakeDatabase())

    with pytest.raises(LookupError):
        use_case.execute(FuncProfileCommand(address=hex(orphan)))


def test_func_profile_unresolvable_symbol_raises():
    functions = _FakeFunctions(containing={})
    use_case = FuncProfileUseCase(functions, _FakeXrefs(), _FakeBlocks(), _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(FuncProfileCommand(address="nope"))


# -- view -------------------------------------------------------------------


def test_func_profile_view_projects_result():
    result = FuncProfileResult(
        profile=FuncProfile(
            address=Address(0x401000),
            name="process",
            size=0x120,
            block_count=3,
            edge_count=4,
            caller_count=2,
            callee_count=5,
        )
    )

    view = func_profile_view(result)

    assert view == {
        "address": "0x401000",
        "name": "process",
        "size": 0x120,
        "block_count": 3,
        "edge_count": 4,
        "caller_count": 2,
        "callee_count": 5,
    }


def test_func_profile_view_preserves_null_name():
    result = FuncProfileResult(
        profile=FuncProfile(
            address=Address(0x401000),
            name=None,
            size=0,
            block_count=0,
            edge_count=0,
            caller_count=0,
            callee_count=0,
        )
    )

    view = func_profile_view(result)

    assert view["name"] is None
    assert view["address"] == "0x401000"
