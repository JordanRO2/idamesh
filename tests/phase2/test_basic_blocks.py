"""Unit tests for the ``basic_blocks`` use-case and view (no IDA).

A fake :class:`BasicBlockGateway` and a fake database gateway stand in for the
IDA adapter, so the selector-resolution, per-call capping, and wire-projection
contracts of the tool are exercised without a database. The fake gateway
resolves through the real :class:`Selector`, covering hex, decimal, and symbol
inputs plus the unresolved-symbol failure path.
"""

from __future__ import annotations

import pytest

from idamesh.application.contexts.basic_blocks import BasicBlocksUseCase
from idamesh.application.dto.basic_blocks import (
    MAX_BASIC_BLOCKS,
    BasicBlocksCommand,
    BasicBlocksResult,
)
from idamesh.domain.entities.basic_block import BasicBlock
from idamesh.domain.values.address import Address, Selector
from idamesh.interface.catalog.basic_blocks import (
    basic_block_view,
    basic_blocks_view,
)


class _FakeDatabase:
    """A resolver-backed database gateway over a fixed symbol table."""

    def __init__(self, symbols: dict[str, int] | None = None) -> None:
        self._symbols = symbols or {}

    def resolve_symbol(self, name: str) -> int | None:
        return self._symbols.get(name)

    def resolve(self, selector: Selector) -> Address:
        # Mirror the real gateway: numeric kinds parse directly, symbols look up.
        return selector.resolve(self)


class _FakeBasicBlockGateway:
    """An in-memory ``BasicBlockGateway`` over a fixed function-to-blocks map."""

    def __init__(
        self,
        blocks: dict[int, list[BasicBlock]] | None = None,
        no_function: set[int] | None = None,
    ) -> None:
        self._blocks = blocks or {}
        self._no_function = no_function or set()
        self.blocks_seen: list[Address] = []

    def blocks(self, ea: Address) -> list[BasicBlock]:
        self.blocks_seen.append(ea)
        if int(ea) in self._no_function:
            raise LookupError(f"no function contains {ea.hex()}")
        return list(self._blocks.get(int(ea), []))


def _block(start: int, end: int, *succs: int) -> BasicBlock:
    return BasicBlock(
        start=Address(start),
        end=Address(end),
        successors=tuple(Address(s) for s in succs),
    )


# -- use-case ---------------------------------------------------------------


def test_basic_blocks_resolves_hex_and_returns_blocks():
    func = 0x401000
    gateway = _FakeBasicBlockGateway(
        blocks={
            func: [
                _block(0x401000, 0x401010, 0x401010, 0x401030),
                _block(0x401010, 0x401030, 0x401030),
                _block(0x401030, 0x401044),
            ]
        }
    )
    use_case = BasicBlocksUseCase(gateway, _FakeDatabase())

    result = use_case.execute(BasicBlocksCommand(address="0x401000"))

    assert result.func == Address(func)
    assert gateway.blocks_seen == [Address(func)]
    assert [b.start.value for b in result.blocks] == [0x401000, 0x401010, 0x401030]
    assert result.blocks[0].successors == (Address(0x401010), Address(0x401030))
    assert result.truncated is False


def test_basic_blocks_resolves_decimal_and_symbol():
    func = 0x408000
    gateway = _FakeBasicBlockGateway(
        blocks={4227072: [_block(4227072, 4227088)], func: [_block(func, func + 8)]}
    )
    database = _FakeDatabase(symbols={"start": func})
    use_case = BasicBlocksUseCase(gateway, database)

    dec = use_case.execute(BasicBlocksCommand(address="4227072"))
    assert dec.func == Address(4227072)

    sym = use_case.execute(BasicBlocksCommand(address="start"))
    assert sym.func == Address(func)
    assert sym.blocks[0].start == Address(func)


def test_basic_blocks_unresolvable_symbol_raises():
    use_case = BasicBlocksUseCase(_FakeBasicBlockGateway(), _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(BasicBlocksCommand(address="nope"))


def test_basic_blocks_caps_and_flags_truncation():
    func = 0x412000
    blocks = [
        _block(0x412000 + i * 4, 0x412000 + (i + 1) * 4)
        for i in range(MAX_BASIC_BLOCKS + 15)
    ]
    gateway = _FakeBasicBlockGateway(blocks={func: blocks})
    use_case = BasicBlocksUseCase(gateway, _FakeDatabase())

    result = use_case.execute(BasicBlocksCommand(address=hex(func)))

    assert len(result.blocks) == MAX_BASIC_BLOCKS
    assert result.truncated is True


def test_basic_blocks_at_limit_is_not_truncated():
    func = 0x413000
    blocks = [
        _block(0x413000 + i * 4, 0x413000 + (i + 1) * 4)
        for i in range(MAX_BASIC_BLOCKS)
    ]
    gateway = _FakeBasicBlockGateway(blocks={func: blocks})
    use_case = BasicBlocksUseCase(gateway, _FakeDatabase())

    result = use_case.execute(BasicBlocksCommand(address=hex(func)))

    assert len(result.blocks) == MAX_BASIC_BLOCKS
    assert result.truncated is False


def test_basic_blocks_out_of_function_propagates_error():
    orphan = 0x600100
    gateway = _FakeBasicBlockGateway(no_function={orphan})
    use_case = BasicBlocksUseCase(gateway, _FakeDatabase())

    with pytest.raises(LookupError):
        use_case.execute(BasicBlocksCommand(address=hex(orphan)))


# -- view -------------------------------------------------------------------


def test_basic_block_view_projects_span_and_successors():
    view = basic_block_view(_block(0x401000, 0x401010, 0x401010, 0x401030))

    assert view == {
        "start": "0x401000",
        "end": "0x401010",
        "successors": ["0x401010", "0x401030"],
    }


def test_basic_block_view_projects_terminal_block_without_successors():
    view = basic_block_view(_block(0x401030, 0x401044))

    assert view["start"] == "0x401030"
    assert view["end"] == "0x401044"
    assert view["successors"] == []


def test_basic_blocks_view_projects_result():
    result = BasicBlocksResult(
        func=Address(0x401000),
        blocks=(
            _block(0x401000, 0x401010, 0x401010),
            _block(0x401010, 0x401030),
        ),
        truncated=True,
    )

    view = basic_blocks_view(result)

    assert view["func"] == "0x401000"
    assert len(view["blocks"]) == 2
    assert view["blocks"][0]["successors"] == ["0x401010"]
    assert view["blocks"][1]["successors"] == []
    assert view["truncated"] is True
