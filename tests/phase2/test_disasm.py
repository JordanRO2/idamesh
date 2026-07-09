"""Unit tests for the ``disasm`` use-case and its wire view (no IDA).

Fake :class:`DisassemblyGateway` and :class:`DatabaseGateway` stand in for the
IDA adapters, so the use-case's selector resolution, count clamping, and
truncation inference — plus the ``DisasmView`` projection — are exercised
without a database.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from idamesh.application.contexts.disasm import DisasmUseCase
from idamesh.application.dto.disasm import (
    DEFAULT_DISASM_COUNT,
    MAX_DISASM_COUNT,
    DisasmCommand,
    DisasmResult,
)
from idamesh.domain.entities.disasm import DisasmLine
from idamesh.domain.values.address import Address, Selector


class _FakeDatabase:
    """A minimal ``DatabaseGateway`` that resolves selectors in-memory."""

    def __init__(self, symbols: Optional[Dict[str, int]] = None) -> None:
        self._symbols = symbols or {}
        self.resolved: List[Selector] = []

    def resolve_symbol(self, name: str) -> Optional[int]:
        return self._symbols.get(name)

    def resolve(self, selector: Selector) -> Address:
        self.resolved.append(selector)
        return selector.resolve(self)


class _FakeDisassembly:
    """A ``DisassemblyGateway`` that emits up to ``produced`` synthetic lines.

    It never returns more than the requested ``count`` (honoring the gateway
    contract) and records each ``(ea, count)`` call so the use-case's clamping
    can be asserted.
    """

    def __init__(self, produced: int) -> None:
        self._produced = produced
        self.calls: List[Tuple[int, int]] = []

    def disassemble(self, ea: Address, count: int) -> List[DisasmLine]:
        self.calls.append((int(ea), count))
        n = min(self._produced, count)
        return [
            DisasmLine(
                ea=Address(int(ea) + i * 4),
                text=f"insn_{i}",
                raw=bytes((0x90, i & 0xFF)),
            )
            for i in range(n)
        ]


def test_use_case_resolves_hex_and_returns_lines():
    db = _FakeDatabase()
    gateway = _FakeDisassembly(produced=3)
    use_case = DisasmUseCase(gateway, db)

    result = use_case.execute(DisasmCommand(address="0x401000", count=10))

    assert result.address == Address(0x401000)
    assert [line.text for line in result.lines] == ["insn_0", "insn_1", "insn_2"]
    # Fewer lines than the budget: the walk ran out, so nothing was truncated.
    assert result.truncated is False
    assert gateway.calls == [(0x401000, 10)]


def test_use_case_flags_truncation_when_budget_filled():
    gateway = _FakeDisassembly(produced=100)
    use_case = DisasmUseCase(gateway, _FakeDatabase())

    result = use_case.execute(DisasmCommand(address="0x401000", count=5))

    assert len(result.lines) == 5
    assert result.truncated is True
    assert gateway.calls[-1] == (0x401000, 5)


def test_use_case_clamps_count_to_server_maximum():
    gateway = _FakeDisassembly(produced=0)
    use_case = DisasmUseCase(gateway, _FakeDatabase())

    # Decimal selector, oversized count.
    use_case.execute(DisasmCommand(address="4198400", count=10_000_000))

    # The gateway sees a clamped budget, never the raw oversized count.
    assert gateway.calls[-1] == (4198400, MAX_DISASM_COUNT)


def test_use_case_resolves_symbol_via_database_and_applies_default_count():
    db = _FakeDatabase(symbols={"main": 0x401500})
    gateway = _FakeDisassembly(produced=1)
    use_case = DisasmUseCase(gateway, db)

    result = use_case.execute(DisasmCommand(address="main"))

    assert result.address == Address(0x401500)
    assert len(result.lines) == 1
    assert result.truncated is False
    # Omitted count falls back to the DTO default.
    assert gateway.calls[-1] == (0x401500, DEFAULT_DISASM_COUNT)
    assert db.resolved[-1].raw == "main"


def test_use_case_zero_count_returns_empty_and_not_truncated():
    gateway = _FakeDisassembly(produced=100)
    use_case = DisasmUseCase(gateway, _FakeDatabase())

    result = use_case.execute(DisasmCommand(address="0x401000", count=0))

    assert result.lines == ()
    assert result.truncated is False
    assert gateway.calls[-1] == (0x401000, 0)


def test_use_case_negative_count_is_clamped_to_zero():
    gateway = _FakeDisassembly(produced=100)
    use_case = DisasmUseCase(gateway, _FakeDatabase())

    result = use_case.execute(DisasmCommand(address="0x401000", count=-5))

    assert result.lines == ()
    assert result.truncated is False
    assert gateway.calls[-1] == (0x401000, 0)


def test_view_projects_lines_to_wire_shape():
    result = DisasmResult(
        address=Address(0x401000),
        lines=(
            DisasmLine(ea=Address(0x401000), text="push rbp", raw=b"\x55"),
            DisasmLine(ea=Address(0x401001), text="mov rbp, rsp", raw=b"\x48\x89\xe5"),
        ),
        truncated=True,
    )

    from idamesh.interface.catalog.disasm import disasm_view

    view = disasm_view(result)

    assert view["address"] == "0x401000"
    assert view["returned"] == 2
    assert view["truncated"] is True
    assert view["instructions"][0] == {
        "addr": "0x401000",
        "bytes": "55",
        "text": "push rbp",
    }
    assert view["instructions"][1] == {
        "addr": "0x401001",
        "bytes": "4889e5",
        "text": "mov rbp, rsp",
    }


def test_line_view_renders_empty_bytes_as_empty_string():
    from idamesh.interface.catalog.disasm import disasm_line_view

    view = disasm_line_view(DisasmLine(ea=Address(0x1000), text="nop", raw=b""))

    assert view == {"addr": "0x1000", "bytes": "", "text": "nop"}


def test_view_projects_empty_listing():
    from idamesh.interface.catalog.disasm import disasm_view

    view = disasm_view(DisasmResult(address=Address(0x1000), lines=(), truncated=False))

    assert view["address"] == "0x1000"
    assert view["instructions"] == []
    assert view["returned"] == 0
    assert view["truncated"] is False
