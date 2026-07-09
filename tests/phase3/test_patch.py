"""Unit tests for the ``patch`` and ``patch_asm`` mutation tools (no IDA).

A fake :class:`PatchGateway` and a resolver-backed fake database replace the IDA
adapter, so the whole write path runs off-host: ``patch`` decodes its hex payload,
resolves a polymorphic selector, and writes the buffer; ``patch_asm`` validates the
assembly text, resolves the selector, assembles one instruction to machine bytes,
and patches those bytes in. The fake gateway records every write and every assemble
and can refuse one two ways — an unwritable region and an un-assemblable
instruction — mirroring the real adapter raising on ``ida_bytes.patch_bytes`` /
``idautils.Assemble`` failures. The ``PatchView`` / ``PatchAsmView`` projections and
the catalog registration (mutating annotation, write marshalling, ``isError``
surfacing) are exercised too, all without a database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, TypeVar

import pytest

from idamesh.application.contexts.patch import PatchAsmUseCase, PatchUseCase
from idamesh.application.dto.patch import (
    PatchAsmCommand,
    PatchAsmResult,
    PatchCommand,
    PatchResult,
)
from idamesh.domain.entities.patch import AsmPatch, BytePatch
from idamesh.domain.values.address import Address, Selector
from idamesh.interface.catalog.patch import patch_view, register_patch
from idamesh.interface.catalog.patch_asm import patch_asm_view, register_patch_asm
from idamesh.interface.mcp.engine import ToolError
from idamesh.interface.mcp.registry import Registry

T = TypeVar("T")


# -- fakes ------------------------------------------------------------------


class _FakeDatabase:
    """A resolver-backed database gateway over a fixed symbol table."""

    def __init__(self, symbols: dict[str, int] | None = None) -> None:
        self._symbols = symbols or {}

    def resolve_symbol(self, name: str) -> int | None:
        return self._symbols.get(name)

    def resolve(self, selector: Selector) -> Address:
        # Mirror the real gateway: numeric kinds parse directly, symbols look up.
        return selector.resolve(self)


@dataclass(frozen=True)
class _Write:
    """One recorded raw-byte write (the exact ea and buffer the gateway saw)."""

    ea: Address
    data: bytes


@dataclass(frozen=True)
class _Assembly:
    """One recorded assemble request (the exact ea and text the gateway saw)."""

    ea: Address
    text: str


class _FakePatchGateway:
    """In-memory ``PatchGateway`` that records writes/assemblies and can refuse them.

    ``patch_bytes`` records the resolved ea and buffer and returns the byte count,
    unless the ea is ``unwritable`` (mirroring ``ida_bytes.patch_bytes`` failing on a
    non-writable region). ``assemble`` records the resolved ea and *stripped* text
    and returns a fixed ``encoded`` buffer, unless the text is ``unassemblable``
    (mirroring ``idautils.Assemble`` returning ``(False, msg)`` for text the
    architecture cannot encode). Recording happens before any refusal so a test can
    assert exactly what reached the SDK.
    """

    def __init__(
        self,
        *,
        encoded: bytes = b"\x90",
        unassemblable: frozenset[str] = frozenset(),
        unwritable: frozenset[int] = frozenset(),
    ) -> None:
        self._encoded = encoded
        self._unassemblable = unassemblable
        self._unwritable = unwritable
        self.writes: list[_Write] = []
        self.assemblies: list[_Assembly] = []

    def patch_bytes(self, ea: Address, data: bytes) -> int:
        self.writes.append(_Write(ea=ea, data=bytes(data)))
        if int(ea) in self._unwritable:
            raise ValueError(f"region not writable at {ea.hex()}")
        return len(data)

    def assemble(self, ea: Address, text: str) -> bytes:
        self.assemblies.append(_Assembly(ea=ea, text=text))
        if text in self._unassemblable:
            raise ValueError(f"cannot assemble {text!r} at {ea.hex()}")
        return self._encoded


@dataclass
class _InlineExecutor:
    """A ``MainThreadExecutor`` that runs jobs inline, recording write affinity."""

    write_flags: list[bool] = field(default_factory=list)

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        self.write_flags.append(write)
        return job()

    def on_kernel_thread(self) -> bool:
        return True


# -- patch use-case: decode & write -----------------------------------------


def test_patch_decodes_hex_and_writes_at_resolved_ea():
    ea = 0x401000
    gateway = _FakePatchGateway()
    use_case = PatchUseCase(gateway, _FakeDatabase())

    result = use_case.execute(PatchCommand(address="0x401000", bytes="90 90"))

    assert isinstance(result, PatchResult)
    assert gateway.writes == [_Write(Address(ea), b"\x90\x90")]
    patch = result.patch
    assert isinstance(patch, BytePatch)
    assert patch.address == Address(ea)
    assert patch.size == 2


def test_patch_size_echoes_number_of_bytes_written():
    gateway = _FakePatchGateway()
    use_case = PatchUseCase(gateway, _FakeDatabase())

    result = use_case.execute(
        PatchCommand(address="0x401000", bytes="deadbeefcafe")
    )

    # Three whitespace-free octet pairs decode to six bytes; the size echoes that.
    assert result.patch.size == 6
    assert gateway.writes == [_Write(Address(0x401000), b"\xde\xad\xbe\xef\xca\xfe")]


@pytest.mark.parametrize(
    "payload, expected",
    [
        ("9090", b"\x90\x90"),
        ("90 90", b"\x90\x90"),
        ("  90\t90\n", b"\x90\x90"),
        ("de ad be ef", b"\xde\xad\xbe\xef"),
    ],
)
def test_patch_tolerates_whitespace_between_octets(payload: str, expected: bytes):
    gateway = _FakePatchGateway()
    use_case = PatchUseCase(gateway, _FakeDatabase())

    use_case.execute(PatchCommand(address="0x401000", bytes=payload))

    assert gateway.writes == [_Write(Address(0x401000), expected)]


def test_patch_resolves_decimal_and_symbol_addresses():
    sym_ea = 0x406060
    gateway = _FakePatchGateway()
    database = _FakeDatabase(symbols={"handler": sym_ea})
    use_case = PatchUseCase(gateway, database)

    dec = use_case.execute(PatchCommand(address="4198400", bytes="cc"))  # 0x401000
    assert dec.patch.address == Address(0x401000)

    sym = use_case.execute(PatchCommand(address="handler", bytes="cc"))
    assert sym.patch.address == Address(sym_ea)
    assert gateway.writes[-1].ea == Address(sym_ea)


# -- patch use-case: rejected hex (becomes isError at the boundary) ----------


@pytest.mark.parametrize("bad", ["", "   ", "zz", "9", "90 9", "90 9g", "0xff"])
def test_patch_rejects_bad_hex_without_touching_gateway(bad: str):
    gateway = _FakePatchGateway()
    use_case = PatchUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(PatchCommand(address="0x401000", bytes=bad))

    # A pure decode failure never resolves an address or reaches the write.
    assert gateway.writes == []


def test_patch_rejects_non_string_bytes():
    gateway = _FakePatchGateway()
    use_case = PatchUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(
            PatchCommand(address="0x401000", bytes=0x9090)  # type: ignore[arg-type]
        )
    assert gateway.writes == []


# -- patch use-case: failure paths ------------------------------------------


def test_patch_propagates_unwritable_region():
    orphan = 0x600100
    gateway = _FakePatchGateway(unwritable=frozenset({orphan}))
    use_case = PatchUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(PatchCommand(address=hex(orphan), bytes="90"))


def test_patch_propagates_unresolvable_symbol_before_writing():
    gateway = _FakePatchGateway()
    use_case = PatchUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(PatchCommand(address="missing", bytes="90"))
    # Resolution fails after a valid decode but before any write.
    assert gateway.writes == []


# -- patch_asm use-case: assemble then patch --------------------------------


def test_patch_asm_assembles_then_patches_the_encoding():
    ea = 0x401000
    gateway = _FakePatchGateway(encoded=b"\xeb\xfe")
    use_case = PatchAsmUseCase(gateway, _FakeDatabase())

    result = use_case.execute(PatchAsmCommand(address="0x401000", assembly="jmp $"))

    assert isinstance(result, PatchAsmResult)
    # The instruction was assembled at the resolved ea, then those bytes patched in.
    assert gateway.assemblies == [_Assembly(Address(ea), "jmp $")]
    assert gateway.writes == [_Write(Address(ea), b"\xeb\xfe")]
    patch = result.patch
    assert isinstance(patch, AsmPatch)
    assert patch.address == Address(ea)
    assert patch.data == b"\xeb\xfe"
    assert patch.size == 2


def test_patch_asm_strips_assembly_before_assembling():
    ea = 0x402000
    gateway = _FakePatchGateway(encoded=b"\x90")
    use_case = PatchAsmUseCase(gateway, _FakeDatabase())

    use_case.execute(PatchAsmCommand(address=hex(ea), assembly="  nop  "))

    # The gateway sees the trimmed instruction text, not the padded input.
    assert gateway.assemblies == [_Assembly(Address(ea), "nop")]


def test_patch_asm_resolves_symbol_address():
    sym_ea = 0x406060
    gateway = _FakePatchGateway(encoded=b"\xc3")
    database = _FakeDatabase(symbols={"handler": sym_ea})
    use_case = PatchAsmUseCase(gateway, database)

    result = use_case.execute(PatchAsmCommand(address="handler", assembly="ret"))

    assert gateway.assemblies == [_Assembly(Address(sym_ea), "ret")]
    assert result.patch.address == Address(sym_ea)


@pytest.mark.parametrize("blank", ["", "   ", "\t", "\n  \n"])
def test_patch_asm_rejects_empty_assembly_without_touching_gateway(blank: str):
    gateway = _FakePatchGateway()
    use_case = PatchAsmUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(PatchAsmCommand(address="0x401000", assembly=blank))

    # The guard runs first: neither an assemble nor a write was attempted.
    assert gateway.assemblies == []
    assert gateway.writes == []


def test_patch_asm_rejects_non_string_assembly():
    gateway = _FakePatchGateway()
    use_case = PatchAsmUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(
            PatchAsmCommand(address="0x401000", assembly=123)  # type: ignore[arg-type]
        )
    assert gateway.assemblies == []
    assert gateway.writes == []


def test_patch_asm_propagates_unsupported_assembly_and_skips_write():
    bad = "frobnicate %r9, [rax*3]"
    gateway = _FakePatchGateway(unassemblable=frozenset({bad}))
    use_case = PatchAsmUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(PatchAsmCommand(address="0x401000", assembly=bad))

    # The assemble was attempted and refused; no bytes were patched.
    assert gateway.assemblies == [_Assembly(Address(0x401000), bad)]
    assert gateway.writes == []


def test_patch_asm_propagates_unresolvable_symbol_before_assembling():
    gateway = _FakePatchGateway()
    use_case = PatchAsmUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(PatchAsmCommand(address="ghost", assembly="nop"))
    assert gateway.assemblies == []
    assert gateway.writes == []


# -- views ------------------------------------------------------------------


def test_patch_view_projects_to_flat_shape():
    view = patch_view(BytePatch(address=Address(0x401000), size=2))

    assert view == {"address": "0x401000", "size": 2, "ok": True}


def test_patch_asm_view_renders_encoding_as_lowercase_hex():
    view = patch_asm_view(
        AsmPatch(address=Address(0x14000A), data=b"\xeb\xfe", size=2)
    )

    assert view == {
        "address": "0x14000a",
        "bytes": "ebfe",
        "size": 2,
        "ok": True,
    }


# -- catalog registration ---------------------------------------------------


def _register_patch(gateway, database, executor):
    registry = Registry()
    register_patch(
        registry,
        patch_use_case=PatchUseCase(gateway, database),
        executor=executor,
    )
    return registry


def _register_patch_asm(gateway, database, executor):
    registry = Registry()
    register_patch_asm(
        registry,
        patch_asm_use_case=PatchAsmUseCase(gateway, database),
        executor=executor,
    )
    return registry


def test_patch_tool_is_registered_as_mutating_not_destructive():
    registry = _register_patch(_FakePatchGateway(), _FakeDatabase(), _InlineExecutor())

    spec = registry.get_tool("patch")
    assert spec is not None
    assert spec.annotations["readOnlyHint"] is False
    # Overwriting bytes is a mutation, but not flagged destructive in this batch.
    assert "destructiveHint" not in spec.annotations


def test_patch_asm_tool_is_registered_as_mutating():
    registry = _register_patch_asm(
        _FakePatchGateway(), _FakeDatabase(), _InlineExecutor()
    )

    spec = registry.get_tool("patch_asm")
    assert spec is not None
    assert spec.annotations["readOnlyHint"] is False
    assert "destructiveHint" not in spec.annotations


def test_patch_tool_invocation_writes_with_write_affinity():
    ea = 0x401000
    gateway = _FakePatchGateway()
    executor = _InlineExecutor()
    registry = _register_patch(gateway, _FakeDatabase(), executor)

    view = registry.get_tool("patch").invoke(address="0x401000", bytes="90 90")

    assert view == {"address": "0x401000", "size": 2, "ok": True}
    assert gateway.writes == [_Write(Address(ea), b"\x90\x90")]
    # The mutation was marshalled with explicit write affinity.
    assert executor.write_flags == [True]


def test_patch_tool_invocation_surfaces_bad_hex_as_tool_error():
    gateway = _FakePatchGateway()
    registry = _register_patch(gateway, _FakeDatabase(), _InlineExecutor())

    with pytest.raises(ToolError):
        registry.get_tool("patch").invoke(address="0x401000", bytes="zz")
    assert gateway.writes == []


def test_patch_tool_invocation_surfaces_unresolvable_address_as_tool_error():
    registry = _register_patch(_FakePatchGateway(), _FakeDatabase(), _InlineExecutor())

    with pytest.raises(ToolError):
        registry.get_tool("patch").invoke(address="ghost", bytes="90")


def test_patch_asm_tool_invocation_returns_encoding_hex_with_write_affinity():
    ea = 0x401000
    gateway = _FakePatchGateway(encoded=b"\xeb\xfe")
    executor = _InlineExecutor()
    registry = _register_patch_asm(gateway, _FakeDatabase(), executor)

    view = registry.get_tool("patch_asm").invoke(
        address="0x401000", assembly="  jmp $  "
    )

    assert view == {
        "address": "0x401000",
        "bytes": "ebfe",
        "size": 2,
        "ok": True,
    }
    # The stripped instruction reached the gateway at the resolved address.
    assert gateway.assemblies == [_Assembly(Address(ea), "jmp $")]
    assert executor.write_flags == [True]


def test_patch_asm_tool_invocation_surfaces_unsupported_assembly_as_tool_error():
    bad = "frobnicate %r9"
    gateway = _FakePatchGateway(unassemblable=frozenset({bad}))
    registry = _register_patch_asm(gateway, _FakeDatabase(), _InlineExecutor())

    with pytest.raises(ToolError):
        registry.get_tool("patch_asm").invoke(address="0x401000", assembly=bad)
    # Assembly was refused, so nothing was patched.
    assert gateway.writes == []
