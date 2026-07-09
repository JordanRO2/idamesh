"""Unit tests for the ``read_struct`` use-case and view (no IDA).

A fake :class:`StructGateway` (returning a layout with int / char / pointer /
array fields, or ``None`` for an unknown name), a fake ``MemoryGateway`` over a
fixed byte map, and a fake ``DatabaseGateway`` (resolving through the real
:class:`Selector` and reporting a configurable endianness) stand in for the IDA
adapter. Together they exercise the selector resolution, the struct-layout lookup,
the pure per-field decode under both byte orders, and the two rendering paths
(scalar integer/hex vs. raw hex-bytes) without a database, plus the unknown-struct
and short-read failure paths.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import pytest

from idamesh.application.contexts.read_struct import ReadStructUseCase
from idamesh.application.dto.read_struct import ReadStructCommand
from idamesh.domain.entities.metadata import DatabaseMetadata, Endianness
from idamesh.domain.entities.struct_layout import StructField, StructLayout
from idamesh.domain.entities.struct_read import StructFieldValue, StructReadResult
from idamesh.domain.values.address import Address, Selector
from idamesh.interface.catalog.read_struct import read_struct_view


# -- fakes ------------------------------------------------------------------


class _FakeDatabase:
    """A resolver-backed database gateway with a fixed endianness and symbols."""

    def __init__(
        self,
        *,
        endianness: Endianness = Endianness.LITTLE,
        symbols: Optional[Dict[str, int]] = None,
    ) -> None:
        self._endianness = endianness
        self._symbols = symbols or {}

    def metadata(self) -> DatabaseMetadata:
        return DatabaseMetadata(
            path="/tmp/sample",
            module="sample",
            architecture="metapc",
            bits=64,
            endianness=self._endianness,
        )

    def is_open(self) -> bool:
        return True

    def resolve_symbol(self, name: str) -> int | None:
        return self._symbols.get(name)

    def resolve(self, selector: Selector) -> Address:
        # Mirror the real gateway: numeric kinds parse directly, symbols look up.
        return selector.resolve(self)


class _FakeMemory:
    """An in-memory ``MemoryGateway`` over a fixed byte map.

    ``blobs`` maps an exact start address to the bytes available there; a read of
    ``size`` returns at most that many (fewer models a short read at a boundary).
    An address absent from ``blobs`` is unreadable.
    """

    def __init__(self, blobs: Optional[Dict[int, bytes]] = None) -> None:
        self._blobs = blobs or {}
        self.read_bytes_seen: List[Tuple[Address, int]] = []

    def read_bytes(self, ea: Address, size: int) -> bytes:
        self.read_bytes_seen.append((ea, size))
        if int(ea) not in self._blobs:
            raise ValueError(f"unreadable region at {ea.hex()}")
        return self._blobs[int(ea)][:size]

    def read_string(self, ea: Address, max_length: Optional[int]) -> Optional[str]:
        raise NotImplementedError


class _FakeStructs:
    """A ``StructGateway`` over a fixed name→layout map (``None`` when absent)."""

    def __init__(self, layouts: Optional[Dict[str, StructLayout]] = None) -> None:
        self._layouts = layouts or {}
        self.layout_seen: List[str] = []

    def list_structs(self, query: str, limit: int):  # pragma: no cover - unused
        raise NotImplementedError

    def layout(self, name: str) -> Optional[StructLayout]:
        self.layout_seen.append(name)
        return self._layouts.get(name)


# -- layout + data fixtures -------------------------------------------------

# A 24-byte aggregate spanning every rendering path: two 4-byte ints, a 1-byte
# char, a 3-byte array (non-scalar → raw hex), 4 bytes of padding, and an 8-byte
# pointer.
_POINT = StructLayout(
    name="Point",
    size=24,
    fields=(
        StructField(name="x", type_name="int", offset=0, size=4),
        StructField(name="y", type_name="int", offset=4, size=4),
        StructField(name="flag", type_name="char", offset=8, size=1),
        StructField(name="buf", type_name="unsigned char[3]", offset=9, size=3),
        StructField(name="pad", type_name="char[4]", offset=12, size=4),
        StructField(name="next", type_name="void *", offset=16, size=8),
    ),
)

# x=1, y=2, flag='A'(0x41), buf=aa bb cc, pad=00.., next=0x404040 (little-endian)
_POINT_BYTES = (
    b"\x01\x00\x00\x00"
    b"\x02\x00\x00\x00"
    b"\x41"
    b"\xaa\xbb\xcc"
    b"\x00\x00\x00\x00"
    b"\x40\x40\x40\x00\x00\x00\x00\x00"
)


def _point_use_case(
    *,
    endianness: Endianness = Endianness.LITTLE,
    symbols: Optional[Dict[str, int]] = None,
    address: int = 0x401000,
) -> Tuple[ReadStructUseCase, _FakeMemory, _FakeStructs]:
    memory = _FakeMemory(blobs={address: _POINT_BYTES})
    structs = _FakeStructs(layouts={"Point": _POINT})
    database = _FakeDatabase(endianness=endianness, symbols=symbols)
    return ReadStructUseCase(structs, memory, database), memory, structs


# -- decoding ---------------------------------------------------------------


def test_read_struct_little_endian_decodes_every_field_path():
    use_case, memory, structs = _point_use_case(endianness=Endianness.LITTLE)

    result = use_case.execute(
        ReadStructCommand(address="0x401000", struct="Point")
    ).result

    assert result.struct == "Point"
    assert result.address == Address(0x401000)
    assert result.size == 24
    # The whole aggregate is read in a single covering byte run.
    assert memory.read_bytes_seen == [(Address(0x401000), 24)]
    assert structs.layout_seen == ["Point"]

    assert result.fields == (
        StructFieldValue("x", "int", 0, "1 (0x1)"),
        StructFieldValue("y", "int", 4, "2 (0x2)"),
        # char (size 1) → scalar 'A' == 65.
        StructFieldValue("flag", "char", 8, "65 (0x41)"),
        # 3-byte array is non-scalar → raw hex in image order.
        StructFieldValue("buf", "unsigned char[3]", 9, "0xaabbcc"),
        StructFieldValue("pad", "char[4]", 12, "0 (0x0)"),
        # pointer (size 8) → scalar decoded little-endian.
        StructFieldValue("next", "void *", 16, "4210752 (0x404040)"),
    )


def test_read_struct_big_endian_decodes_scalars_by_byte_order():
    use_case, _memory, _structs = _point_use_case(endianness=Endianness.BIG)

    result = use_case.execute(
        ReadStructCommand(address="0x401000", struct="Point")
    ).result

    fields = {f.name: f.value for f in result.fields}
    # Same bytes, big-endian: 0x01000000 == 16777216, 0x02000000 == 33554432.
    assert fields["x"] == "16777216 (0x1000000)"
    assert fields["y"] == "33554432 (0x2000000)"
    # char is a single byte → identical under either order.
    assert fields["flag"] == "65 (0x41)"
    # The raw-hex array is byte-order agnostic (image order either way).
    assert fields["buf"] == "0xaabbcc"
    # pointer bytes 40 40 40 00 .. big-endian → 0x4040400000000000.
    assert fields["next"] == "4629770785681047552 (0x4040400000000000)"


def test_read_struct_resolves_decimal_and_symbol():
    use_case, _memory, _structs = _point_use_case(
        symbols={"g_point": 0x401000}, address=0x401000
    )

    sym = use_case.execute(
        ReadStructCommand(address="g_point", struct="Point")
    ).result
    assert sym.address == Address(0x401000)
    assert sym.fields[0].value == "1 (0x1)"

    # Decimal 4198400 == 0x401000 resolves to the same object.
    dec = use_case.execute(
        ReadStructCommand(address="4198400", struct="Point")
    ).result
    assert dec.address == Address(0x401000)


def test_read_struct_empty_aggregate_reads_zero_bytes():
    memory = _FakeMemory(blobs={0x500: b""})
    structs = _FakeStructs(layouts={"Empty": StructLayout(name="Empty", size=0)})
    use_case = ReadStructUseCase(structs, memory, _FakeDatabase())

    result = use_case.execute(
        ReadStructCommand(address="0x500", struct="Empty")
    ).result

    assert result.size == 0
    assert result.fields == ()


# -- failure paths ----------------------------------------------------------


def test_read_struct_unknown_struct_raises():
    memory = _FakeMemory(blobs={0x401000: _POINT_BYTES})
    structs = _FakeStructs(layouts={"Point": _POINT})
    use_case = ReadStructUseCase(structs, memory, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(ReadStructCommand(address="0x401000", struct="Nope"))


def test_read_struct_short_read_raises():
    # Only 8 bytes available where the 24-byte aggregate needs the full run.
    memory = _FakeMemory(blobs={0x401000: b"\x01\x02\x03\x04\x05\x06\x07\x08"})
    structs = _FakeStructs(layouts={"Point": _POINT})
    use_case = ReadStructUseCase(structs, memory, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(ReadStructCommand(address="0x401000", struct="Point"))


def test_read_struct_unreadable_address_raises():
    structs = _FakeStructs(layouts={"Point": _POINT})
    use_case = ReadStructUseCase(structs, _FakeMemory(), _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(ReadStructCommand(address="0xdead", struct="Point"))


def test_read_struct_unresolvable_symbol_raises():
    structs = _FakeStructs(layouts={"Point": _POINT})
    use_case = ReadStructUseCase(structs, _FakeMemory(), _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(ReadStructCommand(address="missing", struct="Point"))


# -- view -------------------------------------------------------------------


def test_read_struct_view_projects_result():
    result = StructReadResult(
        struct="Point",
        address=Address(0x401000),
        size=8,
        fields=(
            StructFieldValue("x", "int", 0, "1 (0x1)"),
            StructFieldValue("buf", "char[4]", 4, "0xaabbccdd"),
        ),
    )

    view = read_struct_view(result)

    assert view == {
        "struct": "Point",
        "address": "0x401000",
        "size": 8,
        "fields": [
            {"name": "x", "type": "int", "offset": 0, "value": "1 (0x1)"},
            {
                "name": "buf",
                "type": "char[4]",
                "offset": 4,
                "value": "0xaabbccdd",
            },
        ],
    }
