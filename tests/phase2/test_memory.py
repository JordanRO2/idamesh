"""Unit tests for the memory-read use-cases and views (no IDA).

A fake :class:`MemoryGateway` and a fake ``DatabaseGateway`` stand in for the IDA
adapter, so the selector-resolution, byte-order decode, signedness, and
wire-projection contracts of ``get_bytes`` / ``get_int`` / ``get_string`` /
``get_global_value`` are exercised without a database. The fake database resolves
through the real :class:`Selector` (covering hex, decimal, and symbol inputs plus
the unresolved-symbol failure path) and reports a configurable endianness so both
byte orders are decoded here in the pure application layer.
"""

from __future__ import annotations

from typing import Optional

import pytest

from idamesh.application.contexts.memory import (
    GetBytesUseCase,
    GetGlobalValueUseCase,
    GetIntUseCase,
    GetStringUseCase,
)
from idamesh.application.dto.memory import (
    GetBytesCommand,
    GetGlobalValueCommand,
    GetIntCommand,
    GetStringCommand,
)
from idamesh.domain.entities.memory import (
    ByteRead,
    GlobalValue,
    IntRead,
    StringRead,
)
from idamesh.domain.entities.metadata import DatabaseMetadata, Endianness
from idamesh.domain.values.address import Address, Selector
from idamesh.interface.catalog.get_bytes import get_bytes_view
from idamesh.interface.catalog.get_global_value import get_global_value_view
from idamesh.interface.catalog.get_int import get_int_view
from idamesh.interface.catalog.get_string import get_string_view


class _FakeDatabase:
    """A resolver-backed database gateway with a fixed endianness and symbols."""

    def __init__(
        self,
        *,
        endianness: Endianness = Endianness.LITTLE,
        symbols: Optional[dict[str, int]] = None,
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

    def resolve_symbol(self, name: str) -> int | None:
        return self._symbols.get(name)

    def resolve(self, selector: Selector) -> Address:
        # Mirror the real gateway: numeric kinds parse directly, symbols look up.
        return selector.resolve(self)


class _FakeMemory:
    """An in-memory ``MemoryGateway`` over fixed byte/string maps.

    ``blobs`` maps an exact start address to the bytes available there; a read of
    ``size`` returns at most that many (fewer models a short read at a boundary).
    An address absent from ``blobs`` is unreadable. ``strings`` maps an address to
    the decoded string (or ``None`` for "no string here").
    """

    def __init__(
        self,
        blobs: Optional[dict[int, bytes]] = None,
        strings: Optional[dict[int, Optional[str]]] = None,
    ) -> None:
        self._blobs = blobs or {}
        self._strings = strings or {}
        self.read_bytes_seen: list[tuple[Address, int]] = []
        self.read_string_seen: list[tuple[Address, Optional[int]]] = []

    def read_bytes(self, ea: Address, size: int) -> bytes:
        self.read_bytes_seen.append((ea, size))
        if int(ea) not in self._blobs:
            raise ValueError(f"unreadable region at {ea.hex()}")
        return self._blobs[int(ea)][:size]

    def read_string(self, ea: Address, max_length: Optional[int]) -> Optional[str]:
        self.read_string_seen.append((ea, max_length))
        if int(ea) not in self._strings:
            raise ValueError(f"unreadable region at {ea.hex()}")
        return self._strings[int(ea)]


# -- get_bytes --------------------------------------------------------------


def test_get_bytes_resolves_hex_and_returns_data():
    memory = _FakeMemory(blobs={0x401000: b"\xde\xad\xbe\xef"})
    use_case = GetBytesUseCase(memory, _FakeDatabase())

    result = use_case.execute(GetBytesCommand(address="0x401000", size=4))

    assert result.read == ByteRead(Address(0x401000), 4, b"\xde\xad\xbe\xef")
    assert memory.read_bytes_seen == [(Address(0x401000), 4)]


def test_get_bytes_resolves_decimal_and_symbol():
    memory = _FakeMemory(blobs={4198400: b"\x01\x02", 0x404040: b"\xaa"})
    database = _FakeDatabase(symbols={"g_flag": 0x404040})
    use_case = GetBytesUseCase(memory, database)

    dec = use_case.execute(GetBytesCommand(address="4198400", size=2))
    assert dec.read.address == Address(4198400)
    assert dec.read.data == b"\x01\x02"

    sym = use_case.execute(GetBytesCommand(address="g_flag", size=1))
    assert sym.read.address == Address(0x404040)
    assert sym.read.data == b"\xaa"


def test_get_bytes_size_reflects_bytes_read():
    memory = _FakeMemory(blobs={0x1000: b"\x01\x02\x03"})
    use_case = GetBytesUseCase(memory, _FakeDatabase())

    # The blob only holds 3 bytes; a larger request yields what is available.
    result = use_case.execute(GetBytesCommand(address="0x1000", size=8))

    assert result.read.data == b"\x01\x02\x03"
    assert result.read.size == 3


def test_get_bytes_rejects_non_positive_size():
    use_case = GetBytesUseCase(_FakeMemory(), _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(GetBytesCommand(address="0x1000", size=0))
    with pytest.raises(ValueError):
        use_case.execute(GetBytesCommand(address="0x1000", size=-4))


def test_get_bytes_unreadable_region_raises():
    use_case = GetBytesUseCase(_FakeMemory(), _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(GetBytesCommand(address="0xdead", size=4))


def test_get_bytes_unresolvable_symbol_raises():
    use_case = GetBytesUseCase(_FakeMemory(), _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(GetBytesCommand(address="missing", size=4))


# -- get_int ----------------------------------------------------------------


def test_get_int_little_endian_unsigned():
    memory = _FakeMemory(blobs={0x1000: b"\x01\x02\x03\x04"})
    use_case = GetIntUseCase(memory, _FakeDatabase(endianness=Endianness.LITTLE))

    result = use_case.execute(GetIntCommand(address="0x1000", size=4))

    assert result.read.value == 0x04030201
    assert result.read.signed is False
    assert result.read.size == 4
    # ``hex`` renders the bytes *as read* (address order), not the decoded value.
    assert result.read.hex == "0x01020304"
    assert result.read.address == Address(0x1000)


def test_get_int_big_endian_unsigned():
    memory = _FakeMemory(blobs={0x1000: b"\x01\x02\x03\x04"})
    use_case = GetIntUseCase(memory, _FakeDatabase(endianness=Endianness.BIG))

    result = use_case.execute(GetIntCommand(address="0x1000", size=4))

    assert result.read.value == 0x01020304
    assert result.read.hex == "0x01020304"


def test_get_int_signed_two_complement_little():
    memory = _FakeMemory(blobs={0x1000: b"\xff\xff\xff\xff"})
    database = _FakeDatabase(endianness=Endianness.LITTLE)

    signed = GetIntUseCase(memory, database).execute(
        GetIntCommand(address="0x1000", size=4, signed=True)
    )
    unsigned = GetIntUseCase(memory, database).execute(
        GetIntCommand(address="0x1000", size=4, signed=False)
    )

    assert signed.read.value == -1
    assert signed.read.signed is True
    assert unsigned.read.value == 0xFFFFFFFF


@pytest.mark.parametrize(
    ("data", "size", "signed", "order", "expected"),
    [
        (b"\x80", 1, True, Endianness.LITTLE, -128),
        (b"\x80", 1, False, Endianness.LITTLE, 128),
        (b"\x00\x80", 2, True, Endianness.LITTLE, -32768),
        (b"\x00\x80", 2, False, Endianness.LITTLE, 0x8000),
        (b"\x80\x00", 2, True, Endianness.BIG, -32768),
        (b"\xff\xff\xff\xff\xff\xff\xff\xff", 8, True, Endianness.LITTLE, -1),
        (
            b"\x00\x00\x00\x00\x00\x00\x00\x80",
            8,
            False,
            Endianness.LITTLE,
            0x8000000000000000,
        ),
    ],
)
def test_get_int_widths_and_signedness(data, size, signed, order, expected):
    memory = _FakeMemory(blobs={0x2000: data})
    use_case = GetIntUseCase(memory, _FakeDatabase(endianness=order))

    result = use_case.execute(
        GetIntCommand(address="0x2000", size=size, signed=signed)
    )

    assert result.read.value == expected
    assert result.read.size == size
    assert result.read.hex == "0x" + data.hex()


def test_get_int_short_read_raises():
    # Only 2 bytes available where 4 are requested → short read.
    memory = _FakeMemory(blobs={0x1000: b"\x01\x02"})
    use_case = GetIntUseCase(memory, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(GetIntCommand(address="0x1000", size=4))


def test_get_int_rejects_non_positive_size():
    memory = _FakeMemory(blobs={0x1000: b"\x01\x02\x03\x04"})
    use_case = GetIntUseCase(memory, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(GetIntCommand(address="0x1000", size=0))


def test_get_int_resolves_symbol():
    memory = _FakeMemory(blobs={0x404040: b"\x2a\x00\x00\x00"})
    database = _FakeDatabase(symbols={"counter": 0x404040})
    use_case = GetIntUseCase(memory, database)

    result = use_case.execute(GetIntCommand(address="counter", size=4))

    assert result.read.value == 42
    assert result.read.address == Address(0x404040)


# -- get_string -------------------------------------------------------------


def test_get_string_reads_and_reports_length():
    memory = _FakeMemory(strings={0x3000: "hello"})
    use_case = GetStringUseCase(memory, _FakeDatabase())

    result = use_case.execute(GetStringCommand(address="0x3000"))

    assert result.read == StringRead(Address(0x3000), "hello", 5)
    # ``max_length`` default is forwarded to the gateway.
    assert memory.read_string_seen == [(Address(0x3000), 4096)]


def test_get_string_forwards_custom_max_length():
    memory = _FakeMemory(strings={0x3000: "hi"})
    use_case = GetStringUseCase(memory, _FakeDatabase())

    use_case.execute(GetStringCommand(address="0x3000", max_length=16))

    assert memory.read_string_seen == [(Address(0x3000), 16)]


def test_get_string_absent_string_raises():
    memory = _FakeMemory(strings={0x3000: None})
    use_case = GetStringUseCase(memory, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(GetStringCommand(address="0x3000"))


def test_get_string_unresolvable_symbol_raises():
    use_case = GetStringUseCase(_FakeMemory(), _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(GetStringCommand(address="nope"))


# -- get_global_value -------------------------------------------------------


def test_get_global_value_resolves_symbol_and_decodes():
    memory = _FakeMemory(blobs={0x404040: b"\x01\x00\x00\x00"})
    database = _FakeDatabase(
        endianness=Endianness.LITTLE, symbols={"g_state": 0x404040}
    )
    use_case = GetGlobalValueUseCase(memory, database)

    result = use_case.execute(GetGlobalValueCommand(name="g_state", size=4))

    assert result.value == GlobalValue(
        name="g_state",
        address=Address(0x404040),
        size=4,
        signed=False,
        value=1,
        hex="0x01000000",
    )


def test_get_global_value_signed_and_big_endian():
    memory = _FakeMemory(blobs={0x500: b"\xff\xff"})
    database = _FakeDatabase(endianness=Endianness.BIG)
    use_case = GetGlobalValueUseCase(memory, database)

    result = use_case.execute(
        GetGlobalValueCommand(name="0x500", size=2, signed=True)
    )

    assert result.value.value == -1
    assert result.value.name == "0x500"
    assert result.value.address == Address(0x500)


def test_get_global_value_unresolvable_name_raises():
    use_case = GetGlobalValueUseCase(_FakeMemory(), _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(GetGlobalValueCommand(name="unknown_global"))


# -- views ------------------------------------------------------------------


def test_get_bytes_view_projects_read():
    view = get_bytes_view(ByteRead(Address(0x401000), 4, b"\xde\xad\xbe\xef"))

    assert view == {"address": "0x401000", "size": 4, "bytes": "deadbeef"}


def test_get_int_view_projects_read():
    view = get_int_view(
        IntRead(Address(0x1000), 4, True, -1, "0xffffffff")
    )

    # ``value`` is a decimal *string* (big-int-safe wire shape); ``hex`` unchanged.
    assert view == {
        "address": "0x1000",
        "size": 4,
        "signed": True,
        "value": "-1",
        "hex": "0xffffffff",
    }


def test_get_int_view_renders_wide_value_without_precision_loss():
    # A full-width 64-bit read above 2**53 would corrupt as a JSON number.
    view = get_int_view(
        IntRead(Address(0x2000), 8, False, 0xFFFFFFFFFFFFFFFF, "0xffffffffffffffff")
    )

    assert view["value"] == "18446744073709551615"


def test_get_string_view_projects_read():
    view = get_string_view(StringRead(Address(0x3000), "hello", 5))

    assert view == {"address": "0x3000", "value": "hello", "length": 5}


def test_get_global_value_view_projects_value():
    view = get_global_value_view(
        GlobalValue("g_state", Address(0x404040), 4, False, 1, "0x01000000")
    )

    # ``value`` is a decimal *string* (big-int-safe wire shape), as get_int does.
    assert view == {
        "name": "g_state",
        "address": "0x404040",
        "size": 4,
        "signed": False,
        "value": "1",
        "hex": "0x01000000",
    }
