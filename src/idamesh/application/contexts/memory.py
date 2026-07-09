"""The memory-read use-cases: ``get_bytes`` / ``get_int`` / ``get_string`` /
``get_global_value``.

Each resolves its polymorphic selector against the database gateway (mirroring
``decompile``), then reads through the :class:`~idamesh.domain.ports.memory.MemoryGateway`.
Integer interpretation is kept *pure* in the application layer: the raw bytes come
from the gateway and are decoded here under the byte order reported by
``DatabaseGateway.metadata()``, so no endianness logic leaks into infrastructure.
"""

from __future__ import annotations

from idamesh.application.dto.memory import (
    GetBytesCommand,
    GetBytesResult,
    GetGlobalValueCommand,
    GetGlobalValueResult,
    GetIntCommand,
    GetIntResult,
    GetStringCommand,
    GetStringResult,
)
from idamesh.domain.entities.memory import (
    ByteRead,
    GlobalValue,
    IntRead,
    StringRead,
)
from idamesh.domain.entities.metadata import Endianness
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.memory import MemoryGateway
from idamesh.domain.values.address import Address, Selector


def _byte_order(endianness: Endianness) -> str:
    """Map a domain :class:`Endianness` to the ``int.from_bytes`` order token."""
    return "big" if endianness is Endianness.BIG else "little"


def _require_positive_size(size: int) -> int:
    """Return ``size`` if it is a positive integer, else raise ``ValueError``.

    Booleans are rejected explicitly: ``True``/``False`` are ``int`` subclasses
    but are never a meaningful byte count.
    """
    if isinstance(size, bool) or not isinstance(size, int):
        raise ValueError(f"size must be an int, got {type(size).__name__}")
    if size <= 0:
        raise ValueError(f"size must be positive, got {size}")
    return size


def _read_int(
    memory: MemoryGateway,
    database: DatabaseGateway,
    ea: Address,
    size: int,
    signed: bool,
) -> tuple[int, str]:
    """Read ``size`` bytes at ``ea`` and decode them under the DB byte order.

    Returns the decoded ``value`` and the ``0x``-prefixed hex rendering of the
    bytes *as read* (image/address order). A non-positive ``size`` or a short read
    (fewer bytes than requested) raises ``ValueError``; the database's endianness
    drives ``int.from_bytes`` and ``signed`` selects a two's-complement decode.
    """
    _require_positive_size(size)
    data = memory.read_bytes(ea, size)
    if len(data) != size:
        raise ValueError(
            f"short read at {ea.hex()}: wanted {size} bytes, got {len(data)}"
        )
    order = _byte_order(database.metadata().endianness)
    value = int.from_bytes(data, byteorder=order, signed=signed)
    return value, "0x" + data.hex()


class GetBytesUseCase:
    """Resolve a selector and read a fixed-size run of raw bytes."""

    def __init__(self, memory: MemoryGateway, database: DatabaseGateway) -> None:
        self._memory = memory
        self._database = database

    def execute(self, command: GetBytesCommand) -> GetBytesResult:
        """Resolve ``command.address`` and read ``command.size`` bytes from it.

        The selector is parsed and resolved against the database gateway; the
        memory gateway then returns the raw bytes, wrapped as a
        :class:`~idamesh.domain.entities.memory.ByteRead`. A non-positive size, an
        unresolvable address, or an unreadable region surfaces as an error the
        interface layer renders as an ``isError`` result.
        """
        _require_positive_size(command.size)
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        data = self._memory.read_bytes(ea, command.size)
        read = ByteRead(address=ea, size=len(data), data=data)
        return GetBytesResult(read=read)


class GetIntUseCase:
    """Resolve a selector, read bytes, and decode them as an integer."""

    def __init__(self, memory: MemoryGateway, database: DatabaseGateway) -> None:
        self._memory = memory
        self._database = database

    def execute(self, command: GetIntCommand) -> GetIntResult:
        """Resolve ``command.address``, read ``command.size`` bytes, and decode.

        The bytes are interpreted under the database's byte order (from
        ``metadata()``) and the requested ``signed`` flag, producing an
        :class:`~idamesh.domain.entities.memory.IntRead` carrying both the decoded
        ``value`` and the ``hex`` rendering of the bytes read. A bad size,
        unresolvable address, or short read surfaces as an ``isError`` result.
        """
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        value, rendered = _read_int(
            self._memory, self._database, ea, command.size, command.signed
        )
        read = IntRead(
            address=ea,
            size=command.size,
            signed=command.signed,
            value=value,
            hex=rendered,
        )
        return GetIntResult(read=read)


class GetStringUseCase:
    """Resolve a selector and read a decoded string from that address."""

    def __init__(self, memory: MemoryGateway, database: DatabaseGateway) -> None:
        self._memory = memory
        self._database = database

    def execute(self, command: GetStringCommand) -> GetStringResult:
        """Resolve ``command.address`` and read a string of up to ``max_length``.

        The selector is resolved against the database gateway; the memory gateway
        reads and decodes the string, wrapped as a
        :class:`~idamesh.domain.entities.memory.StringRead` carrying its decoded
        ``value`` and character ``length``. An unresolvable address or absent
        string surfaces as an error the interface layer renders as an ``isError``
        result.
        """
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        value = self._memory.read_string(ea, command.max_length)
        if value is None:
            raise ValueError(f"no string at {ea.hex()}")
        read = StringRead(address=ea, value=value, length=len(value))
        return GetStringResult(read=read)


class GetGlobalValueUseCase:
    """Resolve a global by name/address and read its value as an integer."""

    def __init__(self, memory: MemoryGateway, database: DatabaseGateway) -> None:
        self._memory = memory
        self._database = database

    def execute(self, command: GetGlobalValueCommand) -> GetGlobalValueResult:
        """Resolve ``command.name`` to a global and decode its value.

        ``name`` (a symbol name or address) is resolved against the database
        gateway; ``command.size`` bytes are read and decoded under the database's
        byte order and ``signed`` flag, exactly as ``get_int`` does, producing a
        :class:`~idamesh.domain.entities.memory.GlobalValue` that also echoes the
        requested ``name`` and the resolved ``address``. An unresolvable name or
        unreadable region surfaces as an ``isError`` result.
        """
        selector = Selector.parse(command.name)
        ea = self._database.resolve(selector)
        value, rendered = _read_int(
            self._memory, self._database, ea, command.size, command.signed
        )
        global_value = GlobalValue(
            name=command.name,
            address=ea,
            size=command.size,
            signed=command.signed,
            value=value,
            hex=rendered,
        )
        return GetGlobalValueResult(value=global_value)
