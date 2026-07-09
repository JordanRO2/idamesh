"""The ``read_struct`` use-case.

Composes three ports without a new adapter: it resolves the polymorphic address
against the :class:`~idamesh.domain.ports.database.DatabaseGateway`, fetches the
named aggregate's field layout from the
:class:`~idamesh.domain.ports.structs.StructGateway`, reads the covering byte run
through the :class:`~idamesh.domain.ports.memory.MemoryGateway`, and decodes each
field *here*, keeping interpretation pure. Primitive fields (1/2/4/8-byte int,
char, or pointer) are rendered as an integer/hex string under the database's byte
order (from ``metadata()``); larger, aggregate, or array fields are rendered as a
raw hexadecimal-bytes string. An unknown struct name or an unresolvable/unreadable
address raises, so the interface layer renders it as an ``isError`` result.
"""

from __future__ import annotations

from idamesh.application.dto.read_struct import ReadStructCommand, ReadStructResult
from idamesh.domain.entities.metadata import Endianness
from idamesh.domain.entities.struct_read import StructFieldValue, StructReadResult
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.memory import MemoryGateway
from idamesh.domain.ports.structs import StructGateway
from idamesh.domain.values.address import Selector

#: Byte widths a field is decoded as a scalar integer/pointer rather than raw hex.
_SCALAR_WIDTHS: frozenset[int] = frozenset({1, 2, 4, 8})


def _byte_order(endianness: Endianness) -> str:
    """Map a domain :class:`Endianness` to the ``int.from_bytes`` order token."""
    return "big" if endianness is Endianness.BIG else "little"


def _render_field(chunk: bytes, size: int, order: str) -> str:
    """Render one field's bytes as a decoded scalar or a raw hex-bytes string.

    A field whose ``size`` is one of :data:`_SCALAR_WIDTHS` and whose ``chunk``
    holds exactly that many bytes is decoded (unsigned) under ``order`` and
    rendered as ``"<decimal> (0x<hex>)"``. Every other field — a larger, aggregate,
    array, or truncated field — is rendered as ``"0x"`` followed by the bytes in
    image (address) order.
    """
    if size in _SCALAR_WIDTHS and len(chunk) == size:
        value = int.from_bytes(chunk, byteorder=order, signed=False)
        return f"{value} (0x{value:x})"
    return "0x" + chunk.hex()


class ReadStructUseCase:
    """Interpret the memory at an address as a named struct, field by field."""

    def __init__(
        self,
        structs: StructGateway,
        memory: MemoryGateway,
        database: DatabaseGateway,
    ) -> None:
        self._structs = structs
        self._memory = memory
        self._database = database

    def execute(self, command: ReadStructCommand) -> ReadStructResult:
        """Resolve ``command.address``, lay out ``command.struct``, and decode.

        The address selector is resolved against the database gateway and the
        struct's layout is fetched from the struct gateway; an unknown struct name
        or unresolvable address raises a ``ValueError``. The aggregate's byte run
        is read through the memory gateway and each field is sliced out by its
        offset and size: a field whose size is one of :data:`_SCALAR_WIDTHS` is
        decoded as an integer under the database's byte order and rendered as an
        integer/hex string, while any other field is rendered as a raw hex-bytes
        string. The decoded fields are returned as a
        :class:`~idamesh.domain.entities.struct_read.StructReadResult`.
        """
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)

        layout = self._structs.layout(command.struct)
        if layout is None:
            raise ValueError(f"unknown struct: {command.struct!r}")

        data = self._memory.read_bytes(ea, layout.size)
        if len(data) != layout.size:
            raise ValueError(
                f"short read at {ea.hex()}: wanted {layout.size} bytes, "
                f"got {len(data)}"
            )

        order = _byte_order(self._database.metadata().endianness)
        fields = tuple(
            StructFieldValue(
                name=field.name,
                type_name=field.type_name,
                offset=field.offset,
                value=_render_field(
                    data[field.offset : field.offset + field.size],
                    field.size,
                    order,
                ),
            )
            for field in layout.fields
        )

        result = StructReadResult(
            struct=command.struct,
            address=ea,
            size=layout.size,
            fields=fields,
        )
        return ReadStructResult(result=result)
