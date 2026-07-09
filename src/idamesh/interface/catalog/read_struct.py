"""Catalog registration and wire-shape projection for ``read_struct``.

The ``StructFieldView`` / ``ReadStructView`` ``TypedDict``s give the schema
compiler an object-rooted ``outputSchema``; :func:`read_struct_view` renders the
decoded struct into that flat shape (address as ``0x`` hex, each field's
``name`` / ``type`` / ``offset`` / ``value``). The field names mirror the
interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, TypedDict

from idamesh.application.contexts.read_struct import ReadStructUseCase
from idamesh.application.dto.read_struct import ReadStructCommand
from idamesh.domain.entities.struct_read import StructFieldValue, StructReadResult
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class StructFieldView(TypedDict):
    """One decoded field of a struct read from memory."""

    name: str
    type: str
    offset: int
    value: str


class ReadStructView(TypedDict):
    """A struct decoded from memory at a resolved address."""

    struct: str
    address: str
    size: int
    fields: List[StructFieldView]


def struct_field_view(field: StructFieldValue) -> StructFieldView:
    """Project one decoded :class:`StructFieldValue` into its wire shape."""
    return StructFieldView(
        name=field.name,
        type=field.type_name,
        offset=field.offset,
        value=field.value,
    )


def read_struct_view(result: StructReadResult) -> ReadStructView:
    """Project a :class:`StructReadResult` into its wire shape."""
    return ReadStructView(
        struct=result.struct,
        address=result.address.hex(),
        size=result.size,
        fields=[struct_field_view(field) for field in result.fields],
    )


def register_read_struct(
    registry: Registry,
    *,
    read_struct_use_case: ReadStructUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``read_struct`` against the struct-read use-case."""

    @registry.tool(name="read_struct")
    def read_struct(address: str, struct: str) -> ReadStructView:
        """Interpret the memory at ``address`` as the aggregate type named
        ``struct``. The ``address`` may be a hexadecimal literal (``0x…``), a
        decimal literal, or a symbol name; it is resolved first. The struct's field
        layout drives the decode: primitive fields (1/2/4/8-byte int, char, or
        pointer) are rendered as an integer/hex ``value`` under the database's byte
        order, while larger, aggregate, or array fields are rendered as a raw
        hex-bytes ``value``. The result reports the ``struct`` name, the resolved
        ``address`` (``0x`` hex), the aggregate ``size``, and one entry per field
        with its ``name``, rendered ``type``, byte ``offset``, and decoded
        ``value``. An unknown struct name or an unresolvable/unreadable address
        yields an error result rather than failing the protocol request.
        Read-only."""
        command = ReadStructCommand(address=address, struct=struct)
        result = run_use_case(
            executor, lambda: read_struct_use_case.execute(command)
        )
        return read_struct_view(result.result)
