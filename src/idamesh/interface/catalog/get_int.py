"""Catalog registration and wire-shape projection for ``get_int``.

The ``GetIntView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`get_int_view` renders the decoded integer into that flat
shape (address as ``0x`` hex). The field names mirror the interoperability
contract; the projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.memory import GetIntUseCase
from idamesh.application.dto.memory import DEFAULT_INT_SIZE, GetIntCommand
from idamesh.domain.entities.memory import IntRead
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class GetIntView(TypedDict):
    """One integer decoded from memory.

    ``value`` is carried as a base-10 **string**, not a JSON number: an 8-byte read
    spans the full 64-bit range and would lose precision above 2**53 in a
    double-based JSON client. ``size`` stays an ``int`` (small); ``hex`` is the
    already-string byte rendering.
    """

    address: str
    size: int
    signed: bool
    value: str
    hex: str


def get_int_view(read: IntRead) -> GetIntView:
    """Project an :class:`IntRead` into its wire shape.

    ``value`` is rendered as a decimal string so the full-width integer survives the
    JSON round-trip without precision loss.
    """
    return GetIntView(
        address=read.address.hex(),
        size=read.size,
        signed=read.signed,
        value=str(read.value),
        hex=read.hex,
    )


def register_get_int(
    registry: Registry,
    *,
    get_int_use_case: GetIntUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``get_int`` against the integer-read use-case."""

    @registry.tool(name="get_int")
    def get_int(
        address: str, size: int = DEFAULT_INT_SIZE, signed: bool = False
    ) -> GetIntView:
        """Read an integer of ``size`` bytes at ``address`` and decode it. The
        ``address`` may be a hexadecimal literal (``0x…``), a decimal literal, or a
        symbol name; it is resolved first. The bytes are interpreted under the
        database's byte order and, when ``signed`` is true, as a two's-complement
        value. The result reports the resolved ``address`` (``0x`` hex), the
        ``size`` and ``signed`` interpretation, the decoded ``value``, and the
        ``hex`` rendering of the bytes read. An out-of-range or unresolvable
        address, or a short read, yields an error result rather than failing the
        protocol request."""
        command = GetIntCommand(address=address, size=size, signed=signed)
        result = run_use_case(
            executor, lambda: get_int_use_case.execute(command)
        )
        return get_int_view(result.read)
