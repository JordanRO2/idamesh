"""Catalog registration and wire-shape projection for ``int_convert``.

The ``IntConvertView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`int_convert_view` renders the pure conversion into that
flat shape. The field names mirror the interoperability contract; the projection
is ours. This tool touches no database — it is a pure integer reinterpreter.
"""

from __future__ import annotations

from typing import Optional, TypedDict

from idamesh.application.contexts.int_convert import IntConvertUseCase
from idamesh.application.dto.int_convert import DEFAULT_BITS, IntConvertCommand
from idamesh.domain.entities.number_conversion import NumberConversion
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class IntConvertView(TypedDict):
    """One integer rendered across every representation.

    ``decimal`` / ``unsigned`` / ``signed`` are carried as base-10 **strings**, not
    JSON numbers: at wide bit widths these values routinely exceed 2**53 and a
    naked JSON number would silently lose precision in a double-based client (JS,
    ``JSON.parse``). ``bits`` stays an ``int`` (it is small and bounded); the
    ``hex`` / ``binary`` / ``octal`` renderings are already strings.
    """

    input: str
    bits: int
    hex: str
    decimal: str
    unsigned: str
    signed: str
    binary: str
    octal: str
    char: Optional[str]


def int_convert_view(conversion: NumberConversion) -> IntConvertView:
    """Project a :class:`NumberConversion` into its wire shape.

    The three integer magnitudes are rendered as decimal strings so an arbitrarily
    wide value survives the JSON round-trip without precision loss.
    """
    return IntConvertView(
        input=conversion.input,
        bits=conversion.bits,
        hex=conversion.hex,
        decimal=str(conversion.decimal),
        unsigned=str(conversion.unsigned),
        signed=str(conversion.signed),
        binary=conversion.binary,
        octal=conversion.octal,
        char=conversion.char,
    )


def register_int_convert(
    registry: Registry,
    *,
    int_convert_use_case: IntConvertUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``int_convert`` against the number-conversion use-case."""

    @registry.tool(name="int_convert")
    def int_convert(value: str, bits: int = DEFAULT_BITS) -> IntConvertView:
        """Reinterpret an integer ``value`` across every representation at a given
        bit width. ``value`` may be written in hexadecimal (``0x…``), binary
        (``0b…``), octal (``0o…``), plain decimal, or as a quoted character
        literal (``'A'``), with an optional leading sign. ``bits`` sets the width
        the unsigned and two's-complement ``signed`` views are computed at. The
        result reports the ``decimal`` value, its ``unsigned`` and ``signed``
        interpretations, its ``hex`` / ``binary`` / ``octal`` renderings, and the
        ASCII ``char`` when the value is printable. This tool reads no database.
        An unparseable value or an out-of-range bit width yields an error result
        rather than failing the protocol request."""
        command = IntConvertCommand(value=value, bits=bits)
        result = run_use_case(
            executor, lambda: int_convert_use_case.execute(command)
        )
        return int_convert_view(result.conversion)
