"""Command/Result DTOs for ``int_convert``."""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.number_conversion import NumberConversion

#: Bit width used when a client omits ``bits``.
DEFAULT_BITS: int = 64


@dataclass(frozen=True)
class IntConvertCommand:
    """Input for ``int_convert``.

    ``value`` is an integer token in hexadecimal (``0x``), binary (``0b``), octal
    (``0o``), decimal, or as a quoted character literal. ``bits`` is the width the
    unsigned and signed two's-complement views are computed at.
    """

    value: str
    bits: int = DEFAULT_BITS


@dataclass(frozen=True)
class IntConvertResult:
    """Output for ``int_convert`` — one value across every representation."""

    conversion: NumberConversion
