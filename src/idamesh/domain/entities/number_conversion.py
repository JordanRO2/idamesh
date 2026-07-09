"""The :class:`NumberConversion` entity — one integer across every representation.

A conversion captures a single parsed integer rendered simultaneously as its
signed decimal value, its unsigned and signed two's-complement interpretations at
a chosen bit width, and its hexadecimal, binary, and octal renderings, plus the
ASCII character it denotes when that is printable. The *shape* (the set of
representation fields) is the interoperability contract a client parses; the
field choices and the bit-width semantics are ours. This entity carries no I/O
and is produced purely by :class:`~idamesh.domain.services.number.NumberService`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class NumberConversion:
    """One integer rendered across hex/decimal/binary/octal and signed views."""

    #: The original, unmodified input token that was parsed.
    input: str
    #: The bit width the unsigned/signed two's-complement views are computed at.
    bits: int
    #: The parsed value as a plain signed decimal integer (input's own sign).
    decimal: int
    #: The value reduced modulo ``2**bits`` — its unsigned interpretation.
    unsigned: int
    #: The two's-complement signed interpretation of ``unsigned`` at ``bits``.
    signed: int
    #: ``0x``-prefixed lowercase hexadecimal of the unsigned value.
    hex: str
    #: ``0b``-prefixed binary of the unsigned value.
    binary: str
    #: ``0o``-prefixed octal of the unsigned value.
    octal: str
    #: The ASCII character the value denotes, or ``None`` when not printable.
    char: Optional[str] = None
