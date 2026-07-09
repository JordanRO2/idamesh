"""Command/Result DTOs for the memory tools.

The four memory reads — ``get_bytes`` / ``get_int`` / ``get_string`` /
``get_global_value`` — share this module. Each command carries a polymorphic
address (or, for ``get_global_value``, a name-or-address) selector and the shape
of the read; each result wraps the matching memory entity. Integer reads name a
byte ``size`` and ``signed`` interpretation; the actual decode (byte order from
the database metadata) happens in the use-case, keeping the domain entity pure.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.memory import (
    ByteRead,
    GlobalValue,
    IntRead,
    StringRead,
)

#: Default integer width (in bytes) read when a client omits ``size``.
DEFAULT_INT_SIZE: int = 4
#: Default maximum bytes scanned for a string when a client omits ``max_length``.
DEFAULT_STRING_MAX_LENGTH: int = 4096


@dataclass(frozen=True)
class GetBytesCommand:
    """Input for ``get_bytes``.

    ``address`` is a polymorphic selector — a hex literal (``0x…``), a decimal
    literal, or a symbol name — resolved to the start of the region; ``size`` is
    the number of bytes to read.
    """

    address: str
    size: int


@dataclass(frozen=True)
class GetBytesResult:
    """Output for ``get_bytes`` — the bytes read from the region."""

    read: ByteRead


@dataclass(frozen=True)
class GetIntCommand:
    """Input for ``get_int``.

    ``address`` is a polymorphic selector resolved to the start of the integer;
    ``size`` is its byte width and ``signed`` selects a two's-complement
    interpretation. The bytes are decoded under the database's byte order.
    """

    address: str
    size: int = DEFAULT_INT_SIZE
    signed: bool = False


@dataclass(frozen=True)
class GetIntResult:
    """Output for ``get_int`` — the decoded integer."""

    read: IntRead


@dataclass(frozen=True)
class GetStringCommand:
    """Input for ``get_string``.

    ``address`` is a polymorphic selector resolved to the start of the string;
    ``max_length`` bounds how many bytes are scanned for it.
    """

    address: str
    max_length: int = DEFAULT_STRING_MAX_LENGTH


@dataclass(frozen=True)
class GetStringResult:
    """Output for ``get_string`` — the string read at the address."""

    read: StringRead


@dataclass(frozen=True)
class GetGlobalValueCommand:
    """Input for ``get_global_value``.

    ``name`` is a global's symbol name or address (a polymorphic selector);
    ``size`` is the byte width read and ``signed`` selects a two's-complement
    interpretation, decoded like ``get_int`` under the database's byte order.
    """

    name: str
    size: int = DEFAULT_INT_SIZE
    signed: bool = False


@dataclass(frozen=True)
class GetGlobalValueResult:
    """Output for ``get_global_value`` — the resolved global's value."""

    value: GlobalValue
