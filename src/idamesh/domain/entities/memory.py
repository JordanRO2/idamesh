"""Memory-read entities: :class:`ByteRead`, :class:`IntRead`, :class:`StringRead`,
and :class:`GlobalValue`.

These back the four memory tools (``get_bytes`` / ``get_int`` / ``get_string`` /
``get_global_value``). Each records what was read from a resolved address and how
it was interpreted. Raw bytes are carried as :class:`bytes` and projected to a hex
string at the interface boundary; an integer read carries both its decoded numeric
``value`` and the ``hex`` rendering of the bytes read. The *shapes* (the field
sets a client parses) are the interoperability contract; the field choices, and
holding the decode result in an immutable record rather than a bare tuple, are
ours.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class ByteRead:
    """Raw bytes read from a region: where they start, how many, and the data."""

    address: Address
    size: int
    data: bytes


@dataclass(frozen=True)
class IntRead:
    """An integer decoded from memory at ``address``.

    ``value`` is the decoded number under the requested ``signed`` interpretation
    and the database's byte order; ``hex`` is the ``0x``-prefixed rendering of the
    read bytes as read.
    """

    address: Address
    size: int
    signed: bool
    value: int
    hex: str


@dataclass(frozen=True)
class StringRead:
    """A string read from memory: its start ``address``, decoded ``value``, and
    the byte ``length`` consumed."""

    address: Address
    value: str
    length: int


@dataclass(frozen=True)
class GlobalValue:
    """The value of a named global read and interpreted as an integer.

    Pairs the resolved global's ``name`` and ``address`` with the same decoded
    ``value`` / ``hex`` view as :class:`IntRead` at the requested width and
    ``signed`` interpretation.
    """

    name: str
    address: Address
    size: int
    signed: bool
    value: int
    hex: str
