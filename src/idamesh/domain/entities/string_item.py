"""The :class:`StringItem` entity — one extracted string in the database.

An extracted string pairs the address it starts at with its decoded text, its
byte length, and the encoding kind IDA classified it as (a C/ASCII string, a
UTF-16/Unicode string, and so on). The *shape* (address, length, kind, value) is
the interoperability contract a client parses; the field choices are ours. The
encoding is kept as a plain ``kind`` string here and projected to the wire key
``type`` at the interface boundary.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class StringItem:
    """A single extracted string: where it lives, how long it is, and its text."""

    address: Address
    length: int
    kind: str
    value: str
