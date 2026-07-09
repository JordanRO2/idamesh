"""Struct-read entities: :class:`StructFieldValue` and :class:`StructReadResult`.

These back ``read_struct``, which interprets the memory at an address as a named
struct. A :class:`StructReadResult` pairs the ``struct`` name and resolved
``address`` with the aggregate's total byte ``size`` and one
:class:`StructFieldValue` per field. Each field value records the member's
``name``, its rendered ``type_name``, its byte ``offset`` within the struct, and
a decoded ``value`` — rendered as an integer/hex string for primitive fields
(1/2/4/8-byte int, char, or pointer, decoded under the database's byte order) and
as a raw hexadecimal-bytes string for larger, aggregate, or array fields. Holding
every field's ``value`` as a string keeps the wire shape uniform across the two
rendering paths; that choice is ours, while the field set is the interoperability
contract a client parses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Tuple

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class StructFieldValue:
    """One decoded field of a struct read from memory.

    ``type_name`` is the field's declared type rendered as text; ``offset`` is its
    byte offset within the struct; ``value`` is the field's decoded rendering — an
    integer/hex string for a primitive field, or a raw hex-bytes string for a
    larger, aggregate, or array field.
    """

    name: str
    type_name: str
    offset: int
    value: str


@dataclass(frozen=True)
class StructReadResult:
    """A struct decoded from memory at a resolved address.

    ``struct`` echoes the requested type name and ``address`` the resolved start;
    ``size`` is the aggregate's total byte width and ``fields`` are its decoded
    members in offset order.
    """

    struct: str
    address: Address
    size: int
    fields: Tuple[StructFieldValue, ...] = field(default_factory=tuple)
