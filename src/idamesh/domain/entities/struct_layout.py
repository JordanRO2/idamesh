"""Struct-layout entities: :class:`StructField` and :class:`StructLayout`.

A :class:`StructLayout` is the field-by-field description of one aggregate type —
its ``name``, its total byte ``size``, and its ordered ``fields``. Each
:class:`StructField` records a member's ``name``, its rendered ``type_name``, its
byte ``offset`` from the start of the aggregate, and its own ``size``. The layout
is produced by :meth:`~idamesh.domain.ports.structs.StructGateway.layout` and
consumed by ``read_struct`` to interpret raw memory: the field offsets and sizes
say where each field lives in the byte run read from an address. The *shapes* are
the interoperability contract a client parses; the field choices are ours.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Tuple


@dataclass(frozen=True)
class StructField:
    """One field in a struct layout: its type, byte offset, and byte size.

    ``type_name`` is the field's declared type rendered as text; ``offset`` is its
    byte offset from the start of the aggregate and ``size`` its own byte width.
    """

    name: str
    type_name: str
    offset: int
    size: int


@dataclass(frozen=True)
class StructLayout:
    """The ordered field layout of one aggregate (struct/union) type.

    ``size`` is the aggregate's total byte width; ``fields`` are its members in
    declaration order, each carrying the offset and size needed to slice a field
    out of a byte run read from memory.
    """

    name: str
    size: int
    fields: Tuple[StructField, ...] = field(default_factory=tuple)
