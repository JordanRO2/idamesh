"""Type-catalog entities: :class:`TypeInfo` and :class:`TypeMember`.

These back the two type tools (``type_query`` / ``type_inspect``). A
:class:`TypeInfo` is one named type from the database's local type library — its
``name``, a coarse ``kind`` token (``"struct"`` / ``"union"`` / ``"enum"`` /
``"typedef"`` / ``"pointer"`` / ``"function"`` / ``"scalar"`` / …), its byte
``size``, and, for aggregate types, its ordered ``members``. A
:class:`TypeMember` records one field's ``name``, its rendered ``type_name``, its
byte ``offset`` from the start of the aggregate, and its own ``size``. Non-
aggregate types (scalars, pointers, typedefs) carry an empty ``members`` tuple —
an absence, not an error. The *shapes* (the field sets a client parses) are the
interoperability contract; the field choices, and holding the layout in an
immutable record, are ours.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Tuple


@dataclass(frozen=True)
class TypeMember:
    """One member of an aggregate type: where it sits and how wide it is.

    ``type_name`` is the member's declared type rendered as text; ``offset`` is
    its byte offset from the start of the enclosing aggregate and ``size`` its
    own byte width.
    """

    name: str
    type_name: str
    offset: int
    size: int


@dataclass(frozen=True)
class TypeInfo:
    """A single named type drawn from the local type library.

    ``kind`` is a coarse classification token; ``size`` is the type's byte width
    (``0`` when the type is incomplete or sizeless). ``members`` is populated only
    for aggregate kinds (struct/union) and is an empty tuple otherwise.
    """

    name: str
    kind: str
    size: int
    members: Tuple[TypeMember, ...] = field(default_factory=tuple)
