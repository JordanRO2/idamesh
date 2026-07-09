"""The struct gateway port: enumerate and lay out aggregate types.

One port serves ``search_structs`` and ``read_struct``. :meth:`list_structs`
returns the struct/union types whose name matches a case-insensitive substring
(empty query = all), each summarized as a
:class:`~idamesh.domain.entities.struct_summary.StructSummary` (name, size, member
count), bounded by ``limit``. :meth:`layout` returns the full field layout of one
aggregate as a :class:`~idamesh.domain.entities.struct_layout.StructLayout`, or
``None`` when no struct of that name exists; ``read_struct`` uses the returned
offsets and sizes to slice a struct out of the bytes read at an address.
Enumeration and layout extraction are the SDK's job; filtering, bounding, and the
response shapes are the application's.
"""

from __future__ import annotations

from typing import List, Optional, Protocol

from idamesh.domain.entities.struct_layout import StructLayout
from idamesh.domain.entities.struct_summary import StructSummary


class StructGateway(Protocol):
    """Read-side access to the database's aggregate (struct/union) types."""

    def list_structs(self, query: str, limit: int) -> List[StructSummary]:
        """Return aggregate types whose name contains ``query`` (case-insensitive).

        An empty ``query`` matches every struct/union type. Each hit is summarized
        as a :class:`~idamesh.domain.entities.struct_summary.StructSummary`. At
        most ``limit`` summaries are returned; the caller decides whether the cap
        elided further matches.
        """
        ...

    def layout(self, name: str) -> Optional[StructLayout]:
        """Return the field layout of the aggregate named ``name``, or ``None``.

        The returned :class:`~idamesh.domain.entities.struct_layout.StructLayout`
        carries the aggregate's total byte size and its ordered fields, each with
        the offset and size needed to slice a field out of a memory read. A name
        that no aggregate binds to yields ``None``, which the caller surfaces as
        an ``isError`` result.
        """
        ...
