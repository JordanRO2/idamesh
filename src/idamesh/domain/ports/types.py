"""The type gateway port: query and inspect the local type catalog.

One port serves both type tools. :meth:`list_types` returns the named types whose
name matches a case-insensitive substring (an empty query means "all"), bounded
by ``limit``; ``type_query`` projects each hit to ``name``/``kind``/``size``.
:meth:`get_type` returns the full :class:`~idamesh.domain.entities.type_info.TypeInfo`
for one named type — members included for aggregates — or ``None`` when no type of
that name exists; ``type_inspect`` renders that, surfacing an unknown name as an
error. Enumeration and layout extraction are the SDK's job; filtering, bounding,
and the response shapes are the application's.
"""

from __future__ import annotations

from typing import List, Optional, Protocol

from idamesh.domain.entities.type_info import TypeInfo


class TypeGateway(Protocol):
    """Read-side access to the database's local type library."""

    def list_types(self, query: str, limit: int) -> List[TypeInfo]:
        """Return named types whose name contains ``query`` (case-insensitive).

        An empty ``query`` matches every named type. At most ``limit`` types are
        returned; the caller decides whether the cap elided further matches. The
        returned :class:`~idamesh.domain.entities.type_info.TypeInfo` records may
        omit member detail, since ``type_query`` projects only name/kind/size.
        """
        ...

    def get_type(self, name: str) -> Optional[TypeInfo]:
        """Return the full type named ``name``, or ``None`` if none exists.

        The returned :class:`~idamesh.domain.entities.type_info.TypeInfo` carries
        the type's kind, byte size, and — for aggregate kinds — its ordered
        member layout. A name that no type in the catalog binds to yields
        ``None``, which the caller surfaces as an ``isError`` result.
        """
        ...
