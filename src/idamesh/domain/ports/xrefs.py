"""The cross-reference repository port, shared by ``xrefs_to`` and ``callees``.

One port serves both tools because both are reference queries over an already
resolved address: :meth:`refs_to` walks the edges pointing *into* an address,
and :meth:`callees` walks the call edges leaving the function that owns an
address. Each returns a list of the shared :class:`~idamesh.domain.entities.xref.Xref`
value object, leaving capping and projection to the caller.
"""

from __future__ import annotations

from typing import List, Protocol

from idamesh.domain.entities.xref import Xref
from idamesh.domain.values.address import Address


class XrefRepository(Protocol):
    """Reference queries over the database's cross-reference graph."""

    def refs_to(self, ea: Address) -> List[Xref]:
        """Return every cross-reference whose target is ``ea``.

        Each edge carries the referring ``source`` address, the reference
        classification, and the name of the function the source falls inside
        when it is inside one.
        """
        ...

    def callees(self, ea: Address) -> List[Xref]:
        """Return the direct call edges out of the function containing ``ea``.

        Each edge's ``target`` is a called function and ``target_name`` is the
        name at that entry; duplicates across the function's body are collapsed.
        """
        ...
