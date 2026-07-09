"""The type-mutation gateway port: apply a C declaration at an address.

This is the *write* counterpart to the read-side :class:`~idamesh.domain.ports.types.TypeGateway`;
kept as its own port so the write surface stays disjoint from type inspection.
One port serves the ``set_type`` tool. :meth:`apply_type` parses a C
declaration/prototype and installs the resulting type on the function or data item
at an effective address, returning the item's name after the change so the caller
can report which symbol was retyped. A declaration the parser cannot understand —
or a type the database refuses to apply at ``ea`` — raises, surfaced by the caller
as an ``isError`` result.
"""

from __future__ import annotations

from typing import Protocol

from idamesh.domain.values.address import Address


class TypeMutationGateway(Protocol):
    """Write-side access to the applied type of an item at an address."""

    def apply_type(self, ea: Address, decl: str) -> str:
        """Parse ``decl`` and apply the resulting type at ``ea``; return the name.

        ``decl`` is a C declaration or function prototype (e.g. ``int f(char *)``
        or ``unsigned int``). On success the parsed type is installed on the item
        at ``ea`` and the item's current name is returned (empty when unnamed).
        Raises an error (surfaced by the caller as an ``isError`` result) when
        ``decl`` does not parse or the type cannot be applied at ``ea``.
        """
        ...
