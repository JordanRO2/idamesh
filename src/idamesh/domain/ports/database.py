"""The database gateway port: metadata reads and address resolution."""

from __future__ import annotations

from typing import Protocol

from idamesh.domain.entities.metadata import DatabaseMetadata
from idamesh.domain.values.address import Address, Selector


class DatabaseGateway(Protocol):
    """Read-side access to the open database and its symbol table.

    The ``resolve_symbol`` method makes any implementation a structural
    :class:`~idamesh.domain.values.address.SymbolResolver`, so a
    :class:`~idamesh.domain.values.address.Selector` can resolve against it.
    """

    def metadata(self) -> DatabaseMetadata:
        """Describe the currently open database."""
        ...

    def is_open(self) -> bool:
        """``True`` when a database is loaded and ready to serve reads."""
        ...

    def resolve_symbol(self, name: str) -> int | None:
        """Resolve a symbol name to an EA integer, or ``None`` if unknown."""
        ...

    def resolve(self, selector: Selector) -> Address:
        """Resolve a hex/decimal/symbol selector to a concrete address.

        Raises ``ValueError`` when a symbol cannot be resolved.
        """
        ...
