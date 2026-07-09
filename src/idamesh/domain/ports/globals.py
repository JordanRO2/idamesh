"""The global repository port: enumerate named data symbols."""

from __future__ import annotations

from typing import Protocol

from idamesh.domain.entities.data import Global
from idamesh.domain.values.pagination import Page, PageRequest


class GlobalRepository(Protocol):
    """Paginated enumeration of the named-global (data) symbol set."""

    def list(self, page: PageRequest) -> Page[Global]:
        """Return the requested slice of globals in address order."""
        ...

    def count(self) -> int:
        """Total number of named globals in the database."""
        ...
