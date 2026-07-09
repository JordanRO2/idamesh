"""The import repository port: enumerate imported symbols."""

from __future__ import annotations

from typing import Protocol

from idamesh.domain.entities.imports import Import
from idamesh.domain.values.pagination import Page, PageRequest


class ImportRepository(Protocol):
    """Paginated enumeration of the module's imported-symbol table."""

    def list(self, page: PageRequest) -> Page[Import]:
        """Return the requested slice of imports, grouped by originating module."""
        ...

    def count(self) -> int:
        """Total number of imported symbols across every module."""
        ...
