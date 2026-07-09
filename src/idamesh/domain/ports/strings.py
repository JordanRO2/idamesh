"""The strings repository port: enumerate the database's extracted strings."""

from __future__ import annotations

from typing import Protocol

from idamesh.domain.entities.string_item import StringItem
from idamesh.domain.values.pagination import Page, PageRequest


class StringsRepository(Protocol):
    """Paginated enumeration of the extracted-string set in address order."""

    def list(self, page: PageRequest) -> Page[StringItem]:
        """Return the requested slice of extracted strings in address order."""
        ...

    def count(self) -> int:
        """Total number of extracted strings in the database."""
        ...
