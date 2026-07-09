"""The function repository port: enumerate and look up functions."""

from __future__ import annotations

from typing import Protocol

from idamesh.domain.entities.function import Function
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import Page, PageRequest


class FunctionRepository(Protocol):
    """Paginated enumeration of, and point lookup into, the function set."""

    def list(self, page: PageRequest) -> Page[Function]:
        """Return the requested slice of functions in address order."""
        ...

    def count(self) -> int:
        """Total number of functions in the database."""
        ...

    def get(self, ea: Address) -> Function | None:
        """The function whose entry point is exactly ``ea``, or ``None``."""
        ...

    def get_containing(self, ea: Address) -> Function | None:
        """The function whose body contains ``ea``, or ``None``."""
        ...
