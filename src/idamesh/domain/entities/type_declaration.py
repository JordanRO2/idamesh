"""Type-declaration entity: :class:`TypeDeclaration`.

Backs the ``declare_type`` tool. A :class:`TypeDeclaration` records one completed
installation of C type(s) into the local type library — the ``names`` of the types
added, from which the ``count`` a client reports is derived. The *shape* (the field
set a client parses) is the interoperability contract; holding the outcome in an
immutable record, and deriving the count from the names, is ours. Source that fails
to parse never produces one — it surfaces as an error at the boundary instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class TypeDeclaration:
    """A completed type installation: the names of the types added."""

    names: Tuple[str, ...]

    @property
    def count(self) -> int:
        """How many types were added — the length of :attr:`names`."""
        return len(self.names)
