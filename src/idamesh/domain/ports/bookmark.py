"""The bookmark gateway port: add a marked position at an address.

Backs the ``add_bookmark`` tool. :meth:`add` records a marked position (bookmark)
at an effective address with a human-readable ``description`` and returns the slot
index the mark occupies, so the caller can report where it landed. Re-marking an
address already bookmarked updates the description in its existing slot rather than
consuming a new one. An address the database cannot bookmark, or an exhausted slot
table, raises a domain error the caller surfaces as an ``isError`` result. The
SDK-level bookmark write is the adapter's job; this port only fixes the contract.
"""

from __future__ import annotations

from typing import Protocol

from idamesh.domain.values.address import Address


class BookmarkGateway(Protocol):
    """Write-side creation of a marked position at an address."""

    def add(self, ea: Address, description: str) -> int:
        """Add or update the bookmark at ``ea``; return its slot index.

        ``description`` is the label shown for the mark. When ``ea`` is already
        bookmarked its slot is reused and the description updated; otherwise a free
        slot is claimed. The returned integer is the slot the mark occupies. Raises
        an error (surfaced by the caller as an ``isError`` result) when the address
        cannot be bookmarked or no slot is available.
        """
        ...
