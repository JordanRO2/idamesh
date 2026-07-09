"""Bookmark entity: :class:`Bookmark`.

Backs the ``add_bookmark`` tool. A :class:`Bookmark` records one completed marked
position at a resolved address — the ``slot`` index the mark occupies. The *shape*
(the field set a client parses) is the interoperability contract; holding the
outcome in an immutable record is ours. A refused bookmark never produces one — it
surfaces as an error at the boundary instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class Bookmark:
    """A completed bookmark: the marked address and its slot index."""

    address: Address
    slot: int
