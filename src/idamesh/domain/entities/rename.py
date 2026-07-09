"""Rename entity: :class:`Renaming`.

Backs the ``rename`` tool. A :class:`Renaming` records one completed name change
at a resolved address — the ``old_name`` that was in force and the ``name`` now
installed. The *shape* (the field set a client parses) is the interoperability
contract; holding the outcome in an immutable record rather than a bare tuple is
ours. Success is implicit in the record's existence: a refused rename never
produces one — it surfaces as an error at the boundary instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class Renaming:
    """A completed rename: the address, the prior name, and the new name."""

    address: Address
    old_name: str
    name: str
