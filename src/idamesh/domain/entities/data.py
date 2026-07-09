"""The :class:`Global` entity — a named data location in the database.

A global is a named, address-bearing data item (not a function). The *shape*
(name, address, size, optional declared type) is the interoperability contract a
client parses; the field choices are ours.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class Global:
    """A single named global (data) symbol."""

    ea: Address
    name: str
    size: int = 0
    type_name: str | None = None
