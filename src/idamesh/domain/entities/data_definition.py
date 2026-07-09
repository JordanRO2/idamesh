"""Data-definition entity: :class:`DataDefinition`.

Backs the ``make_data`` tool. A :class:`DataDefinition` records one completed data
definition at a resolved address — the ``type`` in force afterward and the ``size``
the item occupies. The *shape* (the field set a client parses) is the
interoperability contract; holding the outcome in an immutable record is ours. A
declaration that fails to parse or a definition the database refuses never produces
one — it surfaces as an error at the boundary instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class DataDefinition:
    """A completed data definition: the address, the applied type, and its size."""

    address: Address
    type: str
    size: int
