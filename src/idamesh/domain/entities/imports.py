"""The :class:`Import` entity — one imported symbol resolved by the loader.

An import is a symbol the module borrows from another binary: its name, the
originating library/module it is drawn from, the address of its slot in the
import table, and (on ordinal-linked platforms) the ordinal it was bound by. The
*shape* clients parse is the interoperability contract; the field selection here
is ours.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class Import:
    """A single imported symbol and the module it originates from."""

    ea: Address
    name: str
    module: str
    ordinal: int | None = None
