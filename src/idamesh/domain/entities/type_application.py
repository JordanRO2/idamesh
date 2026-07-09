"""Type-application entity: :class:`TypeApplication`.

Backs the ``set_type`` tool. A :class:`TypeApplication` records one completed
type application at a resolved address — the ``type`` declaration that was applied
and the ``name`` the item carries afterward. The *shape* (the field set a client
parses) is the interoperability contract; holding the outcome in an immutable
record is ours. A declaration that fails to parse or apply never produces one — it
surfaces as an error at the boundary instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class TypeApplication:
    """A completed type application: the address, the item name, and the type."""

    address: Address
    name: str
    type: str
