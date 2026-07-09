"""Code-definition entities: :class:`FunctionDefinition` and :class:`Undefinition`.

Back the ``define_func`` and ``undefine`` tools. A :class:`FunctionDefinition`
records one completed function creation at a resolved address — the ``name`` the
new function carries (``None`` when unnamed). An :class:`Undefinition` records one
completed reversion of the item at a resolved address back to raw bytes. The
*shapes* (the field sets a client parses) are the interoperability contract;
holding each outcome in an immutable record is ours. A refused create/undefine
never produces one — it surfaces as an error at the boundary instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class FunctionDefinition:
    """A completed function creation: the address and the new function's name."""

    address: Address
    name: Optional[str]


@dataclass(frozen=True)
class Undefinition:
    """A completed undefine: the address whose item was reverted to raw bytes."""

    address: Address
