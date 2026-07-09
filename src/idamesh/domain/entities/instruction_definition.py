"""Instruction-definition entity: :class:`InstructionDefinition`.

Backs the ``define_code`` tool. An :class:`InstructionDefinition` records one
completed instruction creation at a resolved address — the ``size`` in bytes the
new instruction occupies. The *shape* (the field set a client parses) is the
interoperability contract; holding the outcome in an immutable record is ours. A
refused creation never produces one — it surfaces as an error at the boundary
instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class InstructionDefinition:
    """A completed instruction creation: the address and the instruction size."""

    address: Address
    size: int
