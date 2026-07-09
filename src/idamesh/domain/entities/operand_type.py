"""Operand-type entity: :class:`OperandTypeSetting`.

Backs the ``set_op_type`` tool. An :class:`OperandTypeSetting` records one
completed change to how an instruction operand is displayed at a resolved address
— the ``operand`` index and the ``type`` (display representation) now in force.
The *shape* (the field set a client parses) is the interoperability contract;
holding the outcome in an immutable record is ours. A refused change never
produces one — it surfaces as an error at the boundary instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class OperandTypeSetting:
    """A completed operand-type change: the address, operand index, and type."""

    address: Address
    operand: int
    type: str
