"""The operand gateway port: set an instruction operand's display type.

Backs the ``set_op_type`` tool. :meth:`set_op_type` changes how operand ``n`` of
the instruction at an effective address is rendered — a numeric base
(hex/dec/oct/bin/char), an offset, or another supported interpretation — and
returns the canonical label of the representation actually in force so the caller
can echo it. An operand index the instruction does not have, an unknown display
kind, or a representation the database refuses raises a domain error the caller
surfaces as an ``isError`` result. The SDK-level operand tagging is the adapter's
job; this port only fixes the contract.
"""

from __future__ import annotations

from typing import Protocol

from idamesh.domain.values.address import Address


class OperandGateway(Protocol):
    """Write-side access to an instruction operand's display representation."""

    def set_op_type(self, ea: Address, operand: int, kind: str) -> str:
        """Set operand ``operand``'s display type at ``ea``; return the label.

        ``operand`` is the zero-based operand index; ``kind`` names the desired
        representation (e.g. ``"hex"``, ``"dec"``, ``"oct"``, ``"bin"``,
        ``"char"``, ``"offset"``). On success the representation is applied and its
        canonical label is returned. Raises an error (surfaced by the caller as an
        ``isError`` result) when the operand index is out of range, the kind is
        unknown, or the representation cannot be applied at ``ea``.
        """
        ...
