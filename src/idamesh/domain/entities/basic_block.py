"""The :class:`BasicBlock` entity — one node of a function's control-flow graph.

A basic block is a maximal straight-line run of instructions with a single entry
and a single exit: control enters only at :attr:`start` and leaves only after the
instruction ending at :attr:`end`, branching to one of the :attr:`successors`.
The half-open ``[start, end)`` span and the successor-start list are the
interoperability contract a client reads to reconstruct the CFG; carrying the
successors as start addresses (rather than block indices) is our choice so a
block stands on its own without a separate node table.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class BasicBlock:
    """A single control-flow basic block: its span and its successor entries."""

    start: Address
    end: Address
    successors: Tuple[Address, ...] = ()

    @property
    def size(self) -> int:
        """Number of address units the block's half-open span covers."""
        return int(self.end) - int(self.start)
