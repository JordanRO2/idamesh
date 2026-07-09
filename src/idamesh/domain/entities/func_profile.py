"""The :class:`FuncProfile` entity — a compact, decompile-free summary of a function.

A profile answers "how big and how connected is this function?" cheaply: its
:attr:`address` and :attr:`name`, its byte :attr:`size`, its control-flow
:attr:`block_count` and :attr:`edge_count`, and its call-graph degree —
:attr:`caller_count` functions reach it, :attr:`callee_count` functions it
reaches. The chosen metric set is our design (the "profile without decompiling"
contract); the flat field shape is what a client parses.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class FuncProfile:
    """Compact per-function metrics aggregated from cheap database queries."""

    address: Address
    name: Optional[str]
    size: int
    block_count: int
    edge_count: int
    caller_count: int
    callee_count: int
