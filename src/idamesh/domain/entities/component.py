"""Component entities — a bounded call-subtree analyzed as one unit.

A :class:`Component` is the call-subtree rooted at one function, explored to a
bounded depth: each reached function becomes a :class:`ComponentMember` carrying
its compact metrics (name, size, caller/callee degree), and the component as a
whole reports aggregate stats — its member count, total byte size, and how many
call edges stay *inside* the component versus leave it (``external_call_count``,
the calls into imports, thunks, or functions beyond the depth bound). The
"analyze a cluster of related functions as a unit" framing and the internal /
external split are our design; the aggregation lives in
:mod:`idamesh.domain.services.component`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class ComponentMember:
    """One function in a component with its compact metrics."""

    address: Address
    name: Optional[str]
    size: int
    caller_count: int
    callee_count: int


@dataclass(frozen=True)
class Component:
    """A bounded call-subtree analyzed as a single unit."""

    root: Address
    depth: int
    member_count: int
    total_size: int
    internal_call_count: int
    external_call_count: int
    truncated: bool
    members: Tuple[ComponentMember, ...] = ()
