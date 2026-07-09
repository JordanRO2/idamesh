"""Recompilation entity: :class:`Recompilation`.

Backs the ``force_recompile`` tool. A :class:`Recompilation` records one completed
decompiler-cache invalidation for the function covering a resolved address. The
*shape* (the field set a client parses) is the interoperability contract; holding
the outcome in an immutable record is ours. A refused invalidation never produces
one — it surfaces as an error at the boundary instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class Recompilation:
    """A completed cache invalidation: the address whose function was flushed."""

    address: Address
