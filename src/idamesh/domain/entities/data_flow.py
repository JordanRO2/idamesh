"""The :class:`DataFlowStep` entity — one hop of an intra-procedural def-use trace.

Each step records one instruction the tracked value flows through: the ``address``
of the instruction, its ``insn`` text, an optional ``target`` (the other location
the value moved to or came from at this hop), and a ``note`` naming the rule that
fired (``use`` / ``propagate`` / ``transform`` / ``redefined`` / ``def`` …). The
step is reused by the taint tracer for the source→sink path it reports.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class DataFlowStep:
    """One instruction the tracked value flows through, with a named rule."""

    address: Address
    insn: str
    note: str
    target: Optional[str] = None
