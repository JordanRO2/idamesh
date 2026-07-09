"""The :class:`TaintPath` entity — one source→sink taint path within a function.

A taint path records that data produced by a *source* (an input-producing call's
return value) reaches the argument of a dangerous *sink* API, following the pure
dataflow tracer between them. It carries the ``source`` and ``sink`` instruction
addresses, the sink ``api`` name, and the ``steps`` (reusing
:class:`~idamesh.domain.entities.data_flow.DataFlowStep`) that connect them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Tuple

from idamesh.domain.entities.data_flow import DataFlowStep
from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class TaintPath:
    """A path from an input source to a dangerous sink argument within a function."""

    source: Address
    sink: Address
    api: str
    steps: Tuple[DataFlowStep, ...] = field(default_factory=tuple)
